/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/santad/EventProviders/SNTEndpointSecurityDataFileAccessAuthorizer.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>
#include <pwd.h>
#include <sys/fcntl.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTStrengthify.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

using santa::EndpointSecurityAPI;
using santa::FAAPolicyProcessor;
using santa::FindPoliciesForTargetsBlock;
using santa::Message;

@interface SNTEndpointSecurityDataFileAccessAuthorizer ()
@property SNTConfigurator *configurator;
@property bool isSubscribed;
@property(copy) FindPoliciesForTargetsBlock findPoliciesForTargetsBlock;
@end

@implementation SNTEndpointSecurityDataFileAccessAuthorizer {
  std::shared_ptr<santa::DataFAAPolicyProcessorProxy> _faaPolicyProcessorProxy;
}

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                        metrics:(std::shared_ptr<santa::Metrics>)metrics
                         logger:(std::shared_ptr<santa::Logger>)logger
                       enricher:(std::shared_ptr<santa::Enricher>)enricher
             faaPolicyProcessor:
                 (std::shared_ptr<santa::DataFAAPolicyProcessorProxy>)faaPolicyProcessorProxy
                      ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter
    findPoliciesForTargetsBlock:(FindPoliciesForTargetsBlock)findPoliciesForTargetsBlock {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:metrics
                    processor:santa::Processor::kDataFileAccessAuthorizer];
  if (self) {
    _faaPolicyProcessorProxy = std::move(faaPolicyProcessorProxy);
    _findPoliciesForTargetsBlock = findPoliciesForTargetsBlock;

    _configurator = [SNTConfigurator configurator];

    SNTMetricBooleanGauge *famEnabled = [[SNTMetricSet sharedInstance]
        booleanGaugeWithName:@"/santa/fam_enabled"
                  fieldNames:@[]
                    helpText:@"Whether or not the FAM client is enabled"];

    WEAKIFY(self);
    [[SNTMetricSet sharedInstance] registerCallback:^{
      STRONGIFY(self);
      [famEnabled set:self.isSubscribed forFieldValues:@[]];
    }];

    [self establishClientOrDie];

    [super enableTargetPathWatching];
  }
  return self;
}

- (NSString *)description {
  return @"DataFileAccessAuthorizer";
}

- (void)processMessage:(Message)msg overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  if (msg->action_type != ES_ACTION_TYPE_AUTH) {
    return;
  }

  __block std::vector<FAAPolicyProcessor::TargetPolicyPair> targetPolicyPairs;
  __block auto pathTargets = msg.PathTargets();

  self.findPoliciesForTargetsBlock(^(santa::LookupPolicyBlock lookupPolicyBlock) {
    size_t idx = 0;
    for (const auto &target : pathTargets) {
      targetPolicyPairs.emplace_back(idx, lookupPolicyBlock(target.path.c_str()));
      idx++;
    }
  });

  FAAPolicyProcessor::ESResult result = _faaPolicyProcessorProxy->ProcessMessage(
      msg, targetPolicyPairs,
      ^bool(const santa::WatchItemPolicyBase &base_policy, const Message::PathTarget &target,
            const Message &msg) {
        for (const santa::WatchItemProcess &process : base_policy.processes) {
          if ((*_faaPolicyProcessorProxy)->PolicyMatchesProcess(process, msg->process)) {
            return true;
          }
        }

        return false;
      },
      self.fileAccessDeniedBlock, overrideAction);

  [self respondToMessage:msg withAuthResult:result.auth_result cacheable:result.cacheable];
}

- (void)handleMessage:(santa::Message &&)esMsg
    recordEventMetrics:(void (^)(santa::EventDisposition))recordEventMetrics {
  SNTOverrideFileAccessAction overrideAction = [self.configurator overrideFileAccessAction];

  // TODO: Hook up KVO watcher to unsubscribe the ES client when FAA is disabled via override
  // action. If the override action is set to Disable, return immediately.
  if (overrideAction == SNTOverrideFileAccessActionDiable) {
    if (esMsg->action_type == ES_ACTION_TYPE_AUTH) {
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
    }
    return;
  }

  if (esMsg->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
    _faaPolicyProcessorProxy->NotifyExit(esMsg->process->audit_token);
    return;
  }

  if (std::optional<FAAPolicyProcessor::ESResult> result =
          _faaPolicyProcessorProxy->ImmediateResponse(esMsg)) {
    [self respondToMessage:esMsg withAuthResult:result->auth_result cacheable:result->cacheable];
    return;
  }

  [self processMessage:std::move(esMsg)
               handler:^(Message msg) {
                 [self processMessage:std::move(msg) overrideAction:overrideAction];
                 recordEventMetrics(santa::EventDisposition::kProcessed);
               }];
}

- (void)enable {
  std::set<es_event_type_t> events = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  if (!self.isSubscribed) {
    if ([super subscribe:events]) {
      self.isSubscribed = true;
    }
  }

  // Always clear cache to ensure operations that were previously allowed are re-evaluated.
  [super clearCache];
}

- (void)disable {
  if (self.isSubscribed) {
    if ([super unsubscribeAll]) {
      self.isSubscribed = false;
    }
    [super unmuteAllTargetPaths];
  }
}

- (void)watchItemsCount:(size_t)count
               newPaths:(const santa::SetPairPathAndType &)newPaths
           removedPaths:(const santa::SetPairPathAndType &)removedPaths {
  if (count == 0) {
    [self disable];
  } else {
    // Stop watching removed paths
    [super unmuteTargetPaths:removedPaths];

    // Begin watching the added paths
    [super muteTargetPaths:newPaths];

    // begin receiving events (if not already)
    [self enable];
  }
}

@end
