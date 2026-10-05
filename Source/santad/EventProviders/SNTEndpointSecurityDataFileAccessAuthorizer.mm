/// Copyright 2022 Google LLC
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
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
#include <set>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTStrengthify.h"
#include "Source/common/es/Message.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

using santa::EndpointSecurityAPI;
using santa::FAAPolicyProcessor;
using santa::FindPoliciesForTargetsBlock;
using santa::Message;

static const std::set<es_event_type_t> kAncestorPathEvents = {
    ES_EVENT_TYPE_AUTH_CLONE,
    ES_EVENT_TYPE_AUTH_RENAME,
};

namespace santa {

// Pairs each target with the policy watching it. When the operation moves or
// clones a directory, each target is also paired with the policy of every
// watched path beneath it, since those paths move or are cloned along with it.
// The policy watching the target comes first, and only the others are marked
// as via an ancestor.
FAAPolicyProcessor::TargetPolicyPairList TargetPolicyPairs(
    const std::vector<Message::PathTarget>& targets, bool directory_tree_op,
    LookupPolicyBlock lookup_policy_block,
    LookupPoliciesBeneathBlock lookup_policies_beneath_block) {
  FAAPolicyProcessor::TargetPolicyPairList pairs;
  pairs.reserve(targets.size());
  for (size_t idx = 0; idx < targets.size(); idx++) {
    // Path() is null-terminated, so the lookups need no string copy
    std::string_view path = targets[idx].Path();
    std::optional<std::shared_ptr<WatchItemPolicyBase>> watching = lookup_policy_block(path.data());
    pairs.emplace_back(idx, watching);
    if (directory_tree_op) {
      for (std::shared_ptr<WatchItemPolicyBase>& policy : lookup_policies_beneath_block(path)) {
        // A policy watching both the target and a path beneath it applies once
        if (watching != policy) {
          pairs.push_back({idx, std::move(policy), /*via_ancestor=*/true});
        }
      }
    }
  }
  return pairs;
}

}  // namespace santa

@interface SNTEndpointSecurityDataFileAccessAuthorizer ()
@property SNTConfigurator* configurator;
@property bool isSubscribed;
@property(copy) FindPoliciesForTargetsBlock findPoliciesForTargetsBlock;
@end

@implementation SNTEndpointSecurityDataFileAccessAuthorizer {
  std::shared_ptr<santa::DataFAAPolicyProcessorProxy> _faaPolicyProcessorProxy;
}

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                        metrics:(std::shared_ptr<santa::ESMetricsObserver>)metrics
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

    SNTMetricBooleanGauge* famEnabled = [[SNTMetricSet sharedInstance]
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

- (NSString*)description {
  return @"DataFileAccessAuthorizer";
}

- (void)processMessage:(Message)msg overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  if (msg->action_type != ES_ACTION_TYPE_AUTH) {
    return;
  }

  __block FAAPolicyProcessor::TargetPolicyPairList targetPolicyPairs;
  // Blocks capture C++ references by reference, so this does not copy the
  // targets. The block runs synchronously, while msg is alive.
  const auto& pathTargets = msg.PathTargets();
  const bool directoryTreeOp = santa::IsDirectoryTreeOperation(msg);

  self.findPoliciesForTargetsBlock(^(santa::LookupPolicyBlock lookupPolicyBlock,
                                     santa::LookupPoliciesBeneathBlock lookupPoliciesBeneathBlock) {
    targetPolicyPairs = santa::TargetPolicyPairs(pathTargets, directoryTreeOp, lookupPolicyBlock,
                                                 lookupPoliciesBeneathBlock);
  });

  FAAPolicyProcessor::ESResult result = _faaPolicyProcessorProxy->ProcessMessage(
      msg, targetPolicyPairs,
      ^FAAPolicyProcessor::PolicyMatch(const santa::WatchItemPolicyBase& base_policy,
                                       const Message::PathTarget& target, const Message& msg) {
        // Note: Iteration order is meaningful. ProcessesWithOptions entries
        // come first in this list so they take precedence over Processes.
        for (const santa::WatchItemProcess& process : base_policy.processes) {
          if ((*_faaPolicyProcessorProxy)->PolicyMatchesProcess(process, msg->process)) {
            return {true, process.options.has_value() ? &process.options.value() : nullptr};
          }
        }

        return {false, nullptr};
      },
      self.fileAccessDeniedBlock, overrideAction);

  // Directory tree operations are decided by the policies beneath the
  // directory, which the ES cache has no knowledge of.
  [self respondToMessage:msg
          withAuthResult:result.auth_result
               cacheable:result.cacheable && !directoryTreeOp];
}

- (void)handleMessage:(santa::Message&&)esMsg
    recordEventMetrics:(void (^)(santa::EventDisposition))recordEventMetrics {
  SNTOverrideFileAccessAction overrideAction = [self.configurator overrideFileAccessAction];

  // TODO: Hook up KVO watcher to unsubscribe the ES client when FAA is disabled via override
  // action. If the override action is set to Disable, return immediately.
  if (overrideAction == SNTOverrideFileAccessActionDisable) {
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

- (santa::ProbeInterest)probeInterest:(const santa::Message&)esMsg {
  if (!self.isSubscribed) {
    return santa::ProbeInterest::kUninterested;
  }

  // Mute Santa's Bundle Service so that it doesn't run afoul of file access protections and
  // can function as expected. Note: Other processes, especially santactl, are explicitly *NOT*
  // allowlisted to prevent it from becoming an oracle.
  const es_process_t* targetProc = esMsg->event.exec.target;
  if ((targetProc->codesigning_flags & (CS_SIGNED | CS_VALID)) == (CS_SIGNED | CS_VALID) &&
      targetProc->team_id.data && strcmp(targetProc->team_id.data, "ZMCG7MLDV9") == 0 &&
      targetProc->signing_id.data &&
      strcmp(targetProc->signing_id.data, "com.northpolesec.santa.bundleservice") == 0) {
    [self muteProcess:&targetProc->audit_token];
    return santa::ProbeInterest::kInterested;
  }

  return santa::ProbeInterest::kUninterested;
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
                newPaths:(const santa::SetPairPathAndType&)newPaths
            removedPaths:(const santa::SetPairPathAndType&)removedPaths
        newAncestorPaths:(const santa::SetPairPathAndType&)newAncestorPaths
    removedAncestorPaths:(const santa::SetPairPathAndType&)removedAncestorPaths {
  if (count == 0) {
    [self disable];
  } else {
    // Stop watching removed paths. This must happen before any muting below:
    // a literal path can move between the watched and ancestor sets, keeping
    // the same ES mute key, and unmuting clears every event on that key.
    [super unmuteTargetPaths:removedPaths];
    [super unmuteTargetPaths:removedAncestorPaths];

    // Begin watching the added paths. Ancestor directories of watched paths
    // are only watched for the operations that move or clone them, and with
    // them the watched paths beneath.
    [super muteTargetPaths:newPaths];
    [super muteTargetPaths:newAncestorPaths forEvents:kAncestorPathEvents];

    // begin receiving events (if not already)
    [self enable];
  }
}

@end
