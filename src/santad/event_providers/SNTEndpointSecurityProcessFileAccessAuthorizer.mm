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

#import "src/santad/event_providers/SNTEndpointSecurityProcessFileAccessAuthorizer.h"
#include <EndpointSecurity/ESTypes.h>
#include "src/santad/event_providers/FAAPolicyProcessor.h"

#include <bsm/libbsm.h>

#include <memory>

#include "src/common/AuditUtilities.h"
#import "src/common/SNTLogging.h"
#include "src/common/SantaCache.h"
#include "src/common/SantaSetCache.h"
#include "src/common/faa/WatchItemPolicy.h"
#include "src/santad/event_providers/SNTEndpointSecurityEventHandler.h"

using santa::FAAPolicyProcessor;
using santa::IterateProcessPoliciesBlock;
using santa::Message;
using santa::PidPidversion;
using santa::ProcessWatchItemPolicy;

using PidPidverPair = std::pair<pid_t, int>;
using ProcessRuleCache = SantaCache<PidPidverPair, std::shared_ptr<ProcessWatchItemPolicy>>;

@interface SNTEndpointSecurityProcessFileAccessAuthorizer ()
@property bool isSubscribed;
@property(copy) IterateProcessPoliciesBlock iterateProcessPoliciesBlock;
@property SNTConfigurator *configurator;
@end

@implementation SNTEndpointSecurityProcessFileAccessAuthorizer {
  std::unique_ptr<ProcessRuleCache> _procRuleCache;
  std::shared_ptr<santa::ProcessFAAPolicyProcessorProxy> _faaPolicyProcessorProxy;
}

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                        metrics:(std::shared_ptr<santa::Metrics>)metrics
             faaPolicyProcessor:
                 (std::shared_ptr<santa::ProcessFAAPolicyProcessorProxy>)faaPolicyProcessorProxy
    iterateProcessPoliciesBlock:(IterateProcessPoliciesBlock)iterateProcessPoliciesBlock {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::Processor::kProcessFileAccessAuthorizer];
  if (self) {
    _faaPolicyProcessorProxy = std::move(faaPolicyProcessorProxy);
    _iterateProcessPoliciesBlock = iterateProcessPoliciesBlock;

    _procRuleCache = std::make_unique<ProcessRuleCache>(2000);
    _configurator = [SNTConfigurator configurator];

    [self establishClientOrDie];
    [self enableProcessWatching];
  }
  return self;
}

- (NSString *)description {
  return @"ProcessFileAccessAuthorizer";
}

- (void)processMessage:(Message)msg
                policy:(std::shared_ptr<ProcessWatchItemPolicy>)procPolicy
        overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  if (msg->action_type != ES_ACTION_TYPE_AUTH) {
    return;
  }

  std::vector<FAAPolicyProcessor::TargetPolicyPair> targetPolicyPairs;
  size_t numTargets = msg.PathTargets().size();
  for (size_t i = 0; i < numTargets; ++i) {
    targetPolicyPairs.emplace_back(i, procPolicy);
  }

  FAAPolicyProcessor::ESResult result = _faaPolicyProcessorProxy->ProcessMessage(
      msg, targetPolicyPairs,
      ^bool(const santa::WatchItemPolicyBase &base_policy, const Message::PathTarget &target,
            const Message &msg) {
        const ProcessWatchItemPolicy *policy =
            dynamic_cast<const ProcessWatchItemPolicy *>(&base_policy);
        if (!policy) {
          LOGW(@"Failed to cast process policy");
          return false;
        }

        if (policy->tree->Contains(target.path.c_str())) {
          return true;
        } else {
          return false;
        }
      },
      self.fileAccessDeniedBlock, overrideAction);

  [self respondToMessage:msg withAuthResult:result.auth_result cacheable:result.cacheable];
}

- (void)handleMessage:(Message &&)esMsg
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

  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
      // On EXEC, the previously executing process image is replaced with a new
      // image and the pidversion is incremented. The old pid+pidversion pair
      // must be cleaned up since there will be no EXIT event for it.
      // There will be a corresponding EXIT for the newly executed process
      // regardless of whether or not it was allowed or denied.
      _procRuleCache->remove(PidPidversion(esMsg->process->audit_token));
      _faaPolicyProcessorProxy->NotifyExit(esMsg->process->audit_token);
      return;
    }

    case ES_EVENT_TYPE_NOTIFY_FORK: {
      // Clone the policy from the parent to the child and also start watching the child.
      // NB: This is safe to do as two steps (get+set) since we process the
      // fork synchronously which will occur before any EXIT event.
      [self startWatching:esMsg->event.fork.child->audit_token
                   policy:_procRuleCache->get(PidPidversion(esMsg->process->audit_token))];
      return;
    }

    case ES_EVENT_TYPE_NOTIFY_EXIT: {
      _procRuleCache->remove(PidPidversion(esMsg->process->audit_token));
      _faaPolicyProcessorProxy->NotifyExit(esMsg->process->audit_token);
      return;
    };

    default: break;
  }

  if (std::optional<FAAPolicyProcessor::ESResult> result =
          _faaPolicyProcessorProxy->ImmediateResponse(esMsg)) {
    [self respondToMessage:esMsg withAuthResult:result->auth_result cacheable:result->cacheable];
    return;
  }

  std::shared_ptr<ProcessWatchItemPolicy> policy =
      _procRuleCache->get(PidPidversion(esMsg->process->audit_token));
  if (!policy) {
    auto pidPidver = PidPidversion(esMsg->process->audit_token);
    policy = [self findPolicyForProcess:esMsg->process];
    if (policy) {
      // Found match, add to the cache. The process is already being watched.
      _procRuleCache->set(pidPidver, policy);
    } else {
      // Still no match, time to give up.
      [self stopWatching:pidPidver];

      LOGI(@"Policy no longer exists for process: %d/%d: %s", pidPidver.first, pidPidver.second,
           esMsg->process->executable->path.data);

      if (esMsg->action_type == ES_ACTION_TYPE_AUTH) {
        [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:true];
      }

      return;
    }
  }

  [self processMessage:std::move(esMsg)
               handler:^(Message msg) {
                 [self processMessage:std::move(msg) policy:policy overrideAction:overrideAction];
                 recordEventMetrics(santa::EventDisposition::kProcessed);
               }];
}

- (std::shared_ptr<ProcessWatchItemPolicy>)findPolicyForProcess:(const es_process_t *)esProc {
  __block std::shared_ptr<ProcessWatchItemPolicy> foundPolicy;
  self.iterateProcessPoliciesBlock(^bool(std::shared_ptr<ProcessWatchItemPolicy> policy) {
    for (const santa::WatchItemProcess &policyProcess : policy->processes) {
      if ((*_faaPolicyProcessorProxy)->PolicyMatchesProcess(policyProcess, esProc)) {
        // Map the new process to the matched policy and begin
        // watching the new process
        foundPolicy = policy;

        // Stop iteration, no need to continue once a match is found
        return true;
      }
    }

    return false;
  });

  return foundPolicy;
}

- (santa::ProbeInterest)probeInterest:(const santa::Message &)esMsg {
  if (!self.isSubscribed) {
    return santa::ProbeInterest::kUninterested;
  }

  std::shared_ptr<ProcessWatchItemPolicy> policy =
      [self findPolicyForProcess:esMsg->event.exec.target];

  if (policy) {
    [self startWatching:esMsg->event.exec.target->audit_token policy:policy];

    return santa::ProbeInterest::kInterested;
  } else {
    return santa::ProbeInterest::kUninterested;
  }
}

- (void)startWatching:(const audit_token_t)tok
               policy:(std::shared_ptr<ProcessWatchItemPolicy>)policy {
  if (policy) {
    _procRuleCache->set(PidPidversion(tok), policy);
  }

  // Note: Always start watching the process, even if no policy currently exists.
  // This is to protect against a race where some lookup might've failed due to
  // cache eviction. The next event from the process will re-trigger policy lookup.
  [self muteProcess:&tok];
}

- (void)stopWatching:(const std::pair<pid_t, int> &)pidPidver {
  audit_token_t stubToken = santa::MakeStubAuditToken(pidPidver.first, pidPidver.second);
  // Note: Process muting is inverted, unmuting here means to stop watching.
  [self unmuteProcess:&stubToken];
  _faaPolicyProcessorProxy->NotifyExit(stubToken);
}

- (void)enable {
  static const std::set<es_event_type_t> events = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXEC,       ES_EVENT_TYPE_NOTIFY_EXIT,   ES_EVENT_TYPE_NOTIFY_FORK};

  if (!self.isSubscribed) {
    if ([super subscribe:events]) {
      LOGD(@"Proc FAA subscribed");
      LOGW(@"Process-centric FAA rule types are currently in beta. Please report any issue to: "
           @"https://github.com/northpolesec/santa");
      self.isSubscribed = true;
    }
  }

  // This method is called any time the config changes. Clear the cache but don't stop
  // watching any of the processes. The next time the process emits some event, it will
  // be reevaluated against the latest config. However we still notify the FAAPolicyProcessor
  // as if the process exited so that caches may be cleaned up.
  _procRuleCache->clear(
      ^(std::pair<pid_t, int> &pidPidver, std::shared_ptr<ProcessWatchItemPolicy> &) {
        _faaPolicyProcessorProxy->NotifyExit(
            santa::MakeStubAuditToken(pidPidver.first, pidPidver.second));
      });

  // Always clear cache to ensure operations that were previously allowed are re-evaluated.
  [super clearCache];
}

- (void)disable {
  if (self.isSubscribed) {
    if ([super unsubscribeAll]) {
      LOGD(@"Proc FAA unsubscribed");
      self.isSubscribed = false;
    }

    _procRuleCache->clear(
        ^(std::pair<pid_t, int> &pidPidver, std::shared_ptr<ProcessWatchItemPolicy> &) {
          [self stopWatching:pidPidver];
        });
  }
}

- (void)processWatchItemsCount:(size_t)count {
  if (count > 0) {
    [self enable];
  } else {
    [self disable];
  }
}

@end
