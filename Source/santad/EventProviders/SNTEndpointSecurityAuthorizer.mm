/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"

#include <EndpointSecurity/ESTypes.h>
#include <os/base.h>
#include <stdlib.h>

#import "Source/common/BranchPrediction.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTLogging.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::AuthResultCache;
using santa::EndpointSecurityAPI;
using santa::EventDisposition;
using santa::Message;

@interface SNTEndpointSecurityAuthorizer ()
@property SNTCompilerController *compilerController;
@property SNTExecutionController *execController;
@property id<SNTEndpointSecurityProbe> procWatcherProbe;
@end

@implementation SNTEndpointSecurityAuthorizer {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<santa::TTYWriter> _ttyWriter;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
               execController:(SNTExecutionController *)execController
           compilerController:(SNTCompilerController *)compilerController
              authResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
                    ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::Processor::kAuthorizer];
  if (self) {
    _execController = execController;
    _compilerController = compilerController;
    _authResultCache = authResultCache;
    _ttyWriter = std::move(ttyWriter);

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"Authorizer";
}

- (bool)respondToMessage:(const santa::Message &)msg
          withAuthResult:(es_auth_result_t)result
       forcePreventCache:(BOOL)forcePreventCache {
  // Don't let the ES framework cache DENY results. Santa only flushes ES cache
  // when a new DENY rule is received. If DENY results were cached and a rule
  // update made the executable allowable, ES would continue to apply the DENY
  // cached result. Note however that the local AuthResultCache will cache
  // DENY results. The caller may also prevent caching if it has reason to so.
  bool cacheable = (result == ES_AUTH_RESULT_ALLOW) && !forcePreventCache;

  if (self.procWatcherProbe) {
    santa::ProbeInterest interest = [self.procWatcherProbe probeInterest:msg];

    // Prevent caching if a probe is interested in the process. But don't re-enable
    // caching if it was already previously disabled.
    cacheable = cacheable && (interest == santa::ProbeInterest::kUninterested);
  }

  return [self respondToMessage:msg withAuthResult:result cacheable:cacheable];
}

- (void)processMessage:(Message)msg {
  if (msg->event_type == ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME) {
    [self.execController
        validateSuspendResumeEvent:msg
                        postAction:^(bool allowed) {
                          es_auth_result_t authResult =
                              allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY;
                          [self respondToMessage:msg
                                  withAuthResult:authResult
                                       cacheable:(authResult == ES_AUTH_RESULT_ALLOW)];
                        }];
    return;
  }

  const es_process_t *targetProc = msg->event.exec.target;

  while (true) {
    SNTAction returnAction = self->_authResultCache->CheckCache(targetProc->executable);
    if (RESPONSE_VALID(returnAction)) {
      es_auth_result_t authResult = ES_AUTH_RESULT_DENY;

      switch (returnAction) {
        case SNTActionRespondAllowCompiler:
          [self.compilerController setProcess:msg->event.exec.target->audit_token isCompiler:true];
          OS_FALLTHROUGH;
        case SNTActionRespondAllow: authResult = ES_AUTH_RESULT_ALLOW; break;
        default: break;
      }

      [self respondToMessage:msg withAuthResult:authResult forcePreventCache:NO];

      return;
    } else if (returnAction == SNTActionRespondHold) {
      _ttyWriter->Write(
          targetProc,
          [NSString stringWithFormat:@"---\n"
                                     @"\033[1mSanta\033[0m\n"
                                     @"\n"
                                     @"Blocked: %s\n"
                                     @"\n"
                                     @"Execution of this binary was blocked because a separate\n"
                                     @"instance is currently pending user authorization.\n"
                                     @"---\n"
                                     @"\n",
                                     targetProc->executable->path.data]);
      [self respondToMessage:msg withAuthResult:ES_AUTH_RESULT_DENY cacheable:false];
      return;
    } else if (returnAction == SNTActionRequestBinary) {
      // TODO(mlw): Add a metric here to observe how ofthen this happens in practice.
      // TODO(mlw): Look into caching a `Deferred<value>` to better prevent
      // raciness of multiple threads checking the cache simultaneously.
      // Also mitigates need to poll.
      usleep(5000);
    } else {
      break;
    }
  }

  self->_authResultCache->AddToCache(targetProc->executable, SNTActionRequestBinary);

  [self.execController validateExecEvent:msg
                              postAction:^bool(SNTAction action) {
                                return [self postAction:action forMessage:msg];
                              }];
}

- (void)handleMessage:(Message &&)esMsg
    recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
      if (![self.execController synchronousShouldProcessExecEvent:esMsg]) {
        [self postAction:SNTActionRespondDeny forMessage:esMsg];
        recordEventMetrics(EventDisposition::kDropped);
        return;
      }
      break;
    case ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME:
      if (esMsg->event.proc_suspend_resume.type != ES_PROC_SUSPEND_RESUME_TYPE_RESUME) {
        [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:YES];
        recordEventMetrics(EventDisposition::kDropped);
        return;
      }
      break;
    default:
      // This is a programming error
      LOGE(@"Attempting to authorize a non-exec event");
      [NSException raise:@"Invalid event type"
                  format:@"Authorizing unexpected event type: %d", esMsg->event_type];
  }

  [self processMessage:std::move(esMsg)
               handler:^(Message msg) {
                 [self processMessage:std::move(msg)];
                 recordEventMetrics(EventDisposition::kProcessed);
               }];
}

- (bool)postAction:(SNTAction)action forMessage:(const Message &)esMsg {
  es_auth_result_t authResult;

  switch (action) {
    case SNTActionRespondAllowCompiler:
      [self.compilerController setProcess:esMsg->event.exec.target->audit_token isCompiler:true];
      OS_FALLTHROUGH;
    case SNTActionRespondHold: OS_FALLTHROUGH;
    case SNTActionRespondAllow: authResult = ES_AUTH_RESULT_ALLOW; break;
    case SNTActionRespondDeny: authResult = ES_AUTH_RESULT_DENY; break;

    // Not setting `authResult` intentionally as no ES response takes place
    case SNTActionHoldAllowed: OS_FALLTHROUGH;
    case SNTActionHoldDenied: break;

    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid action for postAction, exiting.");
      [NSException raise:@"Invalid post action" format:@"Invalid post action: %ld", action];
  }

  self->_authResultCache->AddToCache(esMsg->event.exec.target->executable, action);

  if (action != SNTActionHoldAllowed && action != SNTActionHoldDenied) {
    // Do not allow caching when the action is SNTActionRespondHold because Santa
    // also authorize EXECs that occur while the current authorization is pending.
    return [self respondToMessage:esMsg
                   withAuthResult:authResult
                forcePreventCache:(action == SNTActionRespondHold)];
  } else {
    return true;
  }
}

- (void)enable {
  [super subscribeAndClearCache:{
                                    ES_EVENT_TYPE_AUTH_EXEC,
                                    ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
                                }];
}

- (void)registerAuthExecProbe:(id<SNTEndpointSecurityProbe>)watcher {
  self.procWatcherProbe = watcher;
}

@end
