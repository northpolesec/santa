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

#import "Source/santad/EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"

using santa::IterateProcessPoliciesBlock;
using santa::Message;
using santa::ProcessWatchItemPolicy;

@interface SNTEndpointSecurityProcessFileAccessAuthorizer ()
@property bool isSubscribed;
@property(copy) IterateProcessPoliciesBlock iterateProcessPoliciesBlock;
@end

@implementation SNTEndpointSecurityProcessFileAccessAuthorizer

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                        metrics:(std::shared_ptr<santa::Metrics>)metrics
    iterateProcessPoliciesBlock:(IterateProcessPoliciesBlock)iterateProcessPoliciesBlock {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::Processor::kProcessFileAccessAuthorizer];
  if (self) {
    _iterateProcessPoliciesBlock = iterateProcessPoliciesBlock;

    [self establishClientOrDie];
    [self enableProcessWatching];
  }
  return self;
}

- (NSString *)description {
  return @"ProcessFileAccessAuthorizer";
}

- (void)handleMessage:(Message &&)esMsg
    recordEventMetrics:(void (^)(santa::EventDisposition))recordEventMetrics {
}

- (santa::ProbeInterest)probeInterest:(const santa::Message &)esMsg {
  if (!self.isSubscribed) {
    return santa::ProbeInterest::kUninterested;
  }

  self.iterateProcessPoliciesBlock(^bool(std::shared_ptr<ProcessWatchItemPolicy> policy) {
    return true;
  });

  return santa::ProbeInterest::kUninterested;
}

- (void)enable {
  static const std::set<es_event_type_t> events = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  if (!self.isSubscribed) {
    if ([super subscribe:events]) {
      LOGD(@"Proc FAA subscribed");
      self.isSubscribed = true;
    }
  }

  // Always clear cache to ensure operations that were previously allowed are re-evaluated.
  [super clearCache];
}

- (void)disable {
  if (self.isSubscribed) {
    if ([super unsubscribeAll]) {
      LOGD(@"Proc FAA unsubscribed");
      self.isSubscribed = false;
    }
    [super unmuteAllTargetPaths];
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
