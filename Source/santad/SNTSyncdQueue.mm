/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santad/SNTSyncdQueue.h"

#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/common/SantaCache.h"
#include "Source/common/String.h"

@interface SNTSyncdQueue ()
@property dispatch_queue_t syncdQueue;
@end

@implementation SNTSyncdQueue {
  // TODO(https://github.com/northpolesec/santa/issues/344): Eventually replace with an LRU.
  std::unique_ptr<SantaCache<std::string, NSDate *>> _uploadBackoff;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _uploadBackoff = std::make_unique<SantaCache<std::string, NSDate *>>(256);
    _syncdQueue = dispatch_queue_create("com.northpolesec.syncd_queue", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)addEvents:(NSArray<SNTStoredEvent *> *)events isFromBundle:(BOOL)isFromBundle {
  if (!events.count) return;
  SNTStoredEvent *first = events.firstObject;
  NSString *hash = isFromBundle ? first.fileBundleHash : first.fileSHA256;
  if ([self backoffForPrimaryHash:hash]) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncConnection.remoteObjectProxy postEventsToSyncServer:events fromBundle:isFromBundle];
  }];
}

- (void)addBundleEvent:(SNTStoredEvent *)event reply:(void (^)(SNTBundleEventAction))reply {
  if ([self backoffForPrimaryHash:event.fileBundleHash]) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncConnection.remoteObjectProxy
        postBundleEventToSyncServer:event
                              reply:^(SNTBundleEventAction action) {
                                // Remove the backoff entry for the initial block event. The same
                                // event will be included in the related events synced using
                                // addEvents:isFromBundle:.
                                if (action == SNTBundleEventActionSendEvents) {
                                  _uploadBackoff->remove(
                                      santa::NSStringToUTF8String(event.fileBundleHash));
                                }
                                reply(action);
                              }];
  }];
}

- (void)dispatchBlockOnSyncdQueue:(void (^)(void))block {
  if (!block) return;
  dispatch_async(self.syncdQueue, ^{
    block();
  });
}

// The event upload is skipped if an event has been initiated for it in the last 10 minutes.
// The passed-in hash is fileBundleHash for a bundle event, or fileSHA256 for a normal event.
// Returns YES if backoff is needed, NO otherwise.
- (BOOL)backoffForPrimaryHash:(NSString *)hash {
  NSDate *backoff = _uploadBackoff->get(santa::NSStringToUTF8String(hash));
  NSDate *now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) < 600) return YES;
  _uploadBackoff->set(santa::NSStringToUTF8String(hash), now);
  return NO;
}

@end
