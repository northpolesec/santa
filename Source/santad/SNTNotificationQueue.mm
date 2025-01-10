/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/santad/SNTNotificationQueue.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/RingBuffer.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCNotifierInterface.h"

@interface SNTNotificationQueue ()
@property dispatch_queue_t pendingQueue;
@end

@implementation SNTNotificationQueue {
  std::unique_ptr<santa::RingBuffer<NSMutableDictionary *>> _pendingNotifications;
}

- (instancetype)initWithRingBuffer:
    (std::unique_ptr<santa::RingBuffer<NSMutableDictionary *>>)pendingNotifications {
  self = [super init];
  if (self) {
    _pendingNotifications = std::move(pendingNotifications);

    _pendingQueue = dispatch_queue_create("com.northpolesec.santa.daemon.SNTNotificationQueue",
                                          DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)addEvent:(SNTStoredEvent *)event
    withCustomMessage:(NSString *)message
            customURL:(NSString *)url
             andReply:(void (^)(BOOL authenticated))reply {
  if (!event) {
    if (reply) reply(NO);
    return;
  }

  NSMutableDictionary *d = [NSMutableDictionary dictionary];
  [d setValue:event forKey:@"event"];
  [d setValue:message forKey:@"message"];
  [d setValue:url forKey:@"url"];
  // Copy the block to the heap so it can be called later.
  // This is necessary because the block is allocated on the stack in the
  // Execution controller which goes out of scope.
  [d setValue:[reply copy] forKey:@"reply"];

  dispatch_sync(self.pendingQueue, ^{
    NSDictionary *msg = _pendingNotifications->Enqueue(d).value_or(nil);

    if (msg != nil) {
      LOGI(@"Pending GUI notification count is over %zu, dropping oldest notification.",
           _pendingNotifications->Capacity());
      // Check if the dropped notification had a reply block and if so, call it
      // so any resources can be cleaned up.
      void (^replyBlock)(BOOL) = msg[@"reply"];
      if (replyBlock) {
        replyBlock(NO);
      }
    }

    [self flushQueueLocked];
  });
}

/// For each pending notification, call the reply block if set then clear the
/// reply so it won't be called again when the notification is eventually sent.
- (void)clearAllPendingRepliesLocked {
  for (NSMutableDictionary *pendingDict : *_pendingNotifications) {
    void (^reply)(BOOL authenticated) = pendingDict[@"reply"];
    if (reply) {
      reply(NO);
      [pendingDict removeObjectForKey:@"reply"];
    }
  }
}

- (void)flushQueueLocked {
  id rop = [self.notifierConnection remoteObjectProxy];
  if (!rop) {
    // If a connection doesn't exist, clear any reply blocks in pending messages
    [self clearAllPendingRepliesLocked];
    return;
  }

  while (!_pendingNotifications->Empty()) {
    NSDictionary *d = _pendingNotifications->Dequeue().value_or(nil);
    if (!d) {
      // This shouldn't ever be possible, but bail just in case.
      return;
    }

    void (^reply)(BOOL authenticated) = d[@"reply"];
    if (reply == nil) {
      // The reply block sent to the GUI cannot be nil.
      // The copy is necessary so the block is on the heap.
      reply = [^(BOOL _) {
      } copy];
    }

    [rop postBlockNotification:d[@"event"]
             withCustomMessage:d[@"message"]
                     customURL:d[@"url"]
                      andReply:reply];
  }
}

- (void)setNotifierConnection:(MOLXPCConnection *)notifierConnection {
  _notifierConnection = notifierConnection;

  WEAKIFY(self);
  _notifierConnection.invalidationHandler = ^{
    STRONGIFY(self);
    _notifierConnection = nil;

    // When the connection is invalidated, clear any pending reply blocks
    dispatch_sync(self.pendingQueue, ^{
      [self clearAllPendingRepliesLocked];
    });
  };

  dispatch_sync(self.pendingQueue, ^{
    [self flushQueueLocked];
  });
}

@end
