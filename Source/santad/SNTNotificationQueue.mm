/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/santad/SNTNotificationQueue.h"

#import <Foundation/Foundation.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/RingBuffer.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCNotifierInterface.h"

const uid_t kSNTNotifierNoOwner = (uid_t)-1;

@interface SNTNotificationQueue ()
@property dispatch_queue_t pendingQueue;
@property NSMutableArray* sentToUser;
@end

@implementation SNTNotificationQueue {
  std::unique_ptr<santa::RingBuffer<NSMutableDictionary*>> _pendingNotifications;
  // The connection and its owner are only ever read and written together, under @synchronized
  // (self), so a reader never pairs a connection with the owner of the one it replaced.
  MOLXPCConnection* _notifierConnection;
  uid_t _notifierOwnerUID;
}

- (instancetype)initWithRingBuffer:
    (std::unique_ptr<santa::RingBuffer<NSMutableDictionary*>>)pendingNotifications {
  self = [super init];
  if (self) {
    _pendingNotifications = std::move(pendingNotifications);
    _notifierOwnerUID = kSNTNotifierNoOwner;

    _pendingQueue = dispatch_queue_create("com.northpolesec.santa.daemon.SNTNotificationQueue",
                                          DISPATCH_QUEUE_SERIAL);

    _sentToUser = [NSMutableArray array];
  }
  return self;
}

- (void)addEvent:(SNTStoredExecutionEvent*)event
        withCustomMessage:(NSString*)message
                customURL:(NSString*)url
    eventDetailButtonText:(NSString*)eventDetailButtonText
              configState:(SNTConfigState*)configState
                 andReply:(NotificationReplyBlock)replyBlock {
  if (!event) {
    if (replyBlock) {
      replyBlock(NO);
    }
    return;
  }

  NSMutableDictionary* d = [NSMutableDictionary dictionary];
  [d setValue:event forKey:@"event"];
  [d setValue:message forKey:@"message"];
  [d setValue:url forKey:@"url"];
  [d setValue:eventDetailButtonText forKey:@"buttonText"];
  [d setValue:configState forKey:@"config"];
  // Copy the block to the heap so it can be called later.
  // This is necessary because the block is allocated on the stack in the
  // Execution controller which goes out of scope.
  [d setValue:[replyBlock copy] forKey:@"reply"];

  dispatch_sync(self.pendingQueue, ^{
    NSDictionary* msg = _pendingNotifications->Enqueue(d).value_or(nil);

    if (msg != nil) {
      LOGI(@"Pending GUI notification count is over %zu, dropping oldest notification.",
           _pendingNotifications->Capacity());
      // Check if the dropped notification had a reply block and if so, call it
      // so any resources can be cleaned up.
      NotificationReplyBlock replyBlock = msg[@"reply"];
      if (replyBlock) {
        replyBlock(NO);
      }
    }

    [self flushQueueSerialized];
  });
}

/// Call the reply block, with NO, of each queued notification that has one, and drop those
/// notifications: there is no GUI to send them to. Notifications without a reply stay queued for
/// the next GUI. Notifications already sent are not touched: each is answered by its GUI, or by
/// -clearRepliesSentOverConnectionSerialized: when the connection it went over dies. A replaced
/// GUI can still be alive and showing its prompt.
- (void)clearAllPendingWithRepliesSerialized {
  _pendingNotifications->Erase(
      std::remove_if(_pendingNotifications->begin(), _pendingNotifications->end(),
                     [](NSMutableDictionary* d) {
                       NotificationReplyBlock replyBlock = d[@"reply"];
                       if (replyBlock) {
                         replyBlock(NO);
                         return true;
                       } else {
                         return false;
                       }
                     }),
      _pendingNotifications->end());
}

/// Call the reply block, with NO, of each notification sent over `connection` that has not been
/// answered, and stop tracking them. XPC drops a dead connection's replies, so nothing else will.
- (void)clearRepliesSentOverConnectionSerialized:(MOLXPCConnection*)connection {
  NSIndexSet* unanswered = [self.sentToUser
      indexesOfObjectsPassingTest:^BOOL(NSDictionary* d, NSUInteger idx, BOOL* stop) {
        return d[@"connection"] == connection;
      }];
  for (NSDictionary* d in [self.sentToUser objectsAtIndexes:unanswered]) {
    NotificationReplyBlock replyBlock = d[@"reply"];
    if (replyBlock) {
      replyBlock(NO);
    }
  }
  [self.sentToUser removeObjectsAtIndexes:unanswered];
}

- (void)flushQueueSerialized {
  MOLXPCConnection* connection = self.notifierConnection;
  id rop = [connection remoteObjectProxy];
  if (!rop) {
    // If a connection doesn't exist, clear any reply blocks in pending messages
    [self clearAllPendingWithRepliesSerialized];
    return;
  }

  while (!_pendingNotifications->Empty()) {
    NSMutableDictionary* d = _pendingNotifications->Dequeue().value_or(nil);
    if (!d) {
      // This shouldn't ever be possible, but bail just in case.
      return;
    }

    NotificationReplyBlock replyBlock = d[@"reply"];
    if (replyBlock == nil) {
      // The reply block sent to the GUI cannot be nil. Provide one now if one was not given.
      // The copy is necessary so the block is on the heap.
      replyBlock = [^(BOOL _) {
      } copy];
    }

    // Track the object we're going to send to the user and wrap the call to
    // the replyBlock so that we can remove that object when we get a response
    // from the UI.
    // NB: It is required for this wrapped block to be called asynchronously.
    // The connection is recorded so that when it dies, only the notifications sent over it are
    // answered. Holding it also keeps the MOLXPCConnection alive, and its invalidation handler
    // only runs while it is.
    d[@"connection"] = connection;
    [self.sentToUser addObject:d];
    WEAKIFY(self);
    NotificationReplyBlock wrappedReplyBlock = ^(BOOL authenticated) {
      STRONGIFY(self);
      // The reply block runs once: either here or in -clearRepliesSentOverConnectionSerialized:,
      // whichever removes the notification from sentToUser first.
      __block BOOL unanswered = YES;
      if (self) {
        dispatch_sync(self.pendingQueue, ^{
          NSUInteger i = [self.sentToUser indexOfObjectIdenticalTo:d];
          unanswered = (i != NSNotFound);
          if (unanswered) {
            [self.sentToUser removeObjectAtIndex:i];
          }
        });
      }
      if (unanswered) {
        replyBlock(authenticated);
      }
    };

    [rop postBlockNotification:d[@"event"]
             withCustomMessage:d[@"message"]
                     customURL:d[@"url"]
         eventDetailButtonText:d[@"buttonText"]
                   configState:d[@"config"]
                      andReply:wrappedReplyBlock];
  }
}

- (MOLXPCConnection*)notifierConnection {
  @synchronized(self) {
    return _notifierConnection;
  }
}

- (uid_t)notifierOwnerUID {
  @synchronized(self) {
    return _notifierOwnerUID;
  }
}

- (void)setNotifierConnection:(MOLXPCConnection*)notifierConnection ownerUID:(uid_t)ownerUID {
  @synchronized(self) {
    _notifierConnection = notifierConnection;
    _notifierOwnerUID = notifierConnection ? ownerUID : kSNTNotifierNoOwner;
  }

  WEAKIFY(self);
  WEAKIFY(notifierConnection);
  notifierConnection.invalidationHandler = ^{
    STRONGIFY(self);
    STRONGIFY(notifierConnection);
    @synchronized(self) {
      // A connection that was already replaced (a newer GUI registered, as on a fast user
      // switch) must not clear its successor, or the new session's owner with it.
      if (self->_notifierConnection == notifierConnection) {
        self->_notifierConnection = nil;
        self->_notifierOwnerUID = kSNTNotifierNoOwner;
      }
    }

    // Outside the lock: flushQueueSerialized takes it on pendingQueue.
    dispatch_sync(self.pendingQueue, ^{
      // Answer only what this GUI was sent. Any other GUI, current or replaced, answers its own.
      // Nothing with a reply stays queued to clear here: every enqueue is followed by a flush,
      // which sends it or, with no GUI, answers it.
      [self clearRepliesSentOverConnectionSerialized:notifierConnection];
    });
  };

  dispatch_sync(self.pendingQueue, ^{
    [self flushQueueSerialized];
  });
}

- (void)authorizeTemporaryMonitorMode:(void (^)(BOOL authenticated))reply {
  id rop = [self.notifierConnection synchronousRemoteObjectProxy];
  if (!rop) {
    // No GUI connection. Fail immediately rather than leaving the caller's reply
    // uninvoked, which would stall its fail-closed timeout for the full duration.
    reply(NO);
    return;
  }
  // The proxy is synchronous: if the reply block hasn't run by the time the call
  // returns, the XPC transport failed (e.g. the GUI died mid-auth) and it never
  // will. Convert that into an immediate NO so the caller fails fast.
  __block BOOL replied = NO;
  [rop authorizeTemporaryMonitorMode:^(BOOL authenticated) {
    replied = YES;
    reply(authenticated);
  }];
  if (!replied) {
    reply(NO);
  }
}

- (void)authorizeTemporaryAdminModeForUID:(uid_t)uid
                   requiringJustification:(BOOL)requireJustification
                                    reply:(void (^)(BOOL authenticated, NSString* reason))reply {
  MOLXPCConnection* connection;
  uid_t owner;
  @synchronized(self) {
    connection = _notifierConnection;
    owner = _notifierOwnerUID;
  }
  // Only a request for the connection's owner reaches the prompt.
  if (!connection || owner != uid) {
    reply(NO, @"");
    return;
  }
  id rop = [connection synchronousRemoteObjectProxy];
  if (!rop) {
    // No GUI connection. Fail immediately rather than leaving the caller's reply
    // uninvoked, which would stall its fail-closed timeout for the full duration.
    reply(NO, @"");
    return;
  }
  // The proxy is synchronous: if the reply block hasn't run by the time the call
  // returns, the XPC transport failed (e.g. the GUI died mid-auth) and it never
  // will. Convert that into an immediate NO so the caller fails fast.
  __block BOOL replied = NO;
  [rop authorizeTemporaryAdminModeRequiringJustification:requireJustification
                                                   reply:^(BOOL authenticated, NSString* reason) {
                                                     replied = YES;
                                                     reply(authenticated, reason);
                                                   }];
  if (!replied) {
    reply(NO, @"");
  }
}

@end
