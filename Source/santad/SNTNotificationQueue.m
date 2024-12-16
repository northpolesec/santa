/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/santad/SNTNotificationQueue.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"

static const int kMaximumNotifications = 10;

@interface SNTNotificationQueue ()
@property NSMutableArray *pendingNotifications;
@end

@implementation SNTNotificationQueue

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [NSMutableArray array];
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
  if (self.pendingNotifications.count > kMaximumNotifications) {
    LOGI(@"Pending GUI notification count is over %d, dropping.", kMaximumNotifications);
    if (reply) reply(NO);
    return;
  }

  NSMutableDictionary *d = [@{@"event" : event} mutableCopy];
  if (message) {
    d[@"message"] = message;
  }
  if (url) {
    d[@"url"] = url;
  }

  if (reply) {
    // Copy the block to the heap so it can be called later.
    //
    // This is necessary because the block is allocated on the stack in the
    // Execution controller which goes out of scope.
    d[@"reply"] = [reply copy];
  }

  @synchronized(self.pendingNotifications) {
    [self.pendingNotifications addObject:d];
  }
  [self flushQueueWithReplies:(reply != nil)];
}

- (void)flushQueueWithReplies:(BOOL)hasReplies {
  id rop = [self.notifierConnection remoteObjectProxy];
  if (!rop) {
    if (hasReplies) {
      // There is no connection to the GUI at present and flushQueue was called because of a new
      // notification that requires an authorization response. To prevent those responses from
      // piling up in the background while the UI is unavailble, we now respond with NO for each of
      // these and then remove these pending notificatoins.
      @synchronized(self.pendingNotifications) {
        NSMutableArray *deletedNotifications = [NSMutableArray array];
        for (NSDictionary *d in self.pendingNotifications) {
          if (d[@"reply"] == nil) continue;
          void (^reply)(BOOL authenticated) = d[@"reply"];
          reply(NO);
          [deletedNotifications addObject:d];
        }
        [self.pendingNotifications removeObjectsInArray:deletedNotifications];
      }
    }
    return;
  }

  @synchronized(self.pendingNotifications) {
    NSMutableArray *postedNotifications = [NSMutableArray array];
    for (NSDictionary *d in self.pendingNotifications) {
      [rop postBlockNotification:d[@"event"]
               withCustomMessage:d[@"message"]
                       customURL:d[@"url"]
                        andReply:d[@"reply"]];
      [postedNotifications addObject:d];
    }
    [self.pendingNotifications removeObjectsInArray:postedNotifications];
  }
}

- (void)setNotifierConnection:(MOLXPCConnection *)notifierConnection {
  _notifierConnection = notifierConnection;
  _notifierConnection.invalidationHandler = ^{
    _notifierConnection = nil;
  };
  [self flushQueueWithReplies:NO];
}

@end
