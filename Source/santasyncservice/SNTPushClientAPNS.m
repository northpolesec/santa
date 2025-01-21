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
#import "Source/santasyncservice/SNTPushClientAPNS.h"

#import <MOLXPCConnection/MOLXPCConnection.h>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTSyncState.h"

@interface SNTPushClientAPNS ()
@property(weak) id<SNTPushNotificationsSyncDelegate> delegate;
@property(atomic) NSString *token;
@property NSUInteger fullSyncInterval;
@property NSUInteger globalRuleSyncDeadline;
@end

@implementation SNTPushClientAPNS

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate {
  self = [super init];
  if (self) {
    _delegate = syncDelegate;
    _fullSyncInterval = kDefaultPushNotificationsFullSyncInterval;
    _globalRuleSyncDeadline = kDefaultPushNotificationsGlobalRuleSyncDeadline;
    [self updateToken];
  }
  return self;
}

- (void)updateToken {
  [[self.delegate daemonConnection].remoteObjectProxy
      requestAPNSToken:^void(NSString *deviceToken) {
        self.token = deviceToken;
      }];
}

- (BOOL)isConnected {
  return self.token.length > 0;
}

- (void)APNSTokenChanged {
  [self updateToken];
}

- (void)handlePreflightSyncState:(SNTSyncState *)syncState {
  self.fullSyncInterval = syncState.pushNotificationsFullSyncInterval;
  self.globalRuleSyncDeadline = syncState.pushNotificationsGlobalRuleSyncDeadline;
}

- (void)handleAPNSMessage:(NSDictionary *)message {
  // Embrace APNS; do not rely on any payload information. Message delivery is best effort. Only a
  // single message will be queued per-{bundle ID and device}, in a non-deterministic way.
  // To avoid sync actions from being dropped or delivered out of order, do not store or interpret
  // any payload data. Instead, use the retrieval as signal that there is new data on the sync
  // server for the client. Simply, kick off a sync - but let the sync server know this sync was
  // triggered by a push notification. This allows the sync server to respond with any time
  // sensitive actions, like displaying a UI notification.
  // https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns?language=objc
  [self.delegate pushNotificationSync];
}

@end
