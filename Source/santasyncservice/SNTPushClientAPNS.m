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

#import "Source/common/MOLXPCConnection.h"
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
  LOGD(@"APNS message received: %@", message);

  // The APNS payload is purposefully _very_ simple given the way APNS handles message re-delivery.
  // The payload dictionary contains a single key "S" with a value of either 0 or 1. If the value is
  // 0 then the sync should happen immediately. If the value is 1 then the sync should happen after
  // a random delay between now and the global rule sync deadline. This allows sync servers
  // implementing APNS support to smear syncs of a large number of hosts to avoid a thundering herd,
  // while still reaching resolution within a reasonable time period.
  id syncType = message[@"S"];
  if ([syncType isKindOfClass:[NSNumber class]] && [(NSNumber *)syncType integerValue] == 1) {
    uint32_t delaySeconds = arc4random_uniform((uint32_t)self.globalRuleSyncDeadline);
    LOGD(@"Global rule_sync, staggering: %u second delay", delaySeconds);
    [self.delegate pushNotificationSyncSecondsFromNow:delaySeconds];
    return;
  }
  [self.delegate pushNotificationSyncSecondsFromNow:0];
}

@end
