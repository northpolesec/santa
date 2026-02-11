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

#import <Foundation/Foundation.h>

#import "Source/common/MOLXPCConnection.h"

@protocol SNTPushNotificationsSyncDelegate <NSObject>
- (void)sync;
- (void)syncSecondsFromNow:(uint64_t)seconds;
- (void)ruleSync;
- (void)ruleSyncSecondsFromNow:(uint64_t)seconds;
- (void)preflightSync;
- (void)pushNotificationSyncSecondsFromNow:(uint64_t)seconds;
- (MOLXPCConnection *)daemonConnection;
- (void)eventUploadForPath:(NSString *)path reply:(void (^)(NSError *error))reply;
@end

@class SNTSyncState;

@protocol SNTPushNotificationsClientDelegate <NSObject>

@property(readonly) NSString *token;
@property(readonly) NSUInteger fullSyncInterval;

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate;
- (BOOL)isConnected;
- (void)handlePreflightSyncState:(SNTSyncState *)syncState;

@optional

/// Force an immediate reconnection attempt.
/// Use this when external conditions have changed (e.g., network interface reset)
/// and you want to reconnect without waiting for the normal retry backoff.
- (void)forceReconnect;

@end
