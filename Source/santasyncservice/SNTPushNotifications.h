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

#import <MOLXPCConnection/MOLXPCConnection.h>

@protocol SNTPushNotificationsSyncDelegate <NSObject>
- (void)sync;
- (void)syncSecondsFromNow:(uint64_t)seconds;
- (void)ruleSync;
- (void)ruleSyncSecondsFromNow:(uint64_t)seconds;
- (void)preflightSync;
- (MOLXPCConnection *)daemonConnection;
@end

@class SNTSyncState;

@protocol SNTPushNotificationsClientDelegate <NSObject>
- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate;
- (BOOL)isConnected;
- (void)handlePreflightSyncState:(SNTSyncState *)syncState;

@property(readonly) NSString *token;
@property(readonly) NSUInteger fullSyncInterval;
@end
