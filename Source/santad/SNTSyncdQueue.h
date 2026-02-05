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

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"

@class MOLXPCConnection;

@interface SNTSyncdQueue : NSObject

- (instancetype)initWithCacheSize:(uint64_t)cacheSize;
- (instancetype)init NS_UNAVAILABLE;

- (void)reassessSyncServiceConnection;
- (void)reassessSyncServiceConnectionImmediately;

- (void)addStoredEvent:(SNTStoredEvent *)event;
- (void)addBundleEvents:(NSArray<SNTStoredExecutionEvent *> *)events
         withBundleHash:(NSString *)bundleHash;
- (void)addBundleEvent:(SNTStoredExecutionEvent *)event reply:(void (^)(SNTBundleEventAction))reply;

/// Force the push notification client to reconnect immediately.
/// Use this when external conditions have changed (e.g., network interface reset by content filter)
/// and you want to reconnect without waiting for the normal retry backoff.
- (void)pushNotificationReconnect;

@end
