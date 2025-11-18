/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#include <memory>

#include "Source/common/RingBuffer.h"
#import "Source/common/SNTConfigState.h"

@class SNTStoredExecutionEvent;
@class MOLXPCConnection;

using NotificationReplyBlock = void (^)(BOOL);

@interface SNTNotificationQueue : NSObject

@property(nonatomic) MOLXPCConnection *notifierConnection;

- (instancetype)initWithRingBuffer:
    (std::unique_ptr<santa::RingBuffer<NSMutableDictionary *>>)pendingNotifications
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

- (void)addEvent:(SNTStoredExecutionEvent *)event
    withCustomMessage:(NSString *)message
            customURL:(NSString *)url
          configState:(SNTConfigState *)configState
             andReply:(void (^)(BOOL authenticated))reply;

- (void)authorizeTemporaryMonitorMode:(void (^)(BOOL authenticated))reply;

@end
