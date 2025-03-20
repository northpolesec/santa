/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigState.h"
#import "Source/common/SNTXPCBundleServiceInterface.h"

@class SNTDeviceEvent;
@class SNTFileAccessEvent;
@class SNTStoredEvent;

/// Protocol implemented by SantaGUI and utilized by santad
@protocol SNTNotifierXPC
- (void)postBlockNotification:(SNTStoredEvent *)event
            withCustomMessage:(NSString *)message
                    customURL:(NSString *)url
                  configState:(SNTConfigState *)configState
                     andReply:(void (^)(BOOL authenticated))reply;
- (void)postUSBBlockNotification:(SNTDeviceEvent *)event;
- (void)postFileAccessBlockNotification:(SNTFileAccessEvent *)event
                          customMessage:(NSString *)message
                              customURL:(NSString *)url
                             customText:(NSString *)text
                            configState:(SNTConfigState *)configState API_AVAILABLE(macos(13.0));
- (void)postClientModeNotification:(SNTClientMode)clientmode;
- (void)postRuleSyncNotificationForApplication:(NSString *)app;
- (void)updateCountsForEvent:(SNTStoredEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount;
- (void)requestAPNSToken:(void (^)(NSString *))reply;
@end

@interface SNTXPCNotifierInterface : NSObject

///
///  @return an initialized NSXPCInterface for the SNTNotifierXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)notifierInterface;

@end
