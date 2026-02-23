/// Copyright 2026 North Pole Security, Inc.
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

#import <Foundation/Foundation.h>

#include <memory>

#include "Source/santad/Logs/EndpointSecurity/Logger.h"

@class SNDProcessFlows;
@class SNTNotificationQueue;
@class SNTSyncdQueue;

extern NSString *const kSantaNetworkExtensionProtocolVersion;

@interface SNTNetworkExtensionQueue : NSObject

@property(readonly) NSString *connectedProtocolVersion;

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue *)notifierQueue
                           syncdQueue:(SNTSyncdQueue *)syncdQueue
                               logger:(std::shared_ptr<santa::Logger>)logger
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

- (NSDictionary *)handleRegistrationWithProtocolVersion:(NSString *)protocolVersion
                                                  error:(NSError **)error;

- (void)handleNetworkFlows:(NSArray<SNDProcessFlows *> *)processFlows
               windowStart:(NSDate *)windowStart
                 windowEnd:(NSDate *)windowEnd;

/// Returns YES if the network extension should be installed.
/// Checks that sync v2 is enabled and network extension settings have enable set to YES.
- (BOOL)shouldInstallNetworkExtension;

/// Returns YES if the network extension is currently connected.
- (BOOL)isLoaded;

@end
