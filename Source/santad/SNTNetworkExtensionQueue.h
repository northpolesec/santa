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
@class SNTNetworkExtensionConfig;
@class SNTNetworkExtensionSettings;
@class SNTNotificationQueue;
@class SNTRuleTable;
@class SNTSyncdQueue;

extern NSString* const kSantaNetworkExtensionProtocolVersion;

@interface SNTNetworkExtensionQueue : NSObject

@property(readonly) NSString* connectedProtocolVersion;

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                           syncdQueue:(SNTSyncdQueue*)syncdQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                               logger:(std::shared_ptr<santa::Logger>)logger
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

/// Reconcile santanetd with the current settings + network-flow ruleset, pushing only
/// what changed since the last push (settings always, rules only if their hash moved,
/// nothing if neither changed). Safe to call when santanetd is not connected (no-op).
- (void)reconcileNetworkExtensionConfig;

/// Handle a santanetd registration. Returns the config (settings + full current ruleset) to seed
/// it with — the caller returns it in the registration reply so santanetd applies both atomically.
/// Records it as the last-pushed state so the next reconcile only sends deltas.
- (SNTNetworkExtensionConfig*)handleRegistrationWithProtocolVersion:(NSString*)protocolVersion
                                                              error:(NSError**)error;

- (void)handleNetworkFlows:(NSArray<SNDProcessFlows*>*)processFlows
               windowStart:(NSDate*)windowStart
                 windowEnd:(NSDate*)windowEnd;

/// Returns YES if the network extension should be installed.
/// Checks that sync v2 is enabled and network extension settings have enable set to YES.
- (BOOL)shouldInstallNetworkExtension;

/// Queries the connected network extension for its bundle version info.
- (void)networkExtensionBundleVersionInfo:(void (^)(NSDictionary* bundleInfo))reply;

/// Returns YES if the network extension is currently connected.
- (BOOL)isLoaded;

/// Determines whether the network extension needs to be upgraded.
/// Compares the loaded extension's CFBundleVersion against the on-disk version.
/// Returns YES if the extension is not connected, versions differ, or loaded version is unknown.
/// Returns NO if versions match, or if the on-disk bundle is unreadable.
- (BOOL)networkExtensionNeedsUpgrade;

@end
