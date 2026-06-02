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

#import "Source/common/ne/SNTNetworkExtensionSettings.h"

@interface SNTSyncNetworkExtensionSettings : NSObject <NSSecureCoding>

@property(readonly) BOOL enable;
@property(readonly) SNTNetworkFlowDefaultAction flowDefaultAction;

/// Raw, unnormalized upstream DNS forward timeout from the sync server, in seconds, carried
/// verbatim (0 == "unset"). This is NOT the effective value: the [1,15]s clamp and the 0 -> 5s
/// default are applied only when SNTNetworkExtensionSettings is built from this carrier (see
/// -[SNTNetworkExtensionQueue generateSettingsForProtocolVersion:]). Don't read this directly
/// expecting an in-range value — go through SNTNetworkExtensionSettings for that.
@property(readonly) NSTimeInterval dnsUpstreamTimeoutSecs;

/// Defaults dnsUpstreamTimeoutSecs to 0 ("unset").
- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction;

/// Designated initializer.
- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs;

- (NSData*)serialize;
+ (instancetype)deserialize:(NSData*)data;

@end
