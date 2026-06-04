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

@class SNTNetworkFlowRule;

/// Action applied to network flows that match no NetworkFlowRule. Values mirror
/// pbv2::NetworkFlowDefaultAction (see NetworkFlowDefaultActionFromProto in SNTSyncPreflight).
typedef NS_ENUM(NSInteger, SNTNetworkFlowDefaultAction) {
  SNTNetworkFlowDefaultActionUnspecified = 0,
  SNTNetworkFlowDefaultActionAllow = 1,
  SNTNetworkFlowDefaultActionDeny = 2,
};

/// Settings passed from the daemon (santa) to the network extension (santanetd) over XPC.
///
/// This class conforms to NSSecureCoding, allowing it to be passed directly as a typed
/// argument in XPC protocol methods. NSKeyedArchiver's keyed format provides inherent
/// forward/backward compatibility: old receivers ignore unknown keys, new receivers get
/// nil/0/NO for missing keys.
@interface SNTNetworkExtensionSettings : NSObject <NSSecureCoding>

@property(readonly) BOOL enable;
@property(readonly) SNTNetworkFlowDefaultAction flowDefaultAction;

/// Upstream DNS forward timeout used by santanetd's DNS proxy, in seconds.
/// Normalized to [1.0, 60.0]; values below the floor (incl. unset/0) become the 30.0 default,
/// values above the ceiling clamp to 60.0.
@property(readonly) NSTimeInterval dnsUpstreamTimeoutSecs;

/// The network-flow ruleset for santanetd to apply. At registration this is the full ruleset
/// (possibly empty); on a runtime update, nil means "rules unchanged — keep the existing index"
/// while an empty array means "no rules". Transport-only: intentionally excluded from
/// -isEqual:/-hash (see the implementation), and silently ignored by santanetd builds that predate
/// network-flow rules.
@property(readonly, copy) NSArray<SNTNetworkFlowRule*>* networkFlowRules;

/// Defaults flowDefaultAction to Unspecified and dnsUpstreamTimeoutSecs to 30s.
- (instancetype)initWithEnable:(BOOL)enable;

/// Defaults dnsUpstreamTimeoutSecs to 30s.
- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction;

/// Defaults flowDefaultAction to Unspecified.
- (instancetype)initWithEnable:(BOOL)enable
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs;

/// Defaults networkFlowRules to nil.
- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs;

/// Designated initializer.
- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs
              networkFlowRules:(NSArray<SNTNetworkFlowRule*>*)networkFlowRules;

/// Returns a copy carrying the receiver's scalar settings, with networkFlowRules set to the given
/// array (any networkFlowRules on the receiver are not carried over). Because networkFlowRules is
/// excluded from -isEqual:/-hash, the result compares equal to the receiver — so a rules-bearing
/// copy can stand in for the scalar receiver as cached last-pushed state without perturbing the
/// settings delta.
- (instancetype)settingsByAttachingNetworkFlowRules:(NSArray<SNTNetworkFlowRule*>*)networkFlowRules;

@end
