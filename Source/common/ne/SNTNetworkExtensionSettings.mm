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

#import "Source/common/ne/SNTNetworkExtensionSettings.h"

#include <cmath>

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTNetworkFlowRule.h"

namespace {

// Normalization is deliberately asymmetric. Any value below the floor -- 0/unset (e.g. a missing
// archive key), a negative, or an absurdly small positive like 0.5s -- is treated as "not
// meaningfully set" and becomes the default; we intentionally do NOT clamp sub-floor values up to
// the floor, because an aggressively short cleanup timeout is far more likely a mistake than an
// intent. Above the ceiling IS clamped down to the max. This timeout is a resource-cleanup backstop
// for the DNS proxy's per-query upstream connection, NOT a fast-fail trigger.
const NSTimeInterval kDefaultDNSUpstreamTimeoutSecs = 30.0;
const NSTimeInterval kMinDNSUpstreamTimeoutSecs = 1.0;
const NSTimeInterval kMaxDNSUpstreamTimeoutSecs = 60.0;

NSTimeInterval NormalizeDNSUpstreamTimeout(NSTimeInterval v) {
  // Non-finite (NaN/±INF) is not a meaningful timeout; NaN also slips the </> clamp below because
  // every NaN comparison is false. Treat it as "not meaningfully set" -> default.
  if (!std::isfinite(v)) return kDefaultDNSUpstreamTimeoutSecs;
  // sub-floor (incl. 0) -> default, not clamped to floor
  if (v < kMinDNSUpstreamTimeoutSecs) return kDefaultDNSUpstreamTimeoutSecs;
  if (v > kMaxDNSUpstreamTimeoutSecs) return kMaxDNSUpstreamTimeoutSecs;
  return v;
}

}  // namespace

@interface SNTNetworkExtensionSettings ()
@property(readwrite) BOOL enable;
@property(readwrite) SNTNetworkFlowDefaultAction flowDefaultAction;
@property(readwrite) NSTimeInterval dnsUpstreamTimeoutSecs;
@property(readwrite, copy) NSArray<SNTNetworkFlowRule*>* networkFlowRules;
@end

@implementation SNTNetworkExtensionSettings

- (instancetype)initWithEnable:(BOOL)enable {
  return [self initWithEnable:enable
            flowDefaultAction:SNTNetworkFlowDefaultActionUnspecified
       dnsUpstreamTimeoutSecs:kDefaultDNSUpstreamTimeoutSecs];
}

- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction {
  return [self initWithEnable:enable
            flowDefaultAction:flowDefaultAction
       dnsUpstreamTimeoutSecs:kDefaultDNSUpstreamTimeoutSecs];
}

- (instancetype)initWithEnable:(BOOL)enable
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs {
  return [self initWithEnable:enable
            flowDefaultAction:SNTNetworkFlowDefaultActionUnspecified
       dnsUpstreamTimeoutSecs:dnsUpstreamTimeoutSecs];
}

- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs {
  return [self initWithEnable:enable
            flowDefaultAction:flowDefaultAction
       dnsUpstreamTimeoutSecs:dnsUpstreamTimeoutSecs
             networkFlowRules:nil];
}

- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction
        dnsUpstreamTimeoutSecs:(NSTimeInterval)dnsUpstreamTimeoutSecs
              networkFlowRules:(NSArray<SNTNetworkFlowRule*>*)networkFlowRules {
  self = [super init];
  if (self) {
    _enable = enable;
    _flowDefaultAction = flowDefaultAction;
    _dnsUpstreamTimeoutSecs = NormalizeDNSUpstreamTimeout(dnsUpstreamTimeoutSecs);
    _networkFlowRules = [networkFlowRules copy];
  }
  return self;
}

- (instancetype)settingsByAttachingNetworkFlowRules:
    (NSArray<SNTNetworkFlowRule*>*)networkFlowRules {
  return [[SNTNetworkExtensionSettings alloc] initWithEnable:self.enable
                                           flowDefaultAction:self.flowDefaultAction
                                      dnsUpstreamTimeoutSecs:self.dnsUpstreamTimeoutSecs
                                            networkFlowRules:networkFlowRules];
}

- (BOOL)isEqual:(id)other {
  if (self == other) {
    return YES;
  }
  if (![other isKindOfClass:[SNTNetworkExtensionSettings class]]) {
    return NO;
  }
  SNTNetworkExtensionSettings* o = other;
  // networkFlowRules is intentionally excluded. It's a transport-only field, and
  // SNTNetworkExtensionQueue's reconcileNetworkExtensionConfig tracks the rules delta separately
  // via a cached hash (scalars compared by value here; rules by hash). Including rules here would
  // defeat that fast-path and force materializing/deep-comparing the full ruleset every reconcile.
  return self.enable == o.enable && self.flowDefaultAction == o.flowDefaultAction &&
         self.dnsUpstreamTimeoutSecs == o.dnsUpstreamTimeoutSecs;
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + self.enable;
  result = prime * result + self.flowDefaultAction;
  result = prime * result + (NSUInteger)self.dnsUpstreamTimeoutSecs;
  return result;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, enable);
  ENCODE_BOXABLE(coder, flowDefaultAction);
  ENCODE_BOXABLE(coder, dnsUpstreamTimeoutSecs);
  ENCODE(coder, networkFlowRules);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [self init];
  if (self) {
    DECODE_SELECTOR(decoder, enable, NSNumber, boolValue);
    DECODE_SELECTOR(decoder, flowDefaultAction, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, dnsUpstreamTimeoutSecs, NSNumber, doubleValue);
    DECODE_ARRAY(decoder, networkFlowRules, SNTNetworkFlowRule);
    // Missing key decodes to 0 -> NormalizeDNSUpstreamTimeout turns it into the default.
    _dnsUpstreamTimeoutSecs = NormalizeDNSUpstreamTimeout(_dnsUpstreamTimeoutSecs);
  }
  return self;
}

@end
