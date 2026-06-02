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

#import "Source/common/CoderMacros.h"

namespace {

// Below the floor (incl. 0 from a missing archive key) means "not meaningfully set" -> default.
// Above the ceiling is intentional -> clamp. The 15s ceiling stays well under mDNSResponder's
// ~30s per-question patience so a santanetd SERVFAIL always lands first.
const NSTimeInterval kDefaultDNSUpstreamTimeoutSecs = 5.0;
const NSTimeInterval kMinDNSUpstreamTimeoutSecs = 1.0;
const NSTimeInterval kMaxDNSUpstreamTimeoutSecs = 15.0;

NSTimeInterval NormalizeDNSUpstreamTimeout(NSTimeInterval v) {
  if (v < kMinDNSUpstreamTimeoutSecs) return kDefaultDNSUpstreamTimeoutSecs;
  if (v > kMaxDNSUpstreamTimeoutSecs) return kMaxDNSUpstreamTimeoutSecs;
  return v;
}

}  // namespace

@interface SNTNetworkExtensionSettings ()
@property(readwrite) BOOL enable;
@property(readwrite) SNTNetworkFlowDefaultAction flowDefaultAction;
@property(readwrite) NSTimeInterval dnsUpstreamTimeoutSecs;
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
  self = [super init];
  if (self) {
    _enable = enable;
    _flowDefaultAction = flowDefaultAction;
    _dnsUpstreamTimeoutSecs = NormalizeDNSUpstreamTimeout(dnsUpstreamTimeoutSecs);
  }
  return self;
}

- (BOOL)isEqual:(id)other {
  if (self == other) {
    return YES;
  }
  if (![other isKindOfClass:[SNTNetworkExtensionSettings class]]) {
    return NO;
  }
  SNTNetworkExtensionSettings* o = other;
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
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [self init];
  if (self) {
    DECODE_SELECTOR(decoder, enable, NSNumber, boolValue);
    DECODE_SELECTOR(decoder, flowDefaultAction, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, dnsUpstreamTimeoutSecs, NSNumber, doubleValue);
    // Missing key decodes to 0 -> NormalizeDNSUpstreamTimeout turns it into the default.
    _dnsUpstreamTimeoutSecs = NormalizeDNSUpstreamTimeout(_dnsUpstreamTimeoutSecs);
  }
  return self;
}

@end
