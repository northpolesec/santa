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

#import "Source/common/SNTNetworkFlowRule.h"

#import "Source/common/CoderMacros.h"

@interface SNTNetworkFlowRule ()
@property(readwrite) int64_t ruleId;
@property(readwrite) SNTNetworkFlowRuleState state;
@property(readwrite, copy) NSData* protoBlob;
@end

@implementation SNTNetworkFlowRule

- (instancetype)initWithRuleId:(int64_t)ruleId
                         state:(SNTNetworkFlowRuleState)state
                     protoBlob:(NSData*)protoBlob {
  self = [super init];
  if (self) {
    _ruleId = ruleId;
    _state = state;
    _protoBlob = [protoBlob copy];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, ruleId);
  ENCODE_BOXABLE(coder, state);
  ENCODE(coder, protoBlob);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, ruleId, NSNumber, longLongValue);
    DECODE_SELECTOR(decoder, state, NSNumber, integerValue);
    DECODE(decoder, protoBlob, NSData);
  }
  return self;
}

@end
