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

- (instancetype)initWithState:(SNTNetworkFlowRuleState)state
                       ruleId:(int64_t)ruleId
                    protoBlob:(NSData*)protoBlob {
  if (state != SNTNetworkFlowRuleStateAdd && state != SNTNetworkFlowRuleStateRemove) {
    return nil;
  }
  self = [super init];
  if (self) {
    _state = state;
    _ruleId = ruleId;
    _protoBlob = [protoBlob copy];
  }
  return self;
}

- (instancetype)initAddRuleWithId:(int64_t)ruleId protoBlob:(NSData*)protoBlob {
  if (!protoBlob) {
    return nil;
  }
  return [self initWithState:SNTNetworkFlowRuleStateAdd ruleId:ruleId protoBlob:protoBlob];
}

- (instancetype)initRemoveRuleWithId:(int64_t)ruleId {
  return [self initWithState:SNTNetworkFlowRuleStateRemove ruleId:ruleId protoBlob:nil];
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

    if (_state != SNTNetworkFlowRuleStateAdd && _state != SNTNetworkFlowRuleStateRemove) {
      return nil;
    }
  }
  return self;
}

@end
