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
@property(readwrite, copy) NSString* ruleName;
@property(readwrite) int64_t ruleId;
@property(readwrite) SNTNetworkFlowRuleState state;
@property(readwrite, copy) NSData* protoBlob;
@end

@implementation SNTNetworkFlowRule

- (instancetype)initWithState:(SNTNetworkFlowRuleState)state
                     ruleName:(NSString*)ruleName
                       ruleId:(int64_t)ruleId
                    protoBlob:(NSData*)protoBlob {
  if (state != SNTNetworkFlowRuleStateAdd && state != SNTNetworkFlowRuleStateRemove) {
    return nil;
  }
  self = [super init];
  if (self) {
    _state = state;
    _ruleName = [ruleName copy];
    _ruleId = ruleId;
    _protoBlob = [protoBlob copy];
  }
  return self;
}

- (instancetype)initAddRuleWithName:(NSString*)ruleName
                             ruleId:(int64_t)ruleId
                          protoBlob:(NSData*)protoBlob {
  if (ruleName.length == 0 || !protoBlob) {
    return nil;
  }
  return [self initWithState:SNTNetworkFlowRuleStateAdd
                    ruleName:ruleName
                      ruleId:ruleId
                   protoBlob:protoBlob];
}

- (instancetype)initRemoveRuleWithName:(NSString*)ruleName {
  if (ruleName.length == 0) {
    return nil;
  }
  return [self initWithState:SNTNetworkFlowRuleStateRemove
                    ruleName:ruleName
                      ruleId:0
                   protoBlob:nil];
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE(coder, ruleName);
  ENCODE_BOXABLE(coder, ruleId);
  ENCODE_BOXABLE(coder, state);
  ENCODE(coder, protoBlob);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, ruleName, NSString);
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
