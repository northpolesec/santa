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

typedef NS_ENUM(NSInteger, SNTNetworkFlowRuleState) {
  SNTNetworkFlowRuleStateUnspecified = 0,
  SNTNetworkFlowRuleStateAdd = 1,
  SNTNetworkFlowRuleStateRemove = 2,
};

/// Wire-format wrapper for a single NetworkFlowRule from the sync server.
/// Carries the raw serialized NetworkFlowRule.Add proto bytes when state == Add.
/// Carries only ruleName when state == Remove.
///
/// ruleName is the primary key. ruleId is the rule's version; it is carried on
/// Add rules (and stored, unique, alongside the name) but is not part of a
/// Remove, which identifies the rule to delete by name alone.
@interface SNTNetworkFlowRule : NSObject <NSSecureCoding>

@property(readonly, copy) NSString* ruleName;
@property(readonly) int64_t ruleId;
@property(readonly) SNTNetworkFlowRuleState state;

/// Serialized NetworkFlowRule.Add proto bytes. Nil for Remove rules.
@property(readonly, copy) NSData* protoBlob;

/// Construct an Add rule. Returns nil if ruleName is empty or protoBlob is nil.
- (instancetype)initAddRuleWithName:(NSString*)ruleName
                             ruleId:(int64_t)ruleId
                          protoBlob:(NSData*)protoBlob;

/// Construct a Remove rule. Returns nil if ruleName is empty.
- (instancetype)initRemoveRuleWithName:(NSString*)ruleName;

@end
