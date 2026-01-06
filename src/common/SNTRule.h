/// Copyright 2015-2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <Foundation/Foundation.h>

#import "src/common/SNTCommonEnums.h"

///
///  Represents a Rule.
///
@interface SNTRule : NSObject <NSSecureCoding>

///
///  The hash of the object this rule is for
///
@property(readonly, copy) NSString *identifier;

///
///  The state of this rule
///
@property(readonly) SNTRuleState state;

///
///  The type of object this rule is for (binary, certificate)
///
@property(readonly) SNTRuleType type;

///
///  A custom message that will be displayed if this rule blocks a binary from executing
///
@property(readonly, copy) NSString *customMsg;

///
///  A custom URL to take the user to when this binary is blocked from executing.
///
@property(readonly, copy) NSString *customURL;

///
///  The time when this rule was last retrieved from the rules database, if rule is transitive.
///  Stored as number of seconds since 00:00:00 UTC on 1 January 2001.
///
@property(readonly) NSUInteger timestamp;

///
///  A comment attached to this rule. This is intended only for local rules.
///
@property(readonly, copy) NSString *comment;

///
///  A CEL expression for this rule, required if the state is SNTRuleStateCEL.
///
@property(readonly, copy) NSString *celExpr;

///
///  Whether this rule is a static rule.
///
@property(readonly) BOOL staticRule;

///
///  Designated initializer.
///
- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg
                         customURL:(NSString *)customURL
                         timestamp:(NSUInteger)timestamp
                           comment:(NSString *)comment
                           celExpr:(NSString *)celExpr
                             error:(NSError **)error;

///
///  Initialize with a default timestamp: current time if rule state is transitive, 0 otherwise.
///
- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg
                         customURL:(NSString *)customURL
                           celExpr:(NSString *)celExpr;

///
///  Initialize with a default timestamp: current time if rule state is transitive, 0 otherwise.
///
- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type;

///
///  Initialize with a dictionary received from santactl or a static rule.
///
///  As these methods could potentially pass in a "manually-crafted" dictionary this method
///  will normalize casing of the passed dictionary before trying to parse it. This is
///  potentially a little slow, so this method should not be used in any hot paths.
///
///  If the passed dict cannot be parsed as a rule nil will be returned. Additionally, if the error
///  parameter is a non-nil pointer then it will be populated with an appropriate error object.
///
- (instancetype)initWithDictionary:(NSDictionary *)rawDict error:(NSError **)error;
- (instancetype)initStaticRuleWithDictionary:(NSDictionary *)rawDict error:(NSError **)error;

///
///  Stringify the rule with optional colorization.
///
- (NSString *)stringifyWithColor:(BOOL)colorize;

///
///  Sets timestamp of rule to the current time.
///
- (void)resetTimestamp;

///
///  Returns a dictionary representation of the rule.
///
- (NSDictionary *)dictionaryRepresentation;

@end
