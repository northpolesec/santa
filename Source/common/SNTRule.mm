/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/common/SNTRule.h"

#include <CommonCrypto/CommonCrypto.h>
#include <Kernel/kern/cs_blobs.h>
#include <os/base.h>

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTSyncConstants.h"

// https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/
static const NSUInteger kExpectedTeamIDLength = 10;

@interface SNTRule ()
@property(readwrite) NSUInteger timestamp;
@property(readwrite) SNTRuleState state;
@property(readwrite) SNTRuleType type;
@property(readwrite) NSString *customMsg;
@property(readwrite) NSString *customURL;
@property(readwrite) NSString *comment;
@property(readwrite) NSString *identifier;
@property(readwrite) NSString *celExpr;
@end

@implementation SNTRule

- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg
                         customURL:(NSString *)customURL
                         timestamp:(NSUInteger)timestamp
                           comment:(NSString *)comment
                           celExpr:(NSString *)celExpr
                             error:(NSError **)error {
  self = [super init];
  if (self) {
    if (identifier.length == 0) {
      return nil;
    }

    NSCharacterSet *nonHex =
        [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
    NSCharacterSet *nonAlnum = [[NSCharacterSet
        characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"] invertedSet];

    switch (type) {
      case SNTRuleTypeBinary: OS_FALLTHROUGH;
      case SNTRuleTypeCertificate: {
        if (identifier.length != (CC_SHA256_DIGEST_LENGTH * 2) ||
            [identifier rangeOfCharacterFromSet:nonHex].location != NSNotFound) {
          [SNTError populateError:error
                         withCode:SNTErrorCodeRuleInvalidIdentifier
                           format:@"Rule received with invalid identifier for its type %@",
                                  [self invalidIdentifier:identifier forType:type]];
          return nil;
        }

        // For binary and certificate rules, force the hash identifier to be lowercase hex.
        identifier = [identifier lowercaseString];

        break;
      }

      case SNTRuleTypeTeamID: {
        if (identifier.length != kExpectedTeamIDLength ||
            [identifier rangeOfCharacterFromSet:nonAlnum].location != NSNotFound) {
          [SNTError populateError:error
                         withCode:SNTErrorCodeRuleInvalidIdentifier
                           format:@"Rule received with invalid identifier for its type %@",
                                  [self invalidIdentifier:identifier forType:type]];
          return nil;
        }

        // TeamIDs are always [0-9A-Z], so enforce that the identifier is uppercase
        identifier = [identifier uppercaseString];

        break;
      }

      case SNTRuleTypeSigningID: {
        // SigningID rules are a combination of `TeamID:SigningID`. The TeamID should
        // be forced to be uppercase, but because very loose rules exist for SigningIDs,
        // their case will be kept as-is. However, platform binaries are expected to
        // have the hardcoded string "platform" as the team ID and the case will be left
        // as is.
        NSArray *sidComponents = [identifier componentsSeparatedByString:@":"];
        if (!sidComponents || sidComponents.count < 2) {
          [SNTError populateError:error
                         withCode:SNTErrorCodeRuleInvalidIdentifier
                           format:@"Rule received with invalid identifier for its type %@",
                                  [self invalidIdentifier:identifier forType:type]];
          return nil;
        }

        // The first component is the TeamID
        NSString *teamID = sidComponents[0];

        if (![[teamID lowercaseString] isEqualToString:@"platform"]) {
          if (teamID.length != kExpectedTeamIDLength ||
              [teamID rangeOfCharacterFromSet:nonAlnum].location != NSNotFound) {
            [SNTError populateError:error
                           withCode:SNTErrorCodeRuleInvalidIdentifier
                             format:@"Rule received with invalid identifier for its type %@",
                                    [self invalidIdentifier:identifier forType:type]];
            return nil;
          }
        }

        // The rest of the components are the Signing ID since ":" a legal character.
        // Join all but the last element of the components to rebuild the SigningID.
        NSString *signingID =
            [[sidComponents subarrayWithRange:NSMakeRange(1, sidComponents.count - 1)]
                componentsJoinedByString:@":"];
        if (signingID.length == 0) {
          [SNTError populateError:error
                         withCode:SNTErrorCodeRuleInvalidIdentifier
                           format:@"Rule received with invalid identifier for its type %@",
                                  [self invalidIdentifier:identifier forType:type]];
          return nil;
        }

        // TeamIDs are always [0-9A-Z], so enforce that the TeamID is uppercase, unless "platform"
        if ([[teamID lowercaseString] isEqualToString:@"platform"]) {
          teamID = [teamID lowercaseString];
        } else {
          teamID = [teamID uppercaseString];
        }

        identifier = [NSString stringWithFormat:@"%@:%@", teamID, signingID];
        break;
      }

      case SNTRuleTypeCDHash: {
        if (identifier.length != CS_CDHASH_LEN * 2 ||
            [identifier rangeOfCharacterFromSet:nonHex].location != NSNotFound) {
          [SNTError populateError:error
                         withCode:SNTErrorCodeRuleInvalidIdentifier
                           format:@"Rule received with invalid identifier for its type %@",
                                  [self invalidIdentifier:identifier forType:type]];
          return nil;
        }
        // For CDHash rules, force the hash identifier to be lowercase hex.
        identifier = [identifier lowercaseString];
        break;
      }

      default: {
        break;
      }
    }

    if (state == SNTRuleStateCEL && celExpr.length == 0) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeRuleInvalidCELExpression
                       format:@"Rule received missing CEL expression"];
      return nil;
    }

    _identifier = identifier;
    _state = state;
    _type = type;
    _customMsg = customMsg;
    _customURL = customURL;
    _timestamp = timestamp;
    _comment = comment;
    _celExpr = celExpr;
  }
  return self;
}

- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type
                         customMsg:(NSString *)customMsg
                         customURL:(NSString *)customURL
                           celExpr:(NSString *)celExpr {
  self = [self initWithIdentifier:identifier
                            state:state
                             type:type
                        customMsg:customMsg
                        customURL:customURL
                        timestamp:0
                          comment:nil
                          celExpr:celExpr
                            error:nil];
  // Initialize timestamp to current time if rule is transitive.
  if (self && state == SNTRuleStateAllowTransitive) {
    [self resetTimestamp];
  }
  return self;
}

- (instancetype)initWithIdentifier:(NSString *)identifier
                             state:(SNTRuleState)state
                              type:(SNTRuleType)type {
  return [self initWithIdentifier:identifier
                            state:state
                             type:type
                        customMsg:nil
                        customURL:nil
                        timestamp:0
                          comment:nil
                          celExpr:nil
                            error:nil];
}

- (NSString *)invalidIdentifier:(NSString *)identifier forType:(SNTRuleType)type {
  static NSDictionary<NSNumber *, NSString *> *const typeStr = @{
    @(SNTRuleTypeCDHash) : kRuleTypeCDHash,
    @(SNTRuleTypeBinary) : kRuleTypeBinary,
    @(SNTRuleTypeSigningID) : kRuleTypeSigningID,
    @(SNTRuleTypeCertificate) : kRuleTypeCertificate,
    @(SNTRuleTypeTeamID) : kRuleTypeTeamID,
  };

  return [NSString stringWithFormat:@"(rule type: %@, identifier: %@)",
                                    typeStr[@(type)] ?: @"<unknown>", identifier];
}

// lowercase policy keys and upper case the policy decision.
- (NSDictionary *)normalizeRuleDictionary:(NSDictionary *)dict {
  NSMutableDictionary *newDict = [NSMutableDictionary dictionaryWithCapacity:dict.count];
  for (id rawKey in dict) {
    if (![rawKey isKindOfClass:[NSString class]]) continue;
    NSString *key = (NSString *)rawKey;
    NSString *newKey = [key lowercaseString];
    if (([newKey isEqualToString:kRulePolicy] || [newKey isEqualToString:kRuleType]) &&
        [dict[key] isKindOfClass:[NSString class]]) {
      newDict[newKey] = [dict[key] uppercaseString];
    } else {
      newDict[newKey] = dict[key];
    }
  }
  return newDict;
}

// Converts rule information from santactl or static rules into a SNTRule.
- (instancetype)initWithDictionary:(NSDictionary *)rawDict error:(NSError **)error {
  if (![rawDict isKindOfClass:[NSDictionary class]]) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidType
                     format:@"Rule received with invalid type %@", [rawDict class]];
    return nil;
  }

  NSDictionary *dict = [self normalizeRuleDictionary:rawDict];

  NSString *identifier = dict[kRuleIdentifier];
  if (![identifier isKindOfClass:[NSString class]] || !identifier.length) {
    identifier = dict[kRuleSHA256];
  }
  if (![identifier isKindOfClass:[NSString class]] || !identifier.length) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeRuleMissingIdentifier
                     format:@"Rule received with missing/invalid identifier '%@'", identifier];
    return nil;
  }

  NSString *policyString = dict[kRulePolicy];
  SNTRuleState state;
  if (![policyString isKindOfClass:[NSString class]]) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeRuleMissingPolicy
                     format:@"Rule received with missing/invalid policy '%@'", policyString];
    return nil;
  }
  if ([policyString isEqual:kRulePolicyAllowlist] ||
      [policyString isEqual:kRulePolicyAllowlistDeprecated]) {
    state = SNTRuleStateAllow;
  } else if ([policyString isEqual:kRulePolicyAllowlistCompiler] ||
             [policyString isEqual:kRulePolicyAllowlistCompilerDeprecated]) {
    state = SNTRuleStateAllowCompiler;
  } else if ([policyString isEqual:kRulePolicyAllowlistLocalBinary]) {
    state = SNTRuleStateAllowLocalBinary;
  } else if ([policyString isEqual:kRulePolicyAllowlistLocalSigningID]) {
    state = SNTRuleStateAllowLocalSigningID;
  } else if ([policyString isEqual:kRulePolicyBlocklist] ||
             [policyString isEqual:kRulePolicyBlocklistDeprecated]) {
    state = SNTRuleStateBlock;
  } else if ([policyString isEqual:kRulePolicySilentBlocklist] ||
             [policyString isEqual:kRulePolicySilentBlocklistDeprecated]) {
    state = SNTRuleStateSilentBlock;
  } else if ([policyString isEqual:kRulePolicyRemove]) {
    state = SNTRuleStateRemove;
  } else if ([policyString isEqual:kRulePolicyCEL]) {
    state = SNTRuleStateCEL;
  } else {
    [SNTError populateError:error
                   withCode:SNTErrorCodeRuleInvalidPolicy
                     format:@"Rule received with invalid policy '%@'", policyString];
    return nil;
  }

  NSString *ruleTypeString = dict[kRuleType];
  SNTRuleType type;
  if (![ruleTypeString isKindOfClass:[NSString class]]) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeRuleMissingRuleType
                     format:@"Rule received with missing/invalid rule type '%@'", ruleTypeString];
    return nil;
  }
  if ([ruleTypeString isEqual:kRuleTypeBinary]) {
    type = SNTRuleTypeBinary;
  } else if ([ruleTypeString isEqual:kRuleTypeCertificate]) {
    type = SNTRuleTypeCertificate;
  } else if ([ruleTypeString isEqual:kRuleTypeTeamID]) {
    type = SNTRuleTypeTeamID;
  } else if ([ruleTypeString isEqual:kRuleTypeSigningID]) {
    type = SNTRuleTypeSigningID;
  } else if ([ruleTypeString isEqual:kRuleTypeCDHash]) {
    type = SNTRuleTypeCDHash;
  } else {
    [SNTError populateError:error
                   withCode:SNTErrorCodeRuleInvalidRuleType
                     format:@"Rule received with invalid rule type '%@'", ruleTypeString];
    return nil;
  }

  NSString *customMsg = dict[kRuleCustomMsg];
  if (![customMsg isKindOfClass:[NSString class]] || customMsg.length == 0) {
    customMsg = nil;
  }

  NSString *customURL = dict[kRuleCustomURL];
  if (![customURL isKindOfClass:[NSString class]] || customURL.length == 0) {
    customURL = nil;
  }

  NSString *comment = dict[kRuleComment];
  if (![comment isKindOfClass:[NSString class]] || comment.length == 0) {
    comment = nil;
  }

  NSString *celExpr = dict[kRuleCELExpr];
  if (![celExpr isKindOfClass:[NSString class]] || celExpr.length == 0) {
    celExpr = nil;
  }

  return [self initWithIdentifier:identifier
                            state:state
                             type:type
                        customMsg:customMsg
                        customURL:customURL
                        timestamp:0
                          comment:comment
                          celExpr:celExpr
                            error:error];
}

- (instancetype)initStaticRuleWithDictionary:(NSDictionary *)rawDict error:(NSError **)error {
  self = [self initWithDictionary:rawDict error:error];
  if (self) {
    _staticRule = YES;
  }
  return self;
}

#pragma mark NSSecureCoding

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, identifier);
  ENCODE_BOXABLE(coder, state);
  ENCODE_BOXABLE(coder, type);
  ENCODE(coder, customMsg);
  ENCODE(coder, customURL);
  ENCODE_BOXABLE(coder, timestamp);
  ENCODE(coder, comment);
  ENCODE(coder, celExpr);
  ENCODE_BOXABLE(coder, staticRule);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, identifier, NSString);
    DECODE_SELECTOR(decoder, state, NSNumber, intValue);
    DECODE_SELECTOR(decoder, type, NSNumber, intValue);
    DECODE(decoder, customMsg, NSString);
    DECODE(decoder, customURL, NSString);
    DECODE_SELECTOR(decoder, timestamp, NSNumber, unsignedIntegerValue);
    DECODE(decoder, comment, NSString);
    DECODE(decoder, celExpr, NSString);
    DECODE_SELECTOR(decoder, staticRule, NSNumber, boolValue);
  }
  return self;
}

- (NSString *)ruleStateToPolicyString:(SNTRuleState)state {
  switch (state) {
    case SNTRuleStateAllow: return kRulePolicyAllowlist;
    case SNTRuleStateAllowCompiler: return kRulePolicyAllowlistCompiler;
    case SNTRuleStateBlock: return kRulePolicyBlocklist;
    case SNTRuleStateSilentBlock: return kRulePolicySilentBlocklist;
    case SNTRuleStateRemove: return kRulePolicyRemove;
    case SNTRuleStateAllowTransitive: return @"AllowTransitive";
    case SNTRuleStateAllowLocalBinary: return kRulePolicyAllowlistLocalBinary;
    case SNTRuleStateAllowLocalSigningID: return kRulePolicyAllowlistLocalSigningID;
    case SNTRuleStateCEL: return kRulePolicyCEL;
    // This should never be hit. But is here for completion.
    default: return @"Unknown";
  }
}

- (NSString *)ruleTypeToString:(SNTRuleType)ruleType {
  switch (ruleType) {
    case SNTRuleTypeBinary: return kRuleTypeBinary;
    case SNTRuleTypeCertificate: return kRuleTypeCertificate;
    case SNTRuleTypeTeamID: return kRuleTypeTeamID;
    case SNTRuleTypeSigningID: return kRuleTypeSigningID;
    // This should never be hit. If we have rule types of Unknown then there's a
    // coding error somewhere.
    default: return @"Unknown";
  }
}

// Returns an NSDictionary representation of the rule. Primarily use for
// exporting rules.
- (NSDictionary *)dictionaryRepresentation {
  return @{
    kRuleIdentifier : self.identifier,
    kRulePolicy : [self ruleStateToPolicyString:self.state],
    kRuleType : [self ruleTypeToString:self.type],
    kRuleCustomMsg : self.customMsg ?: @"",
    kRuleCustomURL : self.customURL ?: @"",
    kRuleComment : self.comment ?: @"",
    kRuleCELExpr : self.celExpr ?: @"",
  };
}

- (BOOL)isEqual:(id)other {
  if (other == self) return YES;
  if (![other isKindOfClass:[SNTRule class]]) return NO;
  SNTRule *o = other;
  return ([self.identifier isEqual:o.identifier] && self.state == o.state && self.type == o.type &&
          (self.celExpr == nil || [self.celExpr isEqual:o.celExpr]));
}

- (NSUInteger)hash {
  NSUInteger prime = 31;
  NSUInteger result = 1;
  result = prime * result + [self.identifier hash];
  result = prime * result + self.state;
  result = prime * result + self.type;
  result = prime * result + [self.celExpr hash];
  result = prime * result + [self.celExpr hash];
  return result;
}

- (NSString *)description {
  return [NSString
      stringWithFormat:@"SNTRule: Identifier: %@, State: %ld, Type: %ld, Timestamp: %lu",
                       self.identifier, self.state, self.type, (unsigned long)self.timestamp];
}

- (NSString *)stringifyWithColor:(BOOL)colorize {
  NSMutableString *output;
  // Rule state is saved as eventState for output colorization down below
  SNTEventState eventState = SNTEventStateUnknown;

  switch (self.state) {
    case SNTRuleStateUnknown: return @"None"; break;
    case SNTRuleStateAllow: OS_FALLTHROUGH;
    case SNTRuleStateAllowCompiler: OS_FALLTHROUGH;
    case SNTRuleStateAllowTransitive:
      output = [@"Allowed" mutableCopy];
      eventState = SNTEventStateAllow;
      break;
    case SNTRuleStateBlock: OS_FALLTHROUGH;
    case SNTRuleStateSilentBlock:
      output = [@"Blocked" mutableCopy];
      eventState = SNTEventStateBlock;
      break;
    case SNTRuleStateCEL: output = [@"CEL" mutableCopy]; break;
    case SNTRuleStateRemove: OS_FALLTHROUGH;
    default:
      output = [NSMutableString stringWithFormat:@"Unexpected rule state: %ld", self.state];
      break;
  }

  [output appendString:@" ("];

  switch (self.type) {
    case SNTRuleTypeUnknown: [output appendString:@"Unknown"]; break;
    case SNTRuleTypeCDHash: [output appendString:@"CDHash"]; break;
    case SNTRuleTypeBinary: [output appendString:@"Binary"]; break;
    case SNTRuleTypeSigningID: [output appendString:@"SigningID"]; break;
    case SNTRuleTypeCertificate: [output appendString:@"Certificate"]; break;
    case SNTRuleTypeTeamID: [output appendString:@"TeamID"]; break;
    default:
      output = [NSMutableString stringWithFormat:@"Unexpected rule type: %ld", self.type];
      break;
  }

  // Add additional attributes
  switch (self.state) {
    case SNTRuleStateAllowCompiler: [output appendString:@", Compiler"]; break;
    case SNTRuleStateAllowTransitive: [output appendString:@", Transitive"]; break;
    case SNTRuleStateSilentBlock: [output appendString:@", Silent"]; break;
    default: break;
  }

  if (self.staticRule) {
    [output appendString:@", Static"];
  }

  [output appendString:@")"];

  // Colorize
  if (colorize) {
    if ((SNTEventStateAllow & eventState)) {
      [output insertString:@"\033[32m" atIndex:0];
      [output appendString:@"\033[0m"];
    } else if ((SNTEventStateBlock & eventState)) {
      [output insertString:@"\033[31m" atIndex:0];
      [output appendString:@"\033[0m"];
    } else {
      [output insertString:@"\033[33m" atIndex:0];
      [output appendString:@"\033[0m"];
    }
  }

  if (self.state == SNTRuleStateAllowTransitive) {
    NSDate *date = [NSDate dateWithTimeIntervalSinceReferenceDate:self.timestamp];
    [output appendString:[NSString stringWithFormat:@"\nlast access date: %@", [date description]]];
  }
  return output;
}

#pragma mark Last-access Timestamp

- (void)resetTimestamp {
  self.timestamp = (NSUInteger)[[NSDate date] timeIntervalSinceReferenceDate];
}

@end
