/// Copyright 2024 Google LLC
/// Copyright 2024 North Pole Security, Inc.
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

/**
 * This file declares two types that are mirrors of each other.
 *
 * The C struct serves as a way to group and pass valid rule identifiers around
 * in order to minimize interface changes needed when new rule types are added
 * and also alleviate the need to allocate a short lived object.
 *
 * The Objective C class is used for an XPC boundary to easily pass rule
 * identifiers between Santa components.
 */

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"

struct RuleIdentifiers {
  NSString* cdhash;
  NSString* binarySHA256;
  NSString* signingID;
  NSString* certificateSHA256;
  NSString* teamID;
};

@interface SNTRuleIdentifiers : NSObject <NSSecureCoding>

@property(readonly) NSString* cdhash;
@property(readonly) NSString* binarySHA256;
@property(readonly) NSString* signingID;
@property(readonly) NSString* certificateSHA256;
@property(readonly) NSString* teamID;

/// Raw CS_CDHASH_LEN (20) bytes decoded from the hex `cdhash`. Returns nil
/// if `cdhash` is nil or not a well-formed 40-char hex string. Callers use
/// this when they need the raw bytes for memcmp-style comparisons without
/// re-parsing hex on the hot path.
@property(readonly) NSData* cdhashBytes;

/// Please use `initWithRuleIdentifiers:` or `initWithRuleIdentifiers:andSigningStatus:`
- (instancetype)init NS_UNAVAILABLE;

/// Initialize with a struct of rule identifiers.
- (instancetype)initWithRuleIdentifiers:(struct RuleIdentifiers)identifiers
    NS_DESIGNATED_INITIALIZER;

/// Initialize with a struct of rule identifiers and a signing status.
/// Depending on the signing status, some identifiers may be omitted.
- (instancetype)initWithRuleIdentifiers:(struct RuleIdentifiers)ri
                       andSigningStatus:(SNTSigningStatus)signingStatus;

- (struct RuleIdentifiers)toStruct;

@end
