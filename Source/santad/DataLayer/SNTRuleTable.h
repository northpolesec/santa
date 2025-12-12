/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileAccessRule.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/santad/DataLayer/SNTDatabaseTable.h"

@class SNTCachedDecision;
@class SNTRule;
@class SNTNotificationMessage;

@interface SNTRuleTableRulesHash : NSObject
@property(readonly) NSString *executionRulesHash;
@property(readonly) NSString *fileAccessRulesHash;
@end

///
///  Responsible for managing the rule tables.
///
@interface SNTRuleTable : SNTDatabaseTable

///
///  @return Number of execution rules in the database
///
- (int64_t)executionRuleCount;

///
///  @return Number of file access rules in the database
///
- (int64_t)fileAccessRuleCount;

///
///  @return Number of binary rules in the database
///
- (int64_t)binaryRuleCount;

///
///  @return Number of compiler rules in the database
///
- (int64_t)compilerRuleCount;

///
///  @return Number of transitive rules in the database
///
- (int64_t)transitiveRuleCount;

///
///  @return Number of certificate rules in the database
///
- (int64_t)certificateRuleCount;

///
/// @return Number of team ID rules in the database
///
- (int64_t)teamIDRuleCount;

///
/// @return Number of signing ID rules in the database
///
- (int64_t)signingIDRuleCount;

///
/// @return Number of cdhash rules in the database
///
- (int64_t)cdhashRuleCount;

///
///  @return Rule for given identifiers.
///          Currently: binary, signingID, certificate or teamID (in that order).
///          The first matching rule found is returned.
///
- (SNTRule *)executionRuleForIdentifiers:(struct RuleIdentifiers)identifiers;

///
///  Add an array of execution rules and file access rules to the database. The rules will be added
///  within a transaction and the transaction will abort if any rule fails to add.
///
///  @param executionRules Array of SNTRule objects to add.
///  @param fileAccessRules Array of SNTFileAccessRule objects to add.
///  @param ruleCleanup Rule cleanup type to perform (e.g. all, none, non-transitive).
///  @param errors When returning NO, will be filled with an array of errors.
///  @return YES if adding all rules passed, NO if any were rejected.
///
- (BOOL)addExecutionRules:(NSArray<SNTRule *> *)executionRules
          fileAccessRules:(NSArray<SNTFileAccessRule *> *)fileAccessRules
              ruleCleanup:(SNTRuleCleanup)cleanupType
                   errors:(NSArray<NSError *> **)errors;

///
/// Wrapper for `addExecutionRules:fileAccessRules:ruleCleanup:errors:` when there are no
/// file access rules to add.
///
- (BOOL)addExecutionRules:(NSArray<SNTRule *> *)rules
              ruleCleanup:(SNTRuleCleanup)cleanupType
                   errors:(NSArray<NSError *> **)errors;

///
///  Checks the given array of rules to see if adding any of them to the rules database would
///  require the kernel's decision cache to be flushed.  This should happen if
///     1. any of the rules is not a SNTRuleStateWhitelist
///     2. a SNTRuleStateWhitelist rule is replacing a SNTRuleStateWhitelistCompiler rule.
///
///  @param rules Array of SNTRule that may be added to database.
///  @return YES if kernel cache should be flushed after adding the new rules.
- (BOOL)addedRulesShouldFlushDecisionCache:(NSArray *)rules;

///
///  Update timestamp for given rule to the current time.
///
- (void)resetTimestampForExecutionRule:(SNTRule *)rule;

///
///  Remove transitive rules that haven't been used in a long time.
///
- (void)removeOutdatedTransitiveRules;

///
///  Retrieve all execution rules from the database for export.
///
- (NSArray<SNTRule *> *)retrieveAllExecutionRules;

///
///  Retrieve all file access rules from the database for export.
///
- (NSDictionary<NSString *, NSDictionary *> *)retrieveAllFileAccessRules;

///
///  Update the static rules from the configuration.
///
- (void)updateStaticRules:(NSArray<NSDictionary *> *)staticRules;

///
///  Cached static rules.
///
@property(readonly) NSDictionary<NSString *, SNTRule *> *cachedStaticRules;

///
///  Retrieve a hash of all the non-transitive rules in the database.
///
- (SNTRuleTableRulesHash *)hashOfHashes;

///
///  A map of a file hashes to cached decisions. This is used to pre-validate and allowlist
///  certain critical system binaries that are integral to Santa's functionality.
///
@property(readonly, nonatomic)
    NSDictionary<NSString *, SNTCachedDecision *> *criticalSystemBinaries;

///
/// If set, this callback is called when file access rule content is changed via
/// addExecutionRules:fileAccessRules:ruleCleanup:error: with the latest rule count.
///
@property(copy) void (^fileAccessRulesChangedCallback)(int64_t faaRuleCount);

@end
