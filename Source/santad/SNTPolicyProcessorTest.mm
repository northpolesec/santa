/// Copyright 2024 Google Inc. All rights reserved.
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

#import "Source/santad/SNTPolicyProcessor.h"

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <atomic>
#include <thread>
#include <vector>

#import "Source/common/SNTCELFallbackRule.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigState.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/TestUtils.h"
#import "Source/common/cel/Activation.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EntitlementsFilter.h"

#include "cel/v1.pb.h"

extern struct RuleIdentifiers CreateRuleIDs(SNTCachedDecision* cd);

@interface SNTPolicyProcessor (Testing)
@property SNTConfigurator* configurator;
- (BOOL)evaluateCELFallbackExpressions:(SNTCachedDecision*)cd
                    activationCallback:(ActivationCallbackBlock)activationCallback;
- (void)compileFallbackRules:(NSArray<SNTCELFallbackRule*>*)rules;
- (NSString*)fileIsScopeAllowed:(SNTFileInfo*)fi;
- (NSString*)fileIsScopeBlocked:(SNTFileInfo*)fi;
@end

BOOL CompareMaybeNilStrings(NSString* s1, NSString* s2) {
  return (!s1 && !s2) || [s1 isEqualToString:s2];
}

BOOL RuleIdentifiersAreEqual(struct RuleIdentifiers r1, struct RuleIdentifiers r2) {
  BOOL res = CompareMaybeNilStrings(r1.cdhash, r2.cdhash);
  XCTAssertTrue(res, "cdhash mismatch: got: %@, want: %@", r1.cdhash, r2.cdhash);

  res = CompareMaybeNilStrings(r1.binarySHA256, r2.binarySHA256) && res;
  XCTAssertTrue(res, "binarySHA256 mismatch: got: %@, want: %@", r1.binarySHA256, r2.binarySHA256);

  res = CompareMaybeNilStrings(r1.signingID, r2.signingID) && res;
  XCTAssertTrue(res, "signingID mismatch: got: %@, want: %@", r1.signingID, r2.signingID);

  res = CompareMaybeNilStrings(r1.certificateSHA256, r2.certificateSHA256) && res;
  XCTAssertTrue(res, "certificateSHA256 mismatch: got: %@, want: %@", r1.certificateSHA256,
                r2.certificateSHA256);

  res = CompareMaybeNilStrings(r1.teamID, r2.teamID) && res;
  XCTAssertTrue(res, "teamID mismatch: got: %@, want: %@", r1.teamID, r2.teamID);

  return res;
}

@interface SNTPolicyProcessorTest : XCTestCase
@property SNTPolicyProcessor* processor;
@end

@implementation SNTPolicyProcessorTest
- (void)setUp {
  self.processor = [[SNTPolicyProcessor alloc] init];
}

- (void)tearDown {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[]];
}

- (void)testRule:(SNTRule*)rule
     transitiveRules:(BOOL)transitiveRules
               final:(BOOL)final
             matches:(BOOL)matches
              silent:(BOOL)silent
    expectedDecision:(SNTEventState)decision {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  if (matches) {
    switch (rule.type) {
      case SNTRuleTypeBinary: cd.sha256 = rule.identifier; break;
      case SNTRuleTypeCertificate: cd.certSHA256 = rule.identifier; break;
      case SNTRuleTypeCDHash: cd.cdhash = rule.identifier; break;
      default: break;
    }
  } else {
    switch (rule.type) {
      case SNTRuleTypeBinary:
        cd.sha256 = @"2334567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        break;
      case SNTRuleTypeCertificate:
        cd.certSHA256 = @"2234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        break;
      case SNTRuleTypeCDHash: cd.cdhash = @"b023fbe5361a5bbd793dc3889556e93f41ec9bb8"; break;
      default: break;
    }
  }
  BOOL decisionIsFinal = [self.processor decision:cd
                                          forRule:rule
                              withTransitiveRules:transitiveRules
                         andCELActivationCallback:nil];
  XCTAssertEqual(cd.decision, decision);
  XCTAssertEqual(decisionIsFinal, final);
  XCTAssertEqual(cd.silentBlockGUI, silent);
  XCTAssertEqual(cd.silentBlockTTY, silent);
}

- (void)testDecisionForBlockByCDHashRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockCDHash];
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockCDHash];
}

- (void)testDecisionForSilentBlockByCDHashRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"SILENT_BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockCDHash];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockCDHash];
}

// SILENT_GUI_BLOCKLIST and SILENT_TTY_BLOCKLIST suppress only one notification
// channel, so the two flags must be asserted independently rather than via the
// shared `silent:` helper (which expects them to match).
- (void)testDecisionForSilentGUIBlock {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"SILENT_GUI_BLOCKLIST"
  }
                                                error:nil];
  XCTAssertNotNil(rule, "invalid test rule dictionary");

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.cdhash = rule.identifier;
  [self.processor decision:cd forRule:rule withTransitiveRules:YES andCELActivationCallback:nil];
  XCTAssertEqual(cd.decision, SNTEventStateBlockCDHash);
  XCTAssertTrue(cd.silentBlockGUI);
  XCTAssertFalse(cd.silentBlockTTY);
}

- (void)testDecisionForSilentTTYBlock {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"SILENT_TTY_BLOCKLIST"
  }
                                                error:nil];
  XCTAssertNotNil(rule, "invalid test rule dictionary");

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.cdhash = rule.identifier;
  [self.processor decision:cd forRule:rule withTransitiveRules:YES andCELActivationCallback:nil];
  XCTAssertEqual(cd.decision, SNTEventStateBlockCDHash);
  XCTAssertFalse(cd.silentBlockGUI);
  XCTAssertTrue(cd.silentBlockTTY);
}

- (void)testDecisionForAllowbyCDHashRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"ALLOWLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCDHash];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCDHash];
}

- (void)testDecisionForBlockBySHA256RuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockBinary];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockBinary];
}

- (void)testDecisionForSilenBlockBySHA256RuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"SILENT_BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockBinary];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockBinary];
}

- (void)testDecisionForAllowBySHA256RuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowBinary];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowBinary];
}

- (void)testDecisionForSigningIDBlockRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"ABCDEFGHIJ:ABCDEFGHIJ",
    @"policy" : @"BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockSigningID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockSigningID];
}

// Signing ID rules
- (void)testDecisionForSigningIDSilentBlockRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"TEAMID1234:ABCDEFGHIJ",
    @"policy" : @"SILENT_BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockSigningID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockSigningID];
}

- (void)testDecisionForSigningIDAllowRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"TEAMID1234:ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowSigningID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowSigningID];
}

//  Certificate rules
- (void)testDecisionForCertificateBlockRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CERTIFICATE",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockCertificate];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockCertificate];
}

- (void)testDecisionForCertificateSilentBlockRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CERTIFICATE",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"SILENT_BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockCertificate];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockCertificate];
}

- (void)testDecisionForCertificateAllowRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CERTIFICATE",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCertificate];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCertificate];
}

// Team ID rules
- (void)testDecisionForTeamIDBlockRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"TEAMID",
    @"identifier" : @"TEAMID1234",
    @"policy" : @"BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockTeamID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateBlockTeamID];
}

- (void)testDecisionForTeamIDSilentBlockRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"TEAMID",
    @"identifier" : @"TEAMID1234",
    @"policy" : @"SILENT_BLOCKLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockTeamID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:YES
      expectedDecision:SNTEventStateBlockTeamID];
}

- (void)testDecisionForTeamIDAllowRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"TEAMID",
    @"identifier" : @"TEAMID1234",
    @"policy" : @"ALLOWLIST"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowTeamID];
  // Ensure that nothing changes when disabling transitive rules.
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowTeamID];
}

// Compiler rules
// CDHash
- (void)testDecisionForCDHashCompilerRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"CDHASH",
    @"identifier" : @"a023fbe5361a5bbd793dc3889556e93f41ec9bb8",
    @"policy" : @"ALLOWLIST_COMPILER"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCompilerCDHash];
  // Ensure disabling transitive rules results in a binary allow
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCDHash];
}

// SHA256
- (void)testDecisionForSHA256CompilerRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST_COMPILER"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCompilerBinary];
  // Ensure disabling transitive rules results in a binary allow
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowBinary];
}

// SigningID
- (void)testDecisionForSigningIDCompilerRuleMatches {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"SIGNINGID",
    @"identifier" : @"TEAMID1234:ABCDEFGHIJ",
    @"policy" : @"ALLOWLIST_COMPILER"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");
  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowCompilerSigningID];
  // Ensure disabling transitive rules results in a Signing ID allow
  [self testRule:rule
       transitiveRules:NO
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowSigningID];
}

// Decision-level coverage for https://github.com/northpolesec/santa/issues/1123, driven through
// a real SNTRuleTable so the actual lookup SQL is exercised. Every other test in this file mocks
// the rule table or calls -decision:forRule:... directly, so none of them can catch a precedence
// regression.
//
// Scenario: a Go toolchain is unpacked by an existing compiler. The compiler controller writes a
// transitive Binary rule for the new `go`, which is also covered by a Signing ID
// ALLOWLIST_COMPILER rule. Adding that transitive rule must not change the decision -- if the
// Binary-typed transitive rule outranks the Signing ID rule, `go` silently stops being a compiler
// and everything it builds is blocked.
- (void)testDecisionTransitiveRuleDoesNotShadowSigningIDCompilerRule {
  static NSString* const kSHA256 =
      @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
  static NSString* const kTeamID = @"TEAMID1234";
  static NSString* const kSigningID = @"TEAMID1234:com.example.go";

  // Same assertion with and without the transitive rule present. The pair is the property:
  // writing a transitive rule must be decision-neutral when a compiler rule already covers it.
  for (NSNumber* withTransitiveRule in @[ @NO, @YES ]) {
    FMDatabaseQueue* dbq = [[FMDatabaseQueue alloc] init];
    SNTRuleTable* ruleTable = [[SNTRuleTable alloc] initWithDatabaseQueue:dbq];

    // Partial mock so executionRuleForIdentifiers: runs for real. Only the lazy critical-binary
    // scan is stubbed out -- it spins up an ES client and codesigns system paths, neither of
    // which this test needs.
    id partialRuleTable = OCMPartialMock(ruleTable);
    OCMStub([partialRuleTable criticalSystemBinaries]).andReturn(@{});

    NSMutableArray<SNTRule*>* rules = [NSMutableArray array];
    SNTRule* compilerRule = [[SNTRule alloc] initWithDictionary:@{
      @"rule_type" : @"SIGNINGID",
      @"identifier" : kSigningID,
      @"policy" : @"ALLOWLIST_COMPILER",
    }
                                                          error:nil];
    XCTAssertNotNil(compilerRule, @"invalid test rule dictionary");
    [rules addObject:compilerRule];

    if (withTransitiveRule.boolValue) {
      [rules addObject:[[SNTRule alloc] initWithIdentifier:kSHA256
                                                     state:SNTRuleStateAllowTransitive
                                                      type:SNTRuleTypeBinary]];
    }

    NSArray<NSError*>* errs;
    XCTAssertTrue([ruleTable addExecutionRules:rules ruleCleanup:SNTRuleCleanupNone errors:&errs]);
    XCTAssertNil(errs);
    // Only the database query is under test; keep static rules out of it.
    [ruleTable updateStaticRules:nil];

    id mockConfigurator = OCMClassMock([SNTConfigurator class]);
    OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
    OCMStub([mockConfigurator enableTransitiveRules]).andReturn(YES);

    SNTPolicyProcessor* processor =
        [[SNTPolicyProcessor alloc] initWithRuleTable:partialRuleTable
                                   entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
    processor.configurator = mockConfigurator;

    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    OCMStub([mockFileInfo isMachO]).andReturn(YES);
    OCMStub([mockFileInfo SHA256]).andReturn(kSHA256);
    // Signature validation is passed in as already-completed, so the identifiers the lookup sees
    // are exactly the ones set below rather than whatever a real codesign check would produce.
    OCMReject([mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]]);

    SNTCachedDecision* cached = [[SNTCachedDecision alloc] init];
    cached.sha256 = kSHA256;
    cached.signingID = kSigningID;
    cached.teamID = kTeamID;
    cached.codesignValidationStatus = @(errSecSuccess);

    es_file_t file = MakeESFile("/tmp/go");
    es_process_t proc = MakeESProcess(&file);
    proc.is_platform_binary = false;
    // CS_SIGNED|CS_VALID without ADHOC or DEV_CODE yields SNTSigningStatusProduction, which is
    // what allows Signing ID rules to be considered at all.
    proc.codesigning_flags = CS_SIGNED | CS_VALID;

    SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

    SNTCachedDecision* cd = [processor decisionForFileInfo:mockFileInfo
                                             targetProcess:&proc
                                              imageCPUType:CPU_TYPE_ARM64
                                               configState:configState
                                        activationCallback:nil
                                            cachedDecision:cached];

    NSString* ctx = withTransitiveRule.boolValue ? @"with transitive rule" : @"baseline";
    XCTAssertEqual(cd.decision, SNTEventStateAllowCompilerSigningID,
                   @"%@: the SigningID compiler rule must win", ctx);
    XCTAssertNotEqual(cd.decision, SNTEventStateAllowTransitive,
                      @"%@: a transitive rule must not shadow the compiler rule", ctx);

    [partialRuleTable stopMocking];
    [mockConfigurator stopMocking];
    [mockFileInfo stopMocking];
  }
}

// Transitive allowlist rules
- (void)testDecisionForTransitiveAllowlistRuleMatches {
  SNTRule* rule = [[SNTRule alloc]
      initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                   state:SNTRuleStateAllowTransitive
                    type:SNTRuleTypeBinary];

  [self testRule:rule
       transitiveRules:YES
                 final:YES
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateAllowTransitive];
  // Ensure that a transitive allowlist rule results in an
  // SNTEventStateUnknown if transitive rules are disabled.
  [self testRule:rule
       transitiveRules:NO
                 final:NO
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateUnknown];
}

- (void)testEnsureANonMatchingRuleResultsInUnknown {
  // Set to an invalid state
  SNTRule* rule = [[SNTRule alloc]
      initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                   state:static_cast<SNTRuleState>(88888)
                    type:SNTRuleTypeBinary];

  [self testRule:rule
       transitiveRules:YES
                 final:NO
               matches:NO
                silent:NO
      expectedDecision:SNTEventStateUnknown];

  [self testRule:rule
       transitiveRules:NO
                 final:NO
               matches:YES
                silent:NO
      expectedDecision:SNTEventStateUnknown];
}

- (void)testEnsureCustomURLAndMessageAreSet {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST",
    @"custom_msg" : @"Custom Message",
    @"custom_url" : @"https://example.com"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = rule.identifier;

  [self.processor decision:cd forRule:rule withTransitiveRules:YES andCELActivationCallback:nil];

  XCTAssertEqualObjects(cd.customMsg, @"Custom Message");
  XCTAssertEqualObjects(cd.customURL, @"https://example.com");
}

- (void)testCreateRuleIDs {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];

  cd.cdhash = @"mycdhash";
  cd.sha256 = @"myhash";
  cd.signingID = @"mysid";
  cd.certSHA256 = @"mycerthash";
  cd.teamID = @"mytid";

  cd.signingStatus = SNTSigningStatusProduction;
  XCTAssertTrue(RuleIdentifiersAreEqual(CreateRuleIDs(cd), ((struct RuleIdentifiers){
                                                               .cdhash = @"mycdhash",
                                                               .binarySHA256 = @"myhash",
                                                               .signingID = @"mysid",
                                                               .certificateSHA256 = @"mycerthash",
                                                               .teamID = @"mytid",
                                                           })));

  cd.signingStatus = SNTSigningStatusDevelopment;
  XCTAssertTrue(RuleIdentifiersAreEqual(CreateRuleIDs(cd), ((struct RuleIdentifiers){
                                                               .cdhash = @"mycdhash",
                                                               .binarySHA256 = @"myhash",
                                                               .signingID = nil,
                                                               .certificateSHA256 = @"mycerthash",
                                                               .teamID = nil,
                                                           })));

  cd.signingStatus = SNTSigningStatusAdhoc;
  XCTAssertTrue(RuleIdentifiersAreEqual(CreateRuleIDs(cd), ((struct RuleIdentifiers){
                                                               .cdhash = @"mycdhash",
                                                               .binarySHA256 = @"myhash",
                                                               .signingID = nil,
                                                               .certificateSHA256 = nil,
                                                               .teamID = nil,
                                                           })));

  cd.signingStatus = SNTSigningStatusInvalid;
  XCTAssertTrue(RuleIdentifiersAreEqual(CreateRuleIDs(cd), ((struct RuleIdentifiers){
                                                               .cdhash = nil,
                                                               .binarySHA256 = @"myhash",
                                                               .signingID = nil,
                                                               .certificateSHA256 = nil,
                                                               .teamID = nil,
                                                           })));

  cd.signingStatus = SNTSigningStatusUnsigned;
  XCTAssertTrue(RuleIdentifiersAreEqual(CreateRuleIDs(cd), ((struct RuleIdentifiers){
                                                               .cdhash = nil,
                                                               .binarySHA256 = @"myhash",
                                                               .signingID = nil,
                                                               .certificateSHA256 = nil,
                                                               .teamID = nil,
                                                           })));
}

- (void)testDecisionBuildsSigningIDAndTeamIDFromProcess {
  // The cached decision's teamID/signingID are built from the target process's
  // team_id/signing_id string tokens, with signingID formatted as
  // "teamID:signingID". Characterizes that format across the token conversion.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];

  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/bin/ls"];
  XCTAssertNotNil(fi);

  es_file_t file = MakeESFile("/bin/ls");
  es_process_t proc = MakeESProcess(&file);
  proc.codesigning_flags = CS_SIGNED | CS_VALID;
  proc.signing_id = MakeESStringToken("com.apple.ls");
  proc.team_id = MakeESStringToken("EQHXZ8M8AV");

  SNTConfigState* configState =
      [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];

  SNTCachedDecision* cd = [processor decisionForFileInfo:fi
                                           targetProcess:&proc
                                            imageCPUType:CPU_TYPE_ARM64
                                             configState:configState
                                      activationCallback:nil
                                          cachedDecision:nil];

  XCTAssertEqualObjects(cd.teamID, @"EQHXZ8M8AV");
  XCTAssertEqualObjects(cd.signingID, @"EQHXZ8M8AV:com.apple.ls");
  // /bin/ls validates cleanly, so the fresh path must record the success. This
  // is the sole production write of the property the whole feature consumes.
  XCTAssertEqualObjects(cd.codesignValidationStatus, @(errSecSuccess));
}

- (void)testDecisionReusesCompletedCodesignValidation {
  // Each case is a validation that already completed and produced no
  // certificate, so certSHA256 cannot distinguish it from "never validated".
  NSArray<NSDictionary*>* cases = @[
    @{
      // Ad-hoc, linker-signed: valid signature, no certificate.
      @"status" : @(errSecSuccess),
      @"codesigning_flags" : @(CS_SIGNED | CS_VALID | CS_ADHOC | CS_LINKER_SIGNED),
      @"expected_signing_status" : @(SNTSigningStatusAdhoc),
      @"expected_extra" : [NSNull null],
    },
    @{
      @"status" : @(errSecCSUnsigned),
      @"codesigning_flags" : @0,
      @"expected_signing_status" : @(SNTSigningStatusUnsigned),
      @"expected_extra" : [NSString
          stringWithFormat:@"Signature ignored due to error: %ld", (long)errSecCSUnsigned],
    },
  ];

  for (NSDictionary* testCase in cases) {
    id mockRuleTable = OCMClassMock([SNTRuleTable class]);
    SNTPolicyProcessor* processor =
        [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                   entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
    id mockConfigurator = OCMClassMock([SNTConfigurator class]);
    OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
    processor.configurator = mockConfigurator;

    id mockFileInfo = OCMClassMock([SNTFileInfo class]);
    // The assertion that matters: static validation must not run again.
    OCMReject([mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]]);
    OCMStub([mockFileInfo isMachO]).andReturn(YES);

    SNTCachedDecision* cached = [[SNTCachedDecision alloc] init];
    cached.sha256 = @"a326a1fb48074202e9ad41e4cd1e389eeea372c8c6f7d7e80da81176d5d9430e";
    cached.codesignValidationStatus = testCase[@"status"];

    es_file_t file = MakeESFile("/tmp/rg");
    es_process_t proc = MakeESProcess(&file);
    proc.is_platform_binary = false;
    proc.codesigning_flags = [testCase[@"codesigning_flags"] unsignedIntValue];
    SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

    SNTCachedDecision* cd = [processor decisionForFileInfo:mockFileInfo
                                             targetProcess:&proc
                                              imageCPUType:CPU_TYPE_ARM64
                                               configState:configState
                                        activationCallback:nil
                                            cachedDecision:cached];

    XCTAssertEqualObjects(cd.codesignValidationStatus, testCase[@"status"]);
    XCTAssertEqual(cd.signingStatus,
                   (SNTSigningStatus)[testCase[@"expected_signing_status"] integerValue]);
    XCTAssertEqual(cd.decision, SNTEventStateAllowUnknown);

    id expectedExtra = testCase[@"expected_extra"];
    if (expectedExtra == [NSNull null]) {
      XCTAssertNil(cd.decisionExtra);
    } else {
      XCTAssertEqualObjects(cd.decisionExtra, expectedExtra);
    }

    OCMVerifyAll(mockFileInfo);
    [mockFileInfo stopMocking];
    [mockConfigurator stopMocking];
    [mockRuleTable stopMocking];
  }
}

- (void)testDecisionBlocksFreshCodesignValidationFailure {
  // A signature failure is not recorded, so it must be re-derived on every
  // execution. Also the only coverage of the fresh failure path.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMStub([mockConfigurator enableBadSignatureProtection]).andReturn(YES);
  processor.configurator = mockConfigurator;

  NSError* csError = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:errSecCSSignatureFailed
                                     userInfo:nil];
  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMExpect([mockFileInfo codesignCheckerWithError:[OCMArg setTo:csError]]).andReturn(nil);
  OCMStub([mockFileInfo isMachO]).andReturn(YES);
  OCMStub([mockFileInfo SHA256])
      .andReturn(@"a326a1fb48074202e9ad41e4cd1e389eeea372c8c6f7d7e80da81176d5d9430e");

  es_file_t file = MakeESFile("/tmp/invalid-signature");
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  proc.codesigning_flags = CS_SIGNED;
  SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

  SNTCachedDecision* cd = [processor decisionForFileInfo:mockFileInfo
                                           targetProcess:&proc
                                            imageCPUType:CPU_TYPE_ARM64
                                             configState:configState
                                      activationCallback:nil
                                          cachedDecision:nil];

  XCTAssertEqual(cd.decision, SNTEventStateBlockCertificate);
  XCTAssertEqual(cd.signingStatus, SNTSigningStatusInvalid);
  XCTAssertEqualObjects(cd.decisionExtra,
                        ([NSString stringWithFormat:@"Blocked due to signature error: %ld",
                                                    (long)errSecCSSignatureFailed]));
  // The failure must NOT be recorded: the next execution has to re-derive it.
  XCTAssertNil(cd.codesignValidationStatus);
  OCMVerifyAll(mockFileInfo);
  [mockFileInfo stopMocking];
  [mockConfigurator stopMocking];
  [mockRuleTable stopMocking];
}

- (void)testDecisionDoesNotBlockReusedUnsignedValidation {
  // errSecCSUnsigned is carved out of bad signature protection: an unsigned
  // binary is not a signature failure. Without that carve-out the setting
  // would block every unsigned binary on the endpoint.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMStub([mockConfigurator enableBadSignatureProtection]).andReturn(YES);
  processor.configurator = mockConfigurator;

  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMReject([mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]]);
  OCMStub([mockFileInfo isMachO]).andReturn(YES);

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] init];
  cached.sha256 = @"a326a1fb48074202e9ad41e4cd1e389eeea372c8c6f7d7e80da81176d5d9430e";
  cached.codesignValidationStatus = @(errSecCSUnsigned);

  es_file_t file = MakeESFile("/tmp/unsigned-tool");
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  proc.codesigning_flags = 0;
  SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

  SNTCachedDecision* cd = [processor decisionForFileInfo:mockFileInfo
                                           targetProcess:&proc
                                            imageCPUType:CPU_TYPE_ARM64
                                             configState:configState
                                      activationCallback:nil
                                          cachedDecision:cached];

  XCTAssertEqual(cd.decision, SNTEventStateAllowUnknown);
  XCTAssertEqual(cd.signingStatus, SNTSigningStatusUnsigned);
  // The failure replay must still happen even though the block does not. These
  // two are easy to conflate when editing that region, so both are pinned.
  XCTAssertEqualObjects(
      cd.decisionExtra,
      ([NSString stringWithFormat:@"Signature ignored due to error: %ld", (long)errSecCSUnsigned]));
  OCMVerifyAll(mockFileInfo);
  [mockFileInfo stopMocking];
  [mockConfigurator stopMocking];
  [mockRuleTable stopMocking];
}

- (void)testDecisionRecordsFreshUnsignedValidation {
  // errSecCSUnsigned is reusable, so a fresh unsigned verdict must be recorded
  // for the next execution to skip.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  processor.configurator = mockConfigurator;

  NSError* csError = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:errSecCSUnsigned
                                     userInfo:nil];
  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMExpect([mockFileInfo codesignCheckerWithError:[OCMArg setTo:csError]]).andReturn(nil);
  OCMStub([mockFileInfo isMachO]).andReturn(YES);
  OCMStub([mockFileInfo SHA256])
      .andReturn(@"a326a1fb48074202e9ad41e4cd1e389eeea372c8c6f7d7e80da81176d5d9430e");

  es_file_t file = MakeESFile("/tmp/unsigned-tool");
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  proc.codesigning_flags = 0;
  SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

  SNTCachedDecision* cd = [processor decisionForFileInfo:mockFileInfo
                                           targetProcess:&proc
                                            imageCPUType:CPU_TYPE_ARM64
                                             configState:configState
                                      activationCallback:nil
                                          cachedDecision:nil];

  XCTAssertEqualObjects(cd.codesignValidationStatus, @(errSecCSUnsigned));
  XCTAssertEqual(cd.decision, SNTEventStateAllowUnknown);
  XCTAssertEqual(cd.signingStatus, SNTSigningStatusUnsigned);
  OCMVerifyAll(mockFileInfo);
  [mockFileInfo stopMocking];
  [mockConfigurator stopMocking];
  [mockRuleTable stopMocking];
}

- (void)testDecisionDoesNotRecordUnsignedVerdictWhenKernelSaysSigned {
  // errSecCSUnsigned is only reusable when the kernel agrees the executable
  // itself carries no signature. When the running image is signed the two
  // sources disagree, so the verdict must not be recorded and the next
  // execution has to re-derive it.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  processor.configurator = mockConfigurator;

  NSError* csError = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:errSecCSUnsigned
                                     userInfo:nil];
  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMExpect([mockFileInfo codesignCheckerWithError:[OCMArg setTo:csError]]).andReturn(nil);
  OCMStub([mockFileInfo isMachO]).andReturn(YES);
  OCMStub([mockFileInfo SHA256])
      .andReturn(@"a326a1fb48074202e9ad41e4cd1e389eeea372c8c6f7d7e80da81176d5d9430e");

  es_file_t file = MakeESFile("/tmp/signed-tool");
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  // The kernel loaded a valid signature for this executable, contradicting the
  // static unsigned verdict.
  proc.codesigning_flags = CS_SIGNED | CS_VALID;
  SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

  SNTCachedDecision* cd = [processor decisionForFileInfo:mockFileInfo
                                           targetProcess:&proc
                                            imageCPUType:CPU_TYPE_ARM64
                                             configState:configState
                                      activationCallback:nil
                                          cachedDecision:nil];

  XCTAssertNil(cd.codesignValidationStatus);
  // The failure effects still apply; only the recording is withheld.
  XCTAssertEqual(cd.signingStatus, SNTSigningStatusInvalid);
  XCTAssertEqualObjects(
      cd.decisionExtra,
      ([NSString stringWithFormat:@"Signature ignored due to error: %ld", (long)errSecCSUnsigned]));
  OCMVerifyAll(mockFileInfo);
  [mockFileInfo stopMocking];
  [mockConfigurator stopMocking];
  [mockRuleTable stopMocking];
}

- (void)testDecisionRevalidatesWhenCachedStatusAbsent {
  // The recorded status gates the skip, not the mere presence of a cached
  // decision: a failure that was deliberately not recorded must be re-derived on
  // the next execution.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  processor.configurator = mockConfigurator;

  NSError* csError = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:errSecCSSignatureFailed
                                     userInfo:nil];
  __block int validations = 0;
  id mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([mockFileInfo codesignCheckerWithError:[OCMArg setTo:csError]])
      .andDo(^(NSInvocation* inv) {
        validations++;
      })
      .andReturn(nil);
  OCMStub([mockFileInfo isMachO]).andReturn(YES);
  OCMStub([mockFileInfo SHA256])
      .andReturn(@"a326a1fb48074202e9ad41e4cd1e389eeea372c8c6f7d7e80da81176d5d9430e");

  es_file_t file = MakeESFile("/tmp/invalid-signature");
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = false;
  proc.codesigning_flags = CS_SIGNED;
  SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:mockConfigurator];

  SNTCachedDecision* first = [processor decisionForFileInfo:mockFileInfo
                                              targetProcess:&proc
                                               imageCPUType:CPU_TYPE_ARM64
                                                configState:configState
                                         activationCallback:nil
                                             cachedDecision:nil];

  XCTAssertNil(first.codesignValidationStatus);
  XCTAssertEqual(validations, 1);

  SNTCachedDecision* second = [processor decisionForFileInfo:mockFileInfo
                                               targetProcess:&proc
                                                imageCPUType:CPU_TYPE_ARM64
                                                 configState:configState
                                          activationCallback:nil
                                              cachedDecision:first];

  XCTAssertEqual(validations, 2, @"an unrecorded failure must be re-derived");
  XCTAssertNil(second.codesignValidationStatus);
  [mockFileInfo stopMocking];
  [mockConfigurator stopMocking];
  [mockRuleTable stopMocking];
}

- (SNTSigningStatus)signingStatusForCodesigningFlags:(uint32_t)csFlags
                                        imageCPUType:(cpu_type_t)imageCPUType {
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];

  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/bin/ls"];
  XCTAssertNotNil(fi);

  es_file_t file = MakeESFile("/bin/ls");
  es_process_t proc = MakeESProcess(&file);
  proc.codesigning_flags = csFlags;

  SNTConfigState* configState =
      [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];

  return [processor decisionForFileInfo:fi
                          targetProcess:&proc
                           imageCPUType:imageCPUType
                            configState:configState
                     activationCallback:nil
                         cachedDecision:nil]
      .signingStatus;
}

// CS_KILLED is invalid on every architecture. A CS_KILL-only image is invalid
// for native arm64, where signing is required, but remains unsigned on x86_64.
- (void)testSigningStatusFromCodesigningFlags {
  XCTAssertEqual([self signingStatusForCodesigningFlags:0 imageCPUType:CPU_TYPE_ARM64],
                 SNTSigningStatusUnsigned);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_KILLED imageCPUType:CPU_TYPE_ANY],
                 SNTSigningStatusInvalid);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_KILL imageCPUType:CPU_TYPE_ARM64],
                 SNTSigningStatusInvalid);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_KILL imageCPUType:CPU_TYPE_X86_64],
                 SNTSigningStatusUnsigned);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_SIGNED imageCPUType:CPU_TYPE_ANY],
                 SNTSigningStatusInvalid);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_SIGNED | CS_VALID | CS_ADHOC
                                           imageCPUType:CPU_TYPE_ANY],
                 SNTSigningStatusAdhoc);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_SIGNED | CS_VALID | CS_DEV_CODE
                                           imageCPUType:CPU_TYPE_ANY],
                 SNTSigningStatusDevelopment);
  XCTAssertEqual([self signingStatusForCodesigningFlags:CS_SIGNED | CS_VALID
                                           imageCPUType:CPU_TYPE_ANY],
                 SNTSigningStatusProduction);
}

- (void)testCELDecisions {
  ActivationCallbackBlock activation =
      ^std::unique_ptr<::google::api::expr::runtime::BaseActivation>(bool useV2) {
    auto makeActivation =
        [&]<bool IsV2>() -> std::unique_ptr<::google::api::expr::runtime::BaseActivation> {
      using ExecutableFileT = typename santa::cel::CELProtoTraits<IsV2>::ExecutableFileT;
      using AncestorT = typename santa::cel::CELProtoTraits<IsV2>::AncestorT;
      using FileDescriptorT = typename santa::cel::CELProtoTraits<IsV2>::FileDescriptorT;
      auto ef = std::make_unique<ExecutableFileT>();
      ef->mutable_signing_time()->set_seconds(1717987200);
      ef->mutable_secure_signing_time()->set_seconds(1717987200);

      return std::make_unique<santa::cel::Activation<IsV2>>(
          std::move(ef),
          ^std::vector<std::string>() {
            return std::vector<std::string>{"arg1", "arg2"};
          },
          ^std::map<std::string, std::string>() {
            return std::map<std::string, std::string>{{"ENV_VARIABLE1", "value1"},
                                                      {"OTHER_ENV_VAR", "value2"}};
          },
          ^uid_t() {
            return 0;
          },
          ^std::string() {
            return "/";
          },
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<AncestorT>() {
            return {};
          },
          ^std::vector<FileDescriptorT>() {
            return {};
          });
    };

    if (useV2) {
      return makeActivation.operator()<true>();
    } else {
      return makeActivation.operator()<false>();
    }
  };

  SNTRule* (^createCELRule)(NSString*, BOOL) = ^SNTRule*(NSString* celExpr, BOOL v2) {
    return [[SNTRule alloc]
           initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        state:v2 ? SNTRuleStateCELv2 : SNTRuleStateCEL
                         type:SNTRuleTypeBinary
                    customMsg:nil
                    customURL:nil
        eventDetailButtonText:nil
                    timestamp:0
                      comment:nil
                      celExpr:celExpr
               seatbeltPolicy:nil
                       ruleId:0
                        error:NULL];
  };
  {
    SNTRule* r = createCELRule(@"target.signing_time > timestamp(1717987100)", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertTrue(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"target.signing_time < timestamp(1717987100)", false);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertTrue(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"'arg1' in args", false);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"has(envs.ENV_VARIABLE1)", false);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"'--inspect' in args ? ALLOWLIST : SILENT_BLOCKLIST", false);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertTrue(cd.silentBlockGUI);
    XCTAssertTrue(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"euid != 0", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"cwd != '/Users/foo'", false);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }
  {
    SNTRule* r = createCELRule(@"euid == 0 ? REQUIRE_TOUCHID : ALLOWLIST", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertTrue(cd.holdAndAsk);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }
  {
    // CELv2 expression returning SEATBELT: rule starts at the block state for
    // its rule type, with cd.seatbeltRequired set so the execution controller
    // can enforce the expectation; non-cacheable because santactl registers
    // a fresh expectation per exec.
    SNTRule* r = createCELRule(@"SEATBELT", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertTrue(cd.seatbeltRequired);
    XCTAssertFalse(cd.cacheable);
  }
  {
    // Direct seatbelt rule (no CEL): same expectations as above, plus a
    // non-empty seatbeltPolicy on the rule.
    SNTRule* r = [[SNTRule alloc]
           initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        state:SNTRuleStateSeatbelt
                         type:SNTRuleTypeBinary
                    customMsg:nil
                    customURL:nil
        eventDetailButtonText:nil
                    timestamp:0
                      comment:nil
                      celExpr:nil
               seatbeltPolicy:@"(version 1)(deny default)"
                       ruleId:0
                        error:NULL];
    XCTAssertNotNil(r);
    XCTAssertEqualObjects(r.seatbeltPolicy, @"(version 1)(deny default)");
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertTrue(cd.seatbeltRequired);
    XCTAssertFalse(cd.cacheable);
  }
}

// A DB CEL rule (state CELv2) allows a matching binary, and repeated
// evaluation of the same identity yields the same decision (exercises the
// compiled-plan cache reuse path introduced in SNTPolicyProcessor).
- (void)testDBCELRuleCachedAcrossEvaluations {
  ActivationCallbackBlock activation =
      ^std::unique_ptr<::google::api::expr::runtime::BaseActivation>(bool useV2) {
    auto makeActivation =
        [&]<bool IsV2>() -> std::unique_ptr<::google::api::expr::runtime::BaseActivation> {
      using ExecutableFileT = typename santa::cel::CELProtoTraits<IsV2>::ExecutableFileT;
      using AncestorT = typename santa::cel::CELProtoTraits<IsV2>::AncestorT;
      using FileDescriptorT = typename santa::cel::CELProtoTraits<IsV2>::FileDescriptorT;
      auto ef = std::make_unique<ExecutableFileT>();
      ef->mutable_signing_time()->set_seconds(1717987200);
      ef->mutable_secure_signing_time()->set_seconds(1717987200);

      return std::make_unique<santa::cel::Activation<IsV2>>(
          std::move(ef),
          ^std::vector<std::string>() {
            return std::vector<std::string>{"arg1", "arg2"};
          },
          ^std::map<std::string, std::string>() {
            return std::map<std::string, std::string>{{"ENV_VARIABLE1", "value1"},
                                                      {"OTHER_ENV_VAR", "value2"}};
          },
          ^uid_t() {
            return 0;
          },
          ^std::string() {
            return "/";
          },
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<AncestorT>() {
            return {};
          },
          ^std::vector<FileDescriptorT>() {
            return {};
          });
    };

    if (useV2) {
      return makeActivation.operator()<true>();
    } else {
      return makeActivation.operator()<false>();
    }
  };

  SNTRule* (^createCELRule)(NSString*, BOOL) = ^SNTRule*(NSString* celExpr, BOOL v2) {
    return [[SNTRule alloc]
           initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        state:v2 ? SNTRuleStateCELv2 : SNTRuleStateCEL
                         type:SNTRuleTypeBinary
                    customMsg:nil
                    customURL:nil
        eventDetailButtonText:nil
                    timestamp:0
                      comment:nil
                      celExpr:celExpr
               seatbeltPolicy:nil
                       ruleId:0
                        error:NULL];
  };

  SNTRule* r = createCELRule(@"target.signing_time > timestamp(1717987100)", true);

  // First evaluation: compile-on-miss populates the plan cache.
  SNTCachedDecision* cd1 = [[SNTCachedDecision alloc] init];
  cd1.sha256 = r.identifier;
  [self.processor decision:cd1
                       forRule:r
           withTransitiveRules:YES
      andCELActivationCallback:activation];
  XCTAssertEqual(cd1.decision, SNTEventStateAllowBinary);

  // Second evaluation of the same rule/identity: cache hit path.
  SNTCachedDecision* cd2 = [[SNTCachedDecision alloc] init];
  cd2.sha256 = r.identifier;
  [self.processor decision:cd2
                       forRule:r
           withTransitiveRules:YES
      andCELActivationCallback:activation];
  XCTAssertEqual(cd2.decision, SNTEventStateAllowBinary);

  XCTAssertEqual(cd1.decision, cd2.decision);
}

- (SNTRule*)celV2RuleWithExpr:(NSString*)expr {
  return [[SNTRule alloc]
         initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                      state:SNTRuleStateCELv2
                       type:SNTRuleTypeBinary
                  customMsg:nil
                  customURL:nil
      eventDetailButtonText:nil
                  timestamp:0
                    comment:nil
                    celExpr:expr
             seatbeltPolicy:nil
                     ruleId:0
                      error:NULL];
}

// A database rule may use policy_for_range(): in range it decides with its
// policy argument, out of range with its out_of_range_policy argument. Either
// way the decision is not cacheable, because the window edge has to enforce
// itself on the next exec.
- (void)testCELRulePolicyForRange {
  SNTRule* inRange =
      [self celV2RuleWithExpr:@"policy_for_range([0, 1, 2, 3, 4, 5, 6], now() - duration('1h'), "
                              @"now() + duration('1h'), false, ALLOWLIST, BLOCKLIST)"];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = inRange.identifier;
  [self.processor decision:cd
                       forRule:inRange
           withTransitiveRules:YES
      andCELActivationCallback:[self fallbackTestActivationCallback]];
  XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
  XCTAssertFalse(cd.cacheable);

  SNTRule* outOfRange =
      [self celV2RuleWithExpr:@"policy_for_range([0, 1, 2, 3, 4, 5, 6], now() + duration('1h'), "
                              @"now() + duration('2h'), false, ALLOWLIST, BLOCKLIST)"];
  SNTCachedDecision* outCD = [[SNTCachedDecision alloc] init];
  outCD.sha256 = outOfRange.identifier;
  [self.processor decision:outCD
                       forRule:outOfRange
           withTransitiveRules:YES
      andCELActivationCallback:[self fallbackTestActivationCallback]];
  XCTAssertEqual(outCD.decision, SNTEventStateBlockBinary);
  XCTAssertFalse(outCD.cacheable);
}

// UNSPECIFIED is for fallback expressions, which have a next rule to fall
// through to; a database rule naming it fails to compile. The activation's euid
// is 501, so the ALLOWLIST branch is the one that would be taken: no decision
// here means the expression never compiled, not that it returned UNSPECIFIED.
- (void)testCELRuleCannotUseUnspecified {
  SNTRule* r = [self celV2RuleWithExpr:@"euid == 501 ? ALLOWLIST : UNSPECIFIED"];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = r.identifier;

  BOOL decisionIsFinal = [self.processor decision:cd
                                          forRule:r
                              withTransitiveRules:YES
                         andCELActivationCallback:[self fallbackTestActivationCallback]];
  XCTAssertFalse(decisionIsFinal);
  XCTAssertEqual(cd.decision, SNTEventStateUnknown);
}

- (void)testCELAncestors {
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;

  ActivationCallbackBlock activation =
      ^std::unique_ptr<::google::api::expr::runtime::BaseActivation>(bool useV2) {
    auto makeActivation =
        [&]<bool IsV2>() -> std::unique_ptr<::google::api::expr::runtime::BaseActivation> {
      using ExecutableFileT = typename santa::cel::CELProtoTraits<IsV2>::ExecutableFileT;
      using ActivationAncestorT = typename santa::cel::CELProtoTraits<IsV2>::AncestorT;
      using ActivationFileDescriptorT = typename santa::cel::CELProtoTraits<IsV2>::FileDescriptorT;
      auto ef = std::make_unique<ExecutableFileT>();

      return std::make_unique<santa::cel::Activation<IsV2>>(
          std::move(ef),
          ^std::vector<std::string>() {
            return std::vector<std::string>{"./malware", "--stealth"};
          },
          ^std::map<std::string, std::string>() {
            return std::map<std::string, std::string>{};
          },
          ^uid_t() {
            return 501;
          },
          ^std::string() {
            return "/Users/admin";
          },
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<ActivationAncestorT>() {
            if constexpr (IsV2) {
              AncestorT launchd;
              launchd.set_path("/sbin/launchd");
              launchd.set_signing_id("platform:com.apple.xpc.launchd");
              launchd.set_team_id("");
              launchd.set_cdhash("abcd1234abcd1234abcd1234abcd1234abcd1234");

              AncestorT terminal;
              terminal.set_path("/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal");
              terminal.set_signing_id("platform:com.apple.Terminal");
              terminal.set_team_id("");
              terminal.set_cdhash("ef012345ef012345ef012345ef012345ef012345");

              AncestorT zsh;
              zsh.set_path("/bin/zsh");
              zsh.set_signing_id("platform:com.apple.zsh");
              zsh.set_team_id("");
              zsh.set_cdhash("56789abc56789abc56789abc56789abc56789abc");

              AncestorT curl;
              curl.set_path("/usr/bin/curl");
              curl.add_args("curl");
              curl.add_args("-fsSL");
              curl.set_signing_id("platform:com.apple.curl");
              curl.set_team_id("");
              curl.set_cdhash("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");

              return std::vector<AncestorT>{curl, zsh, terminal, launchd};
            } else {
              return {};
            }
          },
          ^std::vector<ActivationFileDescriptorT>() {
            return {};
          });
    };

    if (useV2) {
      return makeActivation.operator()<true>();
    } else {
      return makeActivation.operator()<false>();
    }
  };

  SNTRule* (^createCELRule)(NSString*, BOOL) = ^SNTRule*(NSString* celExpr, BOOL v2) {
    return [[SNTRule alloc]
           initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                        state:v2 ? SNTRuleStateCELv2 : SNTRuleStateCEL
                         type:SNTRuleTypeBinary
                    customMsg:nil
                    customURL:nil
        eventDetailButtonText:nil
                    timestamp:0
                      comment:nil
                      celExpr:celExpr
               seatbeltPolicy:nil
                       ruleId:0
                        error:NULL];
  };

  // Test: Check that an ancestor with a specific path exists
  {
    SNTRule* r = createCELRule(@"ancestors.exists(a, a.path == '/bin/zsh')", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Check that no ancestor matches a non-existent path
  {
    SNTRule* r = createCELRule(@"ancestors.exists(a, a.path == '/usr/bin/python3')", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Block if any ancestor has a specific signing_id
  {
    SNTRule* r = createCELRule(@"ancestors.exists(a, a.signing_id == 'platform:com.apple.curl') "
                                "? BLOCKLIST : ALLOWLIST",
                               true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Verify all ancestors are platform binaries (signing_id starts with "platform:")
  {
    SNTRule* r = createCELRule(@"ancestors.all(a, a.signing_id.startsWith('platform:'))", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Check ancestor list size
  {
    SNTRule* r = createCELRule(@"size(ancestors) == 4", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Block if launched from Terminal (checking ancestor path with endsWith)
  {
    SNTRule* r = createCELRule(
        @"ancestors.exists(a, a.path.endsWith('/Terminal')) ? BLOCKLIST : ALLOWLIST", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateBlockBinary);
    XCTAssertFalse(cd.silentBlockGUI);
    XCTAssertFalse(cd.silentBlockTTY);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Match ancestor by cdhash
  {
    SNTRule* r = createCELRule(
        @"ancestors.exists(a, a.cdhash == 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef')", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.cacheable);
  }

  // Test: Index into a repeated field nested within an ancestor (ancestors[0] is curl).
  {
    SNTRule* r = createCELRule(@"ancestors[0].args[1] == '-fsSL'", true);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = r.identifier;
    [self.processor decision:cd
                         forRule:r
             withTransitiveRules:YES
        andCELActivationCallback:activation];
    XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
    XCTAssertFalse(cd.cacheable);
  }
}

#pragma mark - CEL Fallback Expression Tests

- (ActivationCallbackBlock)fallbackTestActivationCallback {
  return ^std::unique_ptr<::google::api::expr::runtime::BaseActivation>(bool useV2) {
    using ExecutableFileT = typename santa::cel::CELProtoTraits<true>::ExecutableFileT;
    using AncestorT = typename santa::cel::CELProtoTraits<true>::AncestorT;
    using FileDescriptorT = typename santa::cel::CELProtoTraits<true>::FileDescriptorT;

    auto ef = std::make_unique<ExecutableFileT>();
    ef->set_signing_id("ZMCG7MLDV9:com.example.testbinary");

    if (useV2) {
      return std::make_unique<santa::cel::Activation<true>>(
          std::move(ef),
          ^std::vector<std::string>() {
            return {"arg0", "arg1"};
          },
          ^std::map<std::string, std::string>() {
            return {{"HOME", "/Users/test"}};
          },
          ^uid_t() {
            return 501;
          },
          ^std::string() {
            return "/tmp";
          },
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<AncestorT>() {
            return {};
          },
          ^std::vector<FileDescriptorT>() {
            return {};
          });
    } else {
      using V1FileT = typename santa::cel::CELProtoTraits<false>::ExecutableFileT;
      using V1AncestorT = typename santa::cel::CELProtoTraits<false>::AncestorT;
      using V1FileDescriptorT = typename santa::cel::CELProtoTraits<false>::FileDescriptorT;
      auto v1ef = std::make_unique<V1FileT>();
      return std::make_unique<santa::cel::Activation<false>>(
          std::move(v1ef),
          ^std::vector<std::string>() {
            return {};
          },
          ^std::map<std::string, std::string>() {
            return {};
          },
          ^uid_t() {
            return 0;
          },
          ^std::string() {
            return "";
          },
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<V1AncestorT>() {
            return {};
          },
          ^std::vector<V1FileDescriptorT>() {
            return {};
          });
    }
  };
}

- (SNTCELFallbackRule*)ruleWithExpr:(NSString*)expr {
  return [[SNTCELFallbackRule alloc] initWithCELExpr:expr
                                           customMsg:nil
                                           customURL:nil
                               eventDetailButtonText:nil];
}

- (void)testCELFallbackExpressionAllow {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateAllowCELFallback);
}

- (void)testCELFallbackExpressionBlock {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"BLOCKLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateBlockCELFallback);
}

- (void)testCELFallbackExpressionSilentBlock {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"SILENT_BLOCKLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateBlockCELFallback);
  XCTAssertTrue(cd.silentBlockGUI);
  XCTAssertTrue(cd.silentBlockTTY);
}

- (void)testCELFallbackUnspecifiedSkipsToNext {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"UNSPECIFIED"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateAllowCELFallback);
}

// A fallback chain's cacheability is the AND of every rule evaluated, not just
// the one that produces the decision. If an earlier rule reads per-execution
// context (args here) and then falls through with UNSPECIFIED, a later constant
// ALLOWLIST must not be cached: the ES cache is keyed by vnode, so a different
// exec with different args could be wrongly auto-allowed. This depends on
// cd.cacheable being applied before the early UNSPECIFIED return and on the
// shared activation's memoizer state persisting across the chain.
- (void)testCELFallbackChainContextFallThroughIsNotCacheable {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"size(args) > 100 ? ALLOWLIST : UNSPECIFIED"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";
  XCTAssertTrue(cd.cacheable);  // sanity: starts cacheable

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateAllowCELFallback);
  XCTAssertFalse(cd.cacheable);
}

// As above, but the earlier rule uses today() (relative time) before falling
// through. today() makes the result non-cacheable, and that must stick through
// to the constant ALLOWLIST that follows.
- (void)testCELFallbackChainRelativeTimeFallThroughIsNotCacheable {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"today() == today() ? UNSPECIFIED : ALLOWLIST"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateAllowCELFallback);
  XCTAssertFalse(cd.cacheable);
}

// Control: a constant-only chain (no per-exec context, no today()) stays
// cacheable, proving the assertions above flip due to the context touch and not
// merely because the chain fell through.
- (void)testCELFallbackChainConstantFallThroughStaysCacheable {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"UNSPECIFIED"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateAllowCELFallback);
  XCTAssertTrue(cd.cacheable);
}

- (void)testCELFallbackAllUnspecifiedFallsThrough {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"UNSPECIFIED"],
    [self ruleWithExpr:@"UNSPECIFIED"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertFalse(handled);
}

- (void)testCELFallbackFirstMatchWins {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"BLOCKLIST"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateBlockCELFallback);
}

- (void)testCELFallbackEmptyRulesReturnNO {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertFalse(handled);
}

- (void)testCELFallbackWithTargetField {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self
        ruleWithExpr:
            @"target.signing_id == 'ZMCG7MLDV9:com.example.testbinary' ? ALLOWLIST : UNSPECIFIED"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateAllowCELFallback);
}

- (void)testCELFallbackUncacheableFieldsAreAvailable {
  // The full activation (including args) is passed through to fallback rules.
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"size(args) > 0 ? BLOCKLIST : UNSPECIFIED"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  // args has ["arg0", "arg1"], so size(args) > 0 is true, returning BLOCKLIST
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateBlockCELFallback);
}

// policy_for_range() is declared for database rules only, so a fallback
// expression naming it fails to compile like any other unknown function. A
// compile failure drops the whole batch, so the ALLOWLIST behind it never gets
// a chance and the empty batch published at init still stands.
- (void)testCELFallbackCannotUsePolicyForRange {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"policy_for_range(duration('30m'), false, ALLOWLIST)"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertFalse(handled);
  XCTAssertEqual(cd.decision, SNTEventStateUnknown);

  // UNSPECIFIED, on the other hand, is still declared for fallback expressions:
  // the same batch shape compiles and the second rule decides.
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"UNSPECIFIED"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* control = [[SNTCachedDecision alloc] init];
  control.sha256 = @"aabbccdd";

  XCTAssertTrue([self.processor
      evaluateCELFallbackExpressions:control
                  activationCallback:[self fallbackTestActivationCallback]]);
  XCTAssertEqual(control.decision, SNTEventStateAllowCELFallback);
}

- (void)testCELFallbackInvalidExpressionSkipped {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"this is invalid !!!"],
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertFalse(handled);
}

- (void)testCELFallbackNilActivationCallbackReturnNO {
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[
    [self ruleWithExpr:@"ALLOWLIST"],
  ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled = [self.processor evaluateCELFallbackExpressions:cd activationCallback:nil];
  XCTAssertFalse(handled);
}

- (void)testCELFallbackCustomMsgAndURL {
  SNTCELFallbackRule* rule =
      [[SNTCELFallbackRule alloc] initWithCELExpr:@"BLOCKLIST"
                                        customMsg:@"Custom block message"
                                        customURL:@"https://example.com/details"
                            eventDetailButtonText:@"Request Access"];
  [[SNTConfigurator configurator] setSyncServerCELFallbackRules:@[ rule ]];
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aabbccdd";

  BOOL handled =
      [self.processor evaluateCELFallbackExpressions:cd
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(handled);
  XCTAssertEqual(cd.decision, SNTEventStateBlockCELFallback);
  XCTAssertEqualObjects(cd.customMsg, @"Custom block message");
  XCTAssertEqualObjects(cd.customURL, @"https://example.com/details");
  XCTAssertEqualObjects(cd.eventDetailButtonText, @"Request Access");
}

// Concurrent evaluation while another thread repeatedly recompiles/swaps the
// fallback rule set (held in the atomically-swapped shared_ptr<const
// FallbackBatch>). Every rule set installed here is non-empty and matches
// unconditionally (ALLOWLIST/BLOCKLIST), and the initial set is published before
// any thread starts, so a correct swap always yields a fallback decision. A
// handled == NO result, a decision that is neither allow nor block, a crash, or
// a UAF would each mean a reader observed a torn/lost/empty batch (a broken
// swap), so all are treated as failures.
- (void)testCELFallbackConcurrentEvalDuringRecompile {
  // Sanity: install rules directly through the writer entry point and confirm
  // the eval path is wired before introducing any concurrency.
  [self.processor compileFallbackRules:@[ [self ruleWithExpr:@"ALLOWLIST"] ]];
  SNTCachedDecision* sanityCD = [[SNTCachedDecision alloc] init];
  sanityCD.sha256 = @"aabbccdd";
  BOOL sanityHandled =
      [self.processor evaluateCELFallbackExpressions:sanityCD
                                  activationCallback:[self fallbackTestActivationCallback]];
  XCTAssertTrue(sanityHandled);
  XCTAssertEqual(sanityCD.decision, SNTEventStateAllowCELFallback);

  // Three distinct non-empty rule sets the writer thread cycles through.
  NSArray<NSArray<SNTCELFallbackRule*>*>* ruleSets = @[
    @[ [self ruleWithExpr:@"ALLOWLIST"] ],
    @[ [self ruleWithExpr:@"BLOCKLIST"] ],
    @[ [self ruleWithExpr:@"BLOCKLIST"], [self ruleWithExpr:@"ALLOWLIST"] ],
  ];

  constexpr int kWriterIters = 500;
  constexpr int kReaderThreads = 8;
  constexpr int kReaderIters = 1500;
  std::atomic<int> failures{0};

  SNTPolicyProcessor* processor = self.processor;

  std::thread writer([processor, ruleSets]() {
    for (int i = 0; i < kWriterIters; i++) {
      [processor compileFallbackRules:ruleSets[i % 3]];
    }
  });

  std::vector<std::thread> readers;
  readers.reserve(kReaderThreads);
  for (int t = 0; t < kReaderThreads; t++) {
    readers.emplace_back([self, processor, &failures]() {
      for (int i = 0; i < kReaderIters; i++) {
        SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
        cd.sha256 = @"aabbccdd";
        BOOL handled =
            [processor evaluateCELFallbackExpressions:cd
                                   activationCallback:[self fallbackTestActivationCallback]];
        // A correct swap always yields a fallback decision (see the test's doc
        // comment), so NO — or any other decision — is a failure.
        if (!handled || (cd.decision != SNTEventStateAllowCELFallback &&
                         cd.decision != SNTEventStateBlockCELFallback)) {
          failures.fetch_add(1);
        }
      }
    });
  }

  writer.join();
  for (auto& th : readers) {
    th.join();
  }

  XCTAssertEqual(failures.load(), 0);
}

- (void)testRuleIdPropagation {
  SNTRule* rule = [[SNTRule alloc] initWithIdentifier:@"a023fbe5361a5bbd793dc3889556e93f41ec9bb8"
                                                state:SNTRuleStateBlock
                                                 type:SNTRuleTypeCDHash
                                            customMsg:nil
                                            customURL:nil
                                eventDetailButtonText:nil
                                              celExpr:nil
                                       seatbeltPolicy:nil
                                               ruleId:42];

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.cdhash = rule.identifier;
  [self.processor decision:cd forRule:rule withTransitiveRules:YES andCELActivationCallback:nil];
  XCTAssertEqual(cd.decision, SNTEventStateBlockCDHash);
  XCTAssertEqual(cd.ruleId, 42LL);
}

- (void)testRuleIdZeroWhenNotSet {
  SNTRule* rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST"
  }
                                                error:nil];
  XCTAssertNotNil(rule);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = rule.identifier;
  [self.processor decision:cd forRule:rule withTransitiveRules:YES andCELActivationCallback:nil];
  XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
  XCTAssertEqual(cd.ruleId, 0LL);
}

- (SNTCachedDecision*)decisionForPlatformBinary:(BOOL)isPlatformBinary {
  // Class-mock the rule table so it returns nil for every lookup, leaving
  // the platform-binary case as the only decision path that can fire.
  id mockRuleTable = OCMClassMock([SNTRuleTable class]);
  SNTPolicyProcessor* processor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:mockRuleTable
                                 entitlementsFilter:santa::EntitlementsFilter::Create(@[], @[])];

  // /bin/ls is an Apple-signed platform binary present on every macOS host.
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/bin/ls"];
  XCTAssertNotNil(fi);

  es_file_t file = MakeESFile("/bin/ls");
  es_process_t proc = MakeESProcess(&file);
  proc.is_platform_binary = isPlatformBinary;
  proc.codesigning_flags = CS_SIGNED | CS_VALID;

  SNTConfigState* configState =
      [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];

  return [processor decisionForFileInfo:fi
                          targetProcess:&proc
                           imageCPUType:CPU_TYPE_ARM64
                            configState:configState
                     activationCallback:nil
                         cachedDecision:nil];
}

- (void)testDecisionAllowsPlatformBinary {
  SNTCachedDecision* cd = [self decisionForPlatformBinary:YES];
  XCTAssertEqual(cd.decision, SNTEventStateAllowPlatform);
  XCTAssertEqualObjects(cd.decisionExtra, @"Platform Binary");
}

- (void)testDecisionDoesNotApplyPlatformBinaryToNonPlatformBinaries {
  SNTCachedDecision* cd = [self decisionForPlatformBinary:NO];
  XCTAssertNotEqual(cd.decision, SNTEventStateAllowPlatform);
  XCTAssertNotEqualObjects(cd.decisionExtra, @"Platform Binary");
}

#pragma mark fileIsScopeAllowed:/fileIsScopeBlocked:

// /bin/ls is an Apple-signed Mach-O executable (with a __PAGEZERO segment)
// present on every macOS host, so it exercises the Mach-O and page-zero paths
// without needing a fixture.
- (SNTFileInfo*)lsFileInfo {
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/bin/ls"];
  XCTAssertNotNil(fi);
  return fi;
}

- (void)testFileIsScopeAllowedWithNoRegexReturnsNilForMachO {
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator allowedPathRegex]).andReturn(nil);
  self.processor.configurator = mockConfigurator;

  // No allowed-path regex: a Mach-O must not be reported as allowed-by-path.
  // (Guards against a nil regex being treated as a match.)
  XCTAssertNil([self.processor fileIsScopeAllowed:[self lsFileInfo]]);

  [mockConfigurator stopMocking];
}

- (void)testFileIsScopeAllowedWithMatchingRegexReturnsReason {
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator allowedPathRegex])
      .andReturn([NSRegularExpression regularExpressionWithPattern:@"^/bin/" options:0 error:NULL]);
  self.processor.configurator = mockConfigurator;

  XCTAssertEqualObjects([self.processor fileIsScopeAllowed:[self lsFileInfo]],
                        @"Allowed Path Regex");

  [mockConfigurator stopMocking];
}

- (void)testFileIsScopeBlockedWithNoRegexReturnsNil {
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator blockedPathRegex]).andReturn(nil);
  OCMStub([mockConfigurator enablePageZeroProtection]).andReturn(NO);
  self.processor.configurator = mockConfigurator;

  // No blocked-path regex: a normal Mach-O must not be reported as
  // blocked-by-path. (Guards against a nil regex being treated as a match.)
  XCTAssertNil([self.processor fileIsScopeBlocked:[self lsFileInfo]]);

  [mockConfigurator stopMocking];
}

- (void)testFileIsScopeBlockedWithMatchingRegexReturnsReason {
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator blockedPathRegex])
      .andReturn([NSRegularExpression regularExpressionWithPattern:@"^/bin/" options:0 error:NULL]);
  self.processor.configurator = mockConfigurator;

  XCTAssertEqualObjects([self.processor fileIsScopeBlocked:[self lsFileInfo]],
                        @"Blocked Path Regex");

  [mockConfigurator stopMocking];
}

@end
