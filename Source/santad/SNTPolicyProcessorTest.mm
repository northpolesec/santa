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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <Kernel/kern/cs_blobs.h>
#include <sys/stat.h>
#include <unistd.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCELFallbackRule.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigState.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#include "Source/common/ScopedFile.h"
#import "Source/common/TestUtils.h"
#import "Source/common/cel/Activation.h"

#include "cel/v1.pb.h"

extern struct RuleIdentifiers CreateRuleIDs(SNTCachedDecision* cd);

@interface SNTPolicyProcessor (Testing)
- (BOOL)evaluateCELFallbackExpressions:(SNTCachedDecision*)cd
                    activationCallback:(ActivationCallbackBlock)activationCallback;
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

// Helpers for the verifyIdentity tests at the bottom of the file.
static const uint8_t kHashA[20] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                   0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14};
static const uint8_t kHashB[20] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
                                   0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd};

static NSString* HexOf(const uint8_t* b, size_t n) {
  NSMutableString* s = [NSMutableString stringWithCapacity:n * 2];
  for (size_t i = 0; i < n; i++)
    [s appendFormat:@"%02x", b[i]];
  return s;
}

// Builds an es_file_t + es_process_t pair. The es_file_t is stored in an out-param
// since es_process_t holds a pointer into it. Caller keeps both alive for the test.
static void MakeTargetProc(es_file_t* outFile, es_process_t* outProc, const char* path,
                           struct stat sb, uint32_t csFlags, const char* teamID,
                           const char* signingID, const uint8_t cdhash[20]) {
  *outFile = MakeESFile(path, sb);
  *outProc = MakeESProcess(outFile);
  outProc->codesigning_flags = csFlags;
  outProc->team_id = MakeESStringToken(teamID);
  outProc->signing_id = MakeESStringToken(signingID);
  memcpy(outProc->cdhash, cdhash, 20);
}

static MOLCodesignChecker* MakeMockChecker(NSString* cdhash, NSString* teamID,
                                           NSString* signingID) {
  MOLCodesignChecker* m = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([m cdhash]).andReturn(cdhash);
  OCMStub([m teamID]).andReturn(teamID);
  OCMStub([m signingID]).andReturn(signingID);
  return m;
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
  XCTAssertEqual(cd.silentBlock, silent);
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
                 timestamp:0
                   comment:nil
                   celExpr:celExpr
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertTrue(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
    XCTAssertFalse(cd.cacheable);
  }
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
                 timestamp:0
                   comment:nil
                   celExpr:celExpr
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
    XCTAssertFalse(cd.silentBlock);
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
    XCTAssertFalse(cd.silentBlock);
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
  return [[SNTCELFallbackRule alloc] initWithCELExpr:expr customMsg:nil customURL:nil];
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
  XCTAssertTrue(cd.silentBlock);
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
                                        customURL:@"https://example.com/details"];
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
}

- (void)testRuleIdPropagation {
  SNTRule* rule = [[SNTRule alloc] initWithIdentifier:@"a023fbe5361a5bbd793dc3889556e93f41ec9bb8"
                                                state:SNTRuleStateBlock
                                                 type:SNTRuleTypeCDHash
                                            customMsg:nil
                                            customURL:nil
                                              celExpr:nil
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

#pragma mark - End-to-end integration tests (outer decisionForFileInfo:targetProcess:…)

// Unsigned file + ES stat that disagrees with disk → should return BlockBinaryMismatch.
- (void)testOuter_Unsigned_StatMismatch_ReturnsBlockBinaryMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(
      /*path_prefix=*/nil, /*size=*/16,
      /*filename_template=*/@"santa_test_XXXXXX", /*keep_path=*/true);
  XCTAssertStatusOk(scopedFile);

  NSError* err;
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:scopedFile->Path() error:&err];
  XCTAssertNotNil(fi);

  struct stat fakeStat = MakeStat(/*offset=*/42);  // differs from the real file's stat
  es_file_t esFile = MakeESFile(scopedFile->Path().UTF8String, fakeStat);
  es_process_t esProc = MakeESProcess(&esFile);
  esProc.codesigning_flags = 0;  // unsigned
  esProc.team_id = MakeESStringToken("");
  esProc.signing_id = MakeESStringToken("");

  SNTConfigState* cs = [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];

  SNTCachedDecision* cd = [self.processor decisionForFileInfo:fi
                                                targetProcess:&esProc
                                                  configState:cs
                                           activationCallback:nil
                                               cachedDecision:nil];

  XCTAssertEqual(cd.decision, SNTEventStateBlockBinaryMismatch);
  XCTAssertEqualObjects(cd.decisionExtra,
                        @"Binary identity mismatch between ES event and on-disk file");
  XCTAssertFalse(cd.holdAndAsk, @"mismatch must never be TouchID-overridable");
  XCTAssertNotEqual(cd.decision & SNTEventStateBlock, (SNTEventState)0);
  XCTAssertEqual(cd.decision & SNTEventStateAllow, (SNTEventState)0);
}

// Re-eval path (existingDecision non-nil) with ES/disk disagreement: verifyIdentity is skipped,
// so BlockBinaryMismatch must NOT be returned.
- (void)testOuter_ReEvalPath_VerificationSkipped {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 16, @"santa_test_XXXXXX",
                                                       /*keep_path=*/true);
  XCTAssertStatusOk(scopedFile);

  NSError* err;
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:scopedFile->Path() error:&err];
  XCTAssertNotNil(fi);

  // Deliberate stat mismatch — if verifyIdentity ran, this would short-circuit to
  // SNTEventStateBlockBinaryMismatch.
  struct stat fakeStat = MakeStat(/*offset=*/42);
  es_file_t esFile = MakeESFile(scopedFile->Path().UTF8String, fakeStat);
  es_process_t esProc = MakeESProcess(&esFile);
  esProc.codesigning_flags = 0;
  esProc.team_id = MakeESStringToken("");
  esProc.signing_id = MakeESStringToken("");

  // Seed an existing decision with NO certSHA256 — so the inner method's codesign
  // branch (`if (!cd.certSHA256.length)`) would fire and would invoke verifyIdentity
  // if it were non-nil. The bypass invariant under test is that the outer method
  // passes verifyIdentity:nil whenever existingDecision is non-nil (per spec §4),
  // independent of the inner method's certSHA256-skip optimization.
  SNTCachedDecision* existing = [[SNTCachedDecision alloc] init];
  // Do NOT set certSHA256.

  SNTConfigState* cs = [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];

  SNTCachedDecision* cd = [self.processor decisionForFileInfo:fi
                                                targetProcess:&esProc
                                                  configState:cs
                                           activationCallback:nil
                                               cachedDecision:existing];

  XCTAssertNotEqual(cd.decision, SNTEventStateBlockBinaryMismatch,
                    @"re-eval path must never surface BinaryMismatch (outer method "
                    @"is required to pass verifyIdentity:nil when existingDecision "
                    @"is non-nil per spec §4)");
}

// Unsigned file + ES stat that agrees with disk → should NOT return BlockBinaryMismatch.
- (void)testOuter_Unsigned_StatMatches_NoMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 16, @"santa_test_XXXXXX",
                                                       /*keep_path=*/true);
  XCTAssertStatusOk(scopedFile);

  NSError* err;
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:scopedFile->Path() error:&err];
  XCTAssertNotNil(fi);

  struct stat realStat;
  XCTAssertEqual(fstat(fi.fileHandle.fileDescriptor, &realStat), 0);

  es_file_t esFile = MakeESFile(scopedFile->Path().UTF8String, realStat);
  es_process_t esProc = MakeESProcess(&esFile);
  esProc.codesigning_flags = 0;
  esProc.team_id = MakeESStringToken("");
  esProc.signing_id = MakeESStringToken("");

  SNTConfigState* cs = [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];

  SNTCachedDecision* cd = [self.processor decisionForFileInfo:fi
                                                targetProcess:&esProc
                                                  configState:cs
                                           activationCallback:nil
                                               cachedDecision:nil];

  XCTAssertNotEqual(cd.decision, SNTEventStateBlockBinaryMismatch);
}

#pragma mark - +verifyIdentityForTargetProc:fd:csInfo: tests

// Case 1: ES signed, disk unsigned (csInfo == nil) -> Mismatch.
- (void)testVerifyIdentity_SignednessDisagrees_EsSignedDiskUnsigned_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T", "S", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

// Case 1 (symmetric): ES unsigned, disk signed -> Mismatch.
- (void)testVerifyIdentity_SignednessDisagrees_EsUnsignedDiskSigned_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), /*csFlags=*/0, "", "", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"T", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Case 2: only ES has TID/SID -> Mismatch.
- (void)testVerifyIdentity_IDPresenceDisagrees_OnlyEsHasIDs_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T", "S", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"", @"");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Case 2: only disk has TID/SID -> Mismatch.
- (void)testVerifyIdentity_IDPresenceDisagrees_OnlyDiskHasIDs_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "", "", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"T", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Case 3: both have IDs, team ID differs -> Mismatch.
- (void)testVerifyIdentity_BothHaveIDs_TeamIDDiffers_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T1", "S", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"T2", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Case 3: both have IDs, signing ID differs -> Mismatch.
- (void)testVerifyIdentity_BothHaveIDs_SigningIDDiffers_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T", "S1", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"T", @"S2");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Case 3: both have IDs, IDs agree, cdhash agrees -> Match.
- (void)testVerifyIdentity_BothHaveIDs_IDsAgreeCdhashAgrees_ReturnsMatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T", "S", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"T", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMatch);
}

// Case 3: both have IDs, IDs agree, cdhash drifts -> DriftAllowed.
- (void)testVerifyIdentity_BothHaveIDs_IDsAgreeCdhashDrifts_ReturnsDriftAllowed {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T", "S", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashB, 20), @"T", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kDriftAllowed);
}

// Case 4: both signed, neither has TID/SID (ad-hoc), cdhash agrees -> Match.
- (void)testVerifyIdentity_BothSignedNeitherHasIDs_CdhashAgrees_ReturnsMatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "", "", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), nil, nil);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMatch);
}

// Case 4: both signed, neither has TID/SID (ad-hoc), cdhash differs -> Mismatch.
- (void)testVerifyIdentity_BothSignedNeitherHasIDs_CdhashDiffers_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "", "", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashB, 20), nil, nil);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Edge case: signed ES target but disk cdhash is empty -> diskSigned=false ->
// signedness disagrees (Case 1) -> Mismatch. (This path returns from Case 1, not
// from the unsigned-path Case 5.)
- (void)testVerifyIdentity_SignedTargetDiskCdhashEmpty_TreatedAsUnsigned_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, "T", "S", kHashA);
  MOLCodesignChecker* csInfo = MakeMockChecker(@"", @"T", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Case 5: both unsigned, stat fields all agree -> Match.
- (void)testVerifyIdentity_Unsigned_StatMatches_ReturnsMatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(/*path_prefix=*/nil, /*size=*/100);
  XCTAssertStatusOk(scopedFile);
  struct stat realStat;
  XCTAssertEqual(fstat(scopedFile->UnsafeFD(), &realStat), 0);
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", realStat, /*csFlags=*/0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc
                                                              fd:scopedFile->UnsafeFD()
                                                          csInfo:nil],
                 IdentityVerifyResult::kMatch);
}

// Case 5: both unsigned, st_dev differs -> Mismatch.
- (void)testVerifyIdentity_Unsigned_DevDiffers_ReturnsMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 100);
  XCTAssertStatusOk(scopedFile);
  struct stat realStat;
  XCTAssertEqual(fstat(scopedFile->UnsafeFD(), &realStat), 0);
  realStat.st_dev += 1;
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", realStat, 0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc
                                                              fd:scopedFile->UnsafeFD()
                                                          csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

// Case 5: both unsigned, st_ino differs -> Mismatch.
- (void)testVerifyIdentity_Unsigned_InoDiffers_ReturnsMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 100);
  XCTAssertStatusOk(scopedFile);
  struct stat realStat;
  XCTAssertEqual(fstat(scopedFile->UnsafeFD(), &realStat), 0);
  realStat.st_ino += 1;
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", realStat, 0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc
                                                              fd:scopedFile->UnsafeFD()
                                                          csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

// Case 5: both unsigned, st_size differs -> Mismatch.
- (void)testVerifyIdentity_Unsigned_SizeDiffers_ReturnsMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 100);
  XCTAssertStatusOk(scopedFile);
  struct stat realStat;
  XCTAssertEqual(fstat(scopedFile->UnsafeFD(), &realStat), 0);
  realStat.st_size += 1;
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", realStat, 0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc
                                                              fd:scopedFile->UnsafeFD()
                                                          csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

// Case 5: both unsigned, st_mtimespec.tv_sec differs -> Mismatch.
- (void)testVerifyIdentity_Unsigned_MtimeSecDiffers_ReturnsMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 100);
  XCTAssertStatusOk(scopedFile);
  struct stat realStat;
  XCTAssertEqual(fstat(scopedFile->UnsafeFD(), &realStat), 0);
  realStat.st_mtimespec.tv_sec += 1;
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", realStat, 0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc
                                                              fd:scopedFile->UnsafeFD()
                                                          csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

// Case 5: both unsigned, st_mtimespec.tv_nsec differs -> Mismatch.
- (void)testVerifyIdentity_Unsigned_MtimeNsecDiffers_ReturnsMismatch {
  auto scopedFile = santa::ScopedFile::CreateTemporary(nil, 100);
  XCTAssertStatusOk(scopedFile);
  struct stat realStat;
  XCTAssertEqual(fstat(scopedFile->UnsafeFD(), &realStat), 0);
  realStat.st_mtimespec.tv_nsec += 1;
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", realStat, 0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc
                                                              fd:scopedFile->UnsafeFD()
                                                          csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

// Case 5: both unsigned, fstat fails (invalid fd) -> Mismatch (fail-closed).
- (void)testVerifyIdentity_Unsigned_FstatFails_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), /*csFlags=*/0, "", "", kHashA);
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:nil],
                 IdentityVerifyResult::kMismatch);
}

#pragma mark - Platform-binary team_id suppression (ES quirk)

// ES does not populate team_id on the target field for binaries with
// is_platform_binary=true, even when the on-disk signature carries a TeamID.
// Observed in production for Apple-signed XPC services inside framework
// bundles (Xcode helpers, Apple developer tooling). The verifier accommodates
// this by suspending the team_id presence and equality checks on that path —
// signing_id and cdhash continue to bind identity end-to-end. The four tests
// below pin: the production case matches, drift still reaches kDriftAllowed,
// signing_id mismatch still bites, and the non-platform path is unaffected.

// Platform binary, ES team_id suppressed, disk has team_id, signing_id and
// cdhash agree -> Match. The shape every Apple-signed XPC service produces.
- (void)testVerifyIdentity_PlatformBinary_ESTeamSuppressed_DiskHasTeam_ReturnsMatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, /*team=*/"",
                 /*sid=*/"com.apple.dt.X", kHashA);
  XCTAssertTrue(proc.is_platform_binary);  // default from MakeESProcess
  MOLCodesignChecker* csInfo =
      MakeMockChecker(HexOf(kHashA, 20), @"59GAB85EFG", @"com.apple.dt.X");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMatch);
}

// Platform binary, ES team_id suppressed, signing_id agrees, cdhash drifts ->
// DriftAllowed. Same publisher (signing_id namespace), so the existing
// drift-within-publisher reasoning carries over.
- (void)testVerifyIdentity_PlatformBinary_ESTeamSuppressed_CdhashDrifts_ReturnsDriftAllowed {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, /*team=*/"",
                 /*sid=*/"com.apple.dt.X", kHashA);
  MOLCodesignChecker* csInfo =
      MakeMockChecker(HexOf(kHashB, 20), @"59GAB85EFG", @"com.apple.dt.X");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kDriftAllowed);
}

// Platform binary, ES team_id suppressed, signing_ids differ -> Mismatch.
// Confirms signing_id equality still gates even when team is suppressed.
- (void)testVerifyIdentity_PlatformBinary_ESTeamSuppressed_SigningIDDiffers_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, /*team=*/"",
                 /*sid=*/"com.apple.dt.X", kHashA);
  MOLCodesignChecker* csInfo =
      MakeMockChecker(HexOf(kHashA, 20), @"59GAB85EFG", @"com.apple.dt.Y");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

// Non-platform binary, ES omits team_id but disk has one -> Mismatch.
// Confirms the platform-binary relaxation does not bleed into the third-party
// path: ES omitting team_id outside is_platform_binary=true is a real
// presence disagreement and case-2 still bites.
- (void)testVerifyIdentity_NonPlatform_ESNoTeam_DiskHasTeam_ReturnsMismatch {
  es_file_t file;
  es_process_t proc;
  MakeTargetProc(&file, &proc, "/tmp/test", MakeStat(), CS_SIGNED, /*team=*/"", /*sid=*/"S",
                 kHashA);
  proc.is_platform_binary = false;
  MOLCodesignChecker* csInfo = MakeMockChecker(HexOf(kHashA, 20), @"T", @"S");
  XCTAssertEqual([SNTPolicyProcessor verifyIdentityForTargetProc:&proc fd:-1 csInfo:csInfo],
                 IdentityVerifyResult::kMismatch);
}

@end
