/// Copyright 2024 Google Inc. All rights reserved.
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

#import "Source/santad/SNTPolicyProcessor.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/cel/Activation.h"
#import "Source/santad/SNTPolicyProcessor.h"

#import "cel/v1.pb.h"

extern struct RuleIdentifiers CreateRuleIDs(SNTCachedDecision *cd);

BOOL CompareMaybeNilStrings(NSString *s1, NSString *s2) {
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
@property SNTPolicyProcessor *processor;
@end

@implementation SNTPolicyProcessorTest
- (void)setUp {
  self.processor = [[SNTPolicyProcessor alloc] init];
}

- (void)testRule:(SNTRule *)rule
     transitiveRules:(BOOL)transitiveRules
               final:(BOOL)final
             matches:(BOOL)matches
              silent:(BOOL)silent
    expectedDecision:(SNTEventState)decision {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
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
  SNTRule *rule = [[SNTRule alloc]
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
  SNTRule *rule = [[SNTRule alloc]
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
  SNTRule *rule = [[SNTRule alloc] initWithDictionary:@{
    @"rule_type" : @"BINARY",
    @"identifier" : @"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    @"policy" : @"ALLOWLIST",
    @"custom_msg" : @"Custom Message",
    @"custom_url" : @"https://example.com"
  }
                                                error:nil];

  XCTAssertNotNil(rule, "invalid test rule dictionary");

  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = rule.identifier;

  [self.processor decision:cd forRule:rule withTransitiveRules:YES andCELActivationCallback:nil];

  XCTAssertEqualObjects(cd.customMsg, @"Custom Message");
  XCTAssertEqualObjects(cd.customURL, @"https://example.com");
}

- (void)testCreateRuleIDs {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];

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
          });
    };

    if (useV2) {
      return makeActivation.operator()<true>();
    } else {
      return makeActivation.operator()<false>();
    }
  };

  SNTRule * (^createCELRule)(NSString *, BOOL) = ^SNTRule *(NSString *celExpr, BOOL v2) {
    return [[SNTRule alloc]
        initWithIdentifier:@"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                     state:v2 ? SNTRuleStateCELv2 : SNTRuleStateCEL
                      type:SNTRuleTypeBinary
                 customMsg:nil
                 customURL:nil
                 timestamp:0
                   comment:nil
                   celExpr:celExpr
                     error:NULL];
  };
  {
    SNTRule *r = createCELRule(@"target.signing_time > timestamp(1717987100)", true);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"target.signing_time < timestamp(1717987100)", false);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"'arg1' in args", false);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"has(envs.ENV_VARIABLE1)", false);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"'--inspect' in args ? ALLOWLIST : SILENT_BLOCKLIST", false);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"euid != 0", true);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"cwd != '/Users/foo'", false);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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
    SNTRule *r = createCELRule(@"euid == 0 ? REQUIRE_TOUCHID : ALLOWLIST", true);
    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
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

@end
