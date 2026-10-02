/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#include <EndpointSecurity/ESTypes.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.h"
#include "Source/common/processtree/process_tree_test_helpers.h"

#include "Source/common/AuditUtilities.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSandboxExecRequest.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EntitlementsFilter.h"
#include "Source/santad/PendingExecCoordinator.h"
#include "Source/santad/ProcessControl.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTPolicyProcessor.h"
#import "Source/santad/SNTSyncdQueue.h"
#include "Source/santad/SandboxExpectations.h"

using santa::Message;
using santa::PendingExecCoordinator;

using PostActionBlock = bool (^)(SNTAction, SNTCachedDecision*);
using VerifyPostActionBlock = PostActionBlock (^)(SNTAction);

static const char* kExampleSigningID = "example.signing.id";
static const char* kExampleTeamID = "myteamid";

VerifyPostActionBlock verifyPostAction = ^PostActionBlock(SNTAction wantAction) {
  return ^bool(SNTAction gotAction, SNTCachedDecision* cd) {
    XCTAssertEqual(gotAction, wantAction);
    return true;
  };
};

static NSString* HexString(const uint8_t* bytes, size_t len) {
  NSMutableString* s = [NSMutableString stringWithCapacity:len * 2];
  for (size_t i = 0; i < len; i++) {
    [s appendFormat:@"%02x", bytes[i]];
  }
  return s;
}

static SNTSandboxExecRequest* MakeSandboxRequest(uint64_t dev, uint64_t ino, const uint8_t* cdhash,
                                                 NSString* sha256) {
  SNTRuleIdentifiers* ids = [[SNTRuleIdentifiers alloc]
      initWithRuleIdentifiers:{.cdhash = HexString(cdhash, 20), .binarySHA256 = sha256}];
  return [[SNTSandboxExecRequest alloc] initWithIdentifiers:ids
                                                      fsDev:dev
                                                      fsIno:ino
                                               resolvedPath:nil];
}

@interface SNTRule ()
// Making these properties readwrite makes some tests much easier to write.
@property(readwrite) SNTRuleState state;
@property(readwrite) SNTRuleType type;
@property(readwrite) NSString* customMsg;
@end

@interface SNTExecutionControllerTest : XCTestCase
@property id mockDecisionCache;
@property id mockConfigurator;
@property id mockCodesignChecker;
@property id mockFileInfo;
@property id mockRuleDatabase;
@property id mockEventDatabase;

@property SNTExecutionController* sut;
@end

@implementation SNTExecutionControllerTest {
  std::shared_ptr<santa::SandboxExpectations> _sandboxExpectations;
}

- (void)setUp {
  [super setUp];

  self.mockDecisionCache = OCMStrictClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache cacheDecision:OCMOCK_ANY]).andReturn(YES);

  [[SNTMetricSet sharedInstance] reset];

  self.mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.mockCodesignChecker alloc]).andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:NULL]])
      .andReturn(self.mockCodesignChecker);

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  NSURL* url = [NSURL URLWithString:@"https://localhost/test"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(url);

  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:nil]])
      .ignoringNonObjectArgs()
      .andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]])
      .andReturn(self.mockCodesignChecker);

  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  std::shared_ptr<santa::EntitlementsFilter> entitlementsFilter =
      santa::EntitlementsFilter::Create(@[], @[]);
  SNTPolicyProcessor* policyProcessor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:self.mockRuleDatabase
                                 entitlementsFilter:entitlementsFilter];

  _sandboxExpectations = std::make_shared<santa::SandboxExpectations>();
  self.sut =
      [[SNTExecutionController alloc] initWithRuleTable:self.mockRuleDatabase
                                             eventTable:self.mockEventDatabase
                                          notifierQueue:nil
                                             syncdQueue:nil
                                                 logger:nullptr
                                              ttyWriter:santa::TTYWriter::Create(true)
                                        policyProcessor:policyProcessor
                                    processControlBlock:santa::ProdSuspendResumeBlock()
                                            processTree:nullptr
                                    sandboxExpectations:_sandboxExpectations
                                 pendingExecCoordinator:std::make_shared<PendingExecCoordinator>()];
}

- (void)tearDown {
  // Make sure `self.sut` is deallocated before the mocks are deallocated and
  // call into `stopMocking`.
  self.sut = nil;
}

- (void)checkMetricCounters:(const NSString*)expectedFieldValueName
                   expected:(NSNumber*)expectedValue {
  SNTMetricSet* metricSet = [SNTMetricSet sharedInstance];
  NSDictionary* eventCounter = [metricSet export][@"metrics"][@"/santa/events"];
  BOOL foundField;
  for (NSDictionary* fieldValue in eventCounter[@"fields"][@"action_response"]) {
    if (![expectedFieldValueName isEqualToString:fieldValue[@"value"]]) continue;
    XCTAssertEqualObjects(expectedValue, fieldValue[@"data"],
                          @"%@ counter does not match expected value", expectedFieldValueName);
    foundField = YES;
    break;
  }

  if (!foundField && expectedValue.intValue != 0) {
    XCTFail(@"failed to find %@ field value", expectedFieldValueName);
  }
}

- (void)testSynchronousShouldProcessExecEvent {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {
                                             .st_dev = 12,
                                             .st_ino = 34,
                                         });
  es_process_t procExec = MakeESProcess(&fileExec);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Undo the default mocks
  self.mockDecisionCache = OCMStrictClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);

  // Throw on non-AUTH EXEC events
  {
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_EXEC;
    Message msg(mockESApi, &esMsg);
    XCTAssertThrows([self.sut synchronousShouldProcessExecEvent:msg]);
  }

  // "Normal" events should be processed
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXEC;
    Message msg(mockESApi, &esMsg);
    XCTAssertTrue([self.sut synchronousShouldProcessExecEvent:msg]);
  }

  // Long or truncated paths are not handled
  {
    size_t oldLen = esMsg.event.exec.target->executable->path.length;
    esMsg.event.exec.target->executable->path.length = 24000;
    es_file_t* targetExecutable = esMsg.event.exec.target->executable;

    Message msg(mockESApi, &esMsg);

    OCMExpect(
        [self.mockDecisionCache cacheDecision:[OCMArg checkWithBlock:^BOOL(SNTCachedDecision* cd) {
                                  return cd.decision == SNTEventStateBlockLongPath &&
                                         cd.vnodeId.fsid == targetExecutable->stat.st_dev &&
                                         cd.vnodeId.fileid == targetExecutable->stat.st_ino;
                                }]]);

    XCTAssertFalse([self.sut synchronousShouldProcessExecEvent:msg]);

    esMsg.event.exec.target->executable->path.length = oldLen;
    esMsg.event.exec.target->executable->path_truncated = true;

    OCMExpect(
        [self.mockDecisionCache cacheDecision:[OCMArg checkWithBlock:^BOOL(SNTCachedDecision* cd) {
                                  return cd.decision == SNTEventStateBlockLongPath &&
                                         cd.vnodeId.fsid == targetExecutable->stat.st_dev &&
                                         cd.vnodeId.fileid == targetExecutable->stat.st_ino;
                                }]]);

    XCTAssertFalse([self.sut synchronousShouldProcessExecEvent:msg]);

    XCTAssertTrue(OCMVerifyAll(self.mockDecisionCache));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)validateExecEvent:(SNTAction)wantAction
             messageSetup:(void (^)(es_message_t*))messageSetupBlock {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {
                                             .st_dev = 12,
                                             .st_ino = 34,
                                         });
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  if (messageSetupBlock) {
    messageSetupBlock(&esMsg);
  }

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    Message msg(mockESApi, &esMsg);
    [self.sut validateExecEvent:msg cachedDecision:nil postAction:verifyPostAction(wantAction)];
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)validateExecEvent:(SNTAction)wantAction {
  [self validateExecEvent:wantAction messageSetup:nil];
}

// Stubs the source-process decision lookup used by the seatbelt self-exec
// relaxation (-isSameBinaryAsInstigator:...). Pass nil to simulate no cached
// decision for the instigator (forcing the (dev, ino) fallback), or a SHA-256 to
// simulate a cached hash for the instigator's image.
- (void)stubInstigatorSHA256:(NSString*)sha256 {
  SNTCachedDecision* dec = nil;
  if (sha256.length) {
    dec = [[SNTCachedDecision alloc] init];
    dec.sha256 = sha256;
  }
  OCMStub([self.mockDecisionCache cachedDecisionForVnode:SantaVnode{}])
      .ignoringNonObjectArgs()
      .andReturn(dec);
}

// Builds an SNTExecutionController backed by the given process tree, sharing the
// same mocks and sandbox expectations as the default `self.sut`. Used by the
// fork-descendant tests, which need a populated process tree (the default
// `self.sut` is built with a nullptr tree).
- (SNTExecutionController*)makeControllerWithProcessTree:
    (std::shared_ptr<santa::santad::process_tree::ProcessTree>)tree {
  std::shared_ptr<santa::EntitlementsFilter> entitlementsFilter =
      santa::EntitlementsFilter::Create(@[], @[]);
  SNTPolicyProcessor* policyProcessor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:self.mockRuleDatabase
                                 entitlementsFilter:entitlementsFilter];
  return
      [[SNTExecutionController alloc] initWithRuleTable:self.mockRuleDatabase
                                             eventTable:self.mockEventDatabase
                                          notifierQueue:nil
                                             syncdQueue:nil
                                                 logger:nullptr
                                              ttyWriter:santa::TTYWriter::Create(true)
                                        policyProcessor:policyProcessor
                                    processControlBlock:santa::ProdSuspendResumeBlock()
                                            processTree:tree
                                    sandboxExpectations:_sandboxExpectations
                                 pendingExecCoordinator:std::make_shared<PendingExecCoordinator>()];
}

- (void)stubRule:(SNTRule*)rule forIdentifiers:(struct RuleIdentifiers)wantIdentifiers {
  OCMStub([self.mockRuleDatabase executionRuleForIdentifiers:wantIdentifiers])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        struct RuleIdentifiers gotIdentifiers = {};
        [inv getArgument:&gotIdentifiers atIndex:2];

        XCTAssertEqualObjects(gotIdentifiers.cdhash, wantIdentifiers.cdhash);
        XCTAssertEqualObjects(gotIdentifiers.binarySHA256, wantIdentifiers.binarySHA256);
        XCTAssertEqualObjects(gotIdentifiers.signingID, wantIdentifiers.signingID);
        XCTAssertEqualObjects(gotIdentifiers.certificateSHA256, wantIdentifiers.certificateSHA256);
        XCTAssertEqualObjects(gotIdentifiers.teamID, wantIdentifiers.teamID);
      })
      .andReturn(rule);
}

- (void)testCriticalSystemBinaryCheckSigningID {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.decision = SNTEventStateAllowBinary;
  SNTCachedDecision* cd2 = [[SNTCachedDecision alloc] init];
  cd2.decision = SNTEventStateAllowSigningID;

  NSString* signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];
  NSDictionary* critBins = @{@"abcdefg" : cd, signingID : cd2};

  OCMStub([self.mockRuleDatabase criticalSystemBinaries]).andReturn(critBins);

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
             }];
}

- (void)testBinaryAllowRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowBinary expected:@1];
}

- (void)testBinaryBlockRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondDeny];
  [self checkMetricCounters:kBlockBinary expected:@1];
}

- (void)testCDHashAllowRule {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeCDHash;

  [self stubRule:rule forIdentifiers:{.cdhash = @"aa00000000000000000000000000000000000000"}];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->cdhash[0] = 0xaa;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
             }];
  [self checkMetricCounters:kAllowCDHash expected:@1];
}

- (void)testCDHashNoHardenedRuntimeRule {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeCDHash;

  // No CDHash should be set when hardened runtime CS flags are not set
  [self stubRule:rule forIdentifiers:{.cdhash = nil}];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->cdhash[0] = 0xaa;
               // Ensure CS_HARD and CS_KILL are not set
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
             }];
  [self checkMetricCounters:kAllowCDHash expected:@1];
}

- (void)testCDHashBlockRule {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeCDHash;

  [self stubRule:rule forIdentifiers:{.cdhash = @"aa00000000000000000000000000000000000000"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->cdhash[0] = 0xaa;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
             }];
  [self checkMetricCounters:kBlockCDHash expected:@1];
}

- (void)testCDHashAllowCompilerRule {
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeCDHash;

  [self stubRule:rule forIdentifiers:{.cdhash = @"aa00000000000000000000000000000000000000"}];

  [self validateExecEvent:SNTActionRespondAllowCompiler
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->cdhash[0] = 0xaa;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
             }];

  [self checkMetricCounters:kAllowCompilerCDHash expected:@1];
}

- (void)testCDHashAllowCompilerRuleTransitiveRuleDisabled {
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeCDHash;

  [self stubRule:rule forIdentifiers:{.cdhash = @"aa00000000000000000000000000000000000000"}];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->cdhash[0] = 0xaa;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
             }];

  [self checkMetricCounters:kAllowCDHash expected:@1];
}

- (void)testSigningIDAllowRule {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeSigningID;

  NSString* signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];

  [self stubRule:rule forIdentifiers:{.signingID = signingID, .teamID = @(kExampleTeamID)}];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];

  [self checkMetricCounters:kAllowSigningID expected:@1];
}

- (void)testSigningIDBlockRule {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeSigningID;

  NSString* signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];
  [self stubRule:rule forIdentifiers:{.signingID = signingID, .teamID = @(kExampleTeamID)}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];
  [self checkMetricCounters:kBlockSigningID expected:@1];
}

- (void)testTeamIDAllowRule {
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeTeamID;

  [self stubRule:rule forIdentifiers:{.teamID = @(kExampleTeamID)}];

  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];
  [self checkMetricCounters:kAllowTeamID expected:@1];
}

- (void)testTeamIDBlockRule {
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeTeamID;

  [self stubRule:rule forIdentifiers:{.teamID = @(kExampleTeamID)}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
             }];
  [self checkMetricCounters:kBlockTeamID expected:@1];
}

- (void)testCertificateAllowRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeCertificate;

  [self stubRule:rule forIdentifiers:{.certificateSHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowCertificate expected:@1];
}

- (void)testCertificateBlockRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);

  id cert = OCMClassMock([MOLCertificate class]);
  OCMStub([self.mockCodesignChecker leafCertificate]).andReturn(cert);
  OCMStub([cert SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateBlock;
  rule.type = SNTRuleTypeCertificate;

  [self stubRule:rule forIdentifiers:{.certificateSHA256 = @"a"}];

  OCMExpect([(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockCertificate expected:@1];
}

- (void)testBinaryAllowCompilerRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowCompiler];
  [self checkMetricCounters:kAllowCompilerBinary expected:@1];
}

- (void)testBinaryAllowCompilerRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowBinary expected:@1];
}

- (void)testBinaryAllowTransitiveRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowTransitive expected:@1];
}

- (void)testBinaryAllowTransitiveRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  OCMExpect([(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kAllowBinary expected:@0];
  [self checkMetricCounters:kAllowTransitive expected:@0];
}

- (void)testSigningIDAllowCompilerRule {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  NSString* signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeSigningID;

  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"a", .signingID = signingID, .teamID = @(kExampleTeamID)}];

  [self validateExecEvent:SNTActionRespondAllowCompiler
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
             }];

  [self checkMetricCounters:kAllowCompilerSigningID expected:@1];
}

- (void)testSigningIDAllowTransitiveRuleDisabled {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowTransitive;
  rule.type = SNTRuleTypeSigningID;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  OCMExpect([(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kAllowSigningID expected:@0];
  [self checkMetricCounters:kAllowTransitive expected:@0];
}

- (void)testThatPlatformBinaryCachedDecisionsSetModeCorrectly {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(NO);

  NSString* signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.decision = SNTEventStateAllowSigningID;
  OCMStub([self.mockRuleDatabase criticalSystemBinaries]).andReturn(@{signingID : cd});

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
  procExec.team_id = MakeESStringToken(kExampleTeamID);
  procExec.signing_id = MakeESStringToken(kExampleSigningID);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  __block SNTCachedDecision* returnedCd = nil;
  {
    Message msg(mockESApi, &esMsg);
    [self.sut validateExecEvent:msg
                 cachedDecision:nil
                     postAction:^bool(SNTAction action, SNTCachedDecision* resultCd) {
                       XCTAssertEqual(action, SNTActionRespondAllow);
                       returnedCd = resultCd;
                       return true;
                     }];
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [self checkMetricCounters:kAllowSigningID expected:@1];
  [self checkMetricCounters:kAllowUnknown expected:@0];

  // The returned cd should be a copy with the correct mode, not the shared dictionary entry.
  XCTAssertEqual(returnedCd.decisionClientMode, SNTClientModeLockdown);
  XCTAssertEqual(cd.decisionClientMode, SNTClientModeUnknown);
}

- (void)testDefaultDecision {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMExpect([(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondAllow];

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  [self validateExecEvent:SNTActionRespondDeny];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockUnknown expected:@1];
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

- (void)testUnreadableFailOpen {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowNoFileInfo expected:@1];
}

- (void)testUnreadableFailClosed {
  // Undo the default mocks
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);

  OCMStub([self.mockFileInfo alloc]).andReturn(nil);
  OCMStub([self.mockFileInfo initWithPath:OCMOCK_ANY error:[OCMArg setTo:nil]]).andReturn(nil);

  OCMStub([self.mockConfigurator failClosed]).andReturn(YES);

  [self validateExecEvent:SNTActionRespondDeny];
  [self checkMetricCounters:kDenyNoFileInfo expected:@1];
}

- (void)testMissingShasum {
  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowScope expected:@1];
}

- (void)testOutOfScope {
  OCMStub([self.mockFileInfo isMachO]).andReturn(NO);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowScope expected:@1];
}

- (void)testPageZero {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo isMissingPageZero]).andReturn(YES);
  OCMExpect([(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockUnknown expected:@1];
}

- (void)testAllEventUpload {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator enableAllEventUpload]).andReturn(YES);
  OCMExpect([(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;

  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllow];
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
}

- (void)testDisableUnknownEventUpload {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMExpect([self.mockConfigurator enableAllEventUpload]).andReturn(NO);
  OCMExpect([self.mockConfigurator disableUnknownEventUpload]).andReturn(YES);

  [self validateExecEvent:SNTActionRespondAllow];
  OCMVerify(never(), [(SNTEventTable*)self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

- (void)validateHoldAndAskWithApproval:(BOOL)approved
                       initialDecision:(SNTEventState)initialState
                      expectedDecision:(SNTEventState)expectedState
                         expectedExtra:(NSString*)expectedExtra
                        expectedAction:(SNTAction)expectedAction
                       expectedControl:(santa::ProcessControl)expectedControl {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  // Create mock notifier queue that captures the reply block
  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  __block NotificationReplyBlock capturedReplyBlock = nil;
  OCMStub([mockNotifierQueue addEvent:OCMOCK_ANY
                    withCustomMessage:OCMOCK_ANY
                            customURL:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained NotificationReplyBlock block;
        [invocation getArgument:&block atIndex:6];
        capturedReplyBlock = [block copy];
      });

  __block BOOL loggerCalled = NO;
  LogExecutionBlock loggerBlock = ^(Message esMsg) {
    loggerCalled = YES;
  };

  // Set initial to opposite of expected to verify it changes
  __block santa::ProcessControl capturedControl =
      approved ? santa::ProcessControl::Kill : santa::ProcessControl::Resume;
  santa::ProcessControlBlock processControl = ^bool(pid_t pid, santa::ProcessControl control) {
    capturedControl = control;
    return true;
  };

  // Create mock policy processor with holdAndAsk decision
  id mockPolicyProcessor = OCMClassMock([SNTPolicyProcessor class]);
  SNTCachedDecision* holdAndAskDecision = [[SNTCachedDecision alloc] init];
  holdAndAskDecision.decision = initialState;
  holdAndAskDecision.holdAndAsk = YES;
  holdAndAskDecision.decisionClientMode = SNTClientModeLockdown;

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  OCMStub([mockPolicyProcessor decisionForFileInfo:OCMOCK_ANY
                                     targetProcess:&procExec
                                       configState:OCMOCK_ANY
                                activationCallback:OCMOCK_ANY
                                    cachedDecision:OCMOCK_ANY])
      .ignoringNonObjectArgs()
      .andReturn(holdAndAskDecision);

  std::shared_ptr<santa::santad::process_tree::ProcessTree> processTree;

  SNTExecutionController* controller = [[SNTExecutionController alloc]
           initWithRuleTable:self.mockRuleDatabase
                  eventTable:self.mockEventDatabase
               notifierQueue:mockNotifierQueue
                  syncdQueue:nil
                      logger:loggerBlock
                   ttyWriter:santa::TTYWriter::Create(true)
             policyProcessor:mockPolicyProcessor
         processControlBlock:processControl
                 processTree:processTree
         sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
      pendingExecCoordinator:std::make_shared<PendingExecCoordinator>()];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  __block SNTAction resultAction = SNTActionUnset;
  {
    Message msg(mockESApi, &esMsg);
    [controller validateExecEvent:msg
                   cachedDecision:nil
                       postAction:^bool(SNTAction action, SNTCachedDecision* cd) {
                         resultAction = action;
                         return true;
                       }];
  }

  XCTAssertNotNil(capturedReplyBlock, @"Reply block should have been captured from notifier queue");
  capturedReplyBlock(approved);

  XCTAssertEqual(holdAndAskDecision.decision, expectedState);
  XCTAssertEqualObjects(holdAndAskDecision.decisionExtra, expectedExtra);
  XCTAssertFalse(holdAndAskDecision.holdAndAsk);
  XCTAssertTrue(loggerCalled);
  XCTAssertEqual(capturedControl, expectedControl);
  XCTAssertEqual(resultAction, expectedAction);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockNotifierQueue stopMocking];
  [mockPolicyProcessor stopMocking];
}

- (void)testHoldAndAskTouchIDApproved {
  [self validateHoldAndAskWithApproval:YES
                       initialDecision:SNTEventStateBlockSigningID
                      expectedDecision:SNTEventStateAllowSigningID
                         expectedExtra:@"TouchID Approved"
                        expectedAction:SNTActionHoldAllowed
                       expectedControl:santa::ProcessControl::Resume];
}

- (void)testHoldAndAskTouchIDDenied {
  [self validateHoldAndAskWithApproval:NO
                       initialDecision:SNTEventStateBlockUnknown
                      expectedDecision:SNTEventStateBlockUnknown
                         expectedExtra:@"TouchID Denied"
                        expectedAction:SNTActionHoldDenied
                       expectedControl:santa::ProcessControl::Kill];
}

// Test that successful TouchID auth populates the cache, and subsequent executions
// of the same binary skip the TouchID prompt (cache hit scenario)
- (void)testTouchIDCacheHitSkipsPrompt {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cachedsha256");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  // Create mock notifier queue that captures the reply block
  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  __block NotificationReplyBlock capturedReplyBlock = nil;
  OCMStub([mockNotifierQueue addEvent:OCMOCK_ANY
                    withCustomMessage:OCMOCK_ANY
                            customURL:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained NotificationReplyBlock block;
        [invocation getArgument:&block atIndex:6];
        capturedReplyBlock = [block copy];
      });

  LogExecutionBlock loggerBlock = ^(Message esMsg) {
  };

  santa::ProcessControlBlock processControl = ^bool(pid_t pid, santa::ProcessControl control) {
    return true;
  };

  // Create mock policy processor that returns a new decision each time
  id mockPolicyProcessor = OCMClassMock([SNTPolicyProcessor class]);
  __block SNTCachedDecision* currentDecision = nil;

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  OCMStub([mockPolicyProcessor decisionForFileInfo:OCMOCK_ANY
                                     targetProcess:&procExec
                                       configState:OCMOCK_ANY
                                activationCallback:OCMOCK_ANY
                                    cachedDecision:OCMOCK_ANY])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        [invocation setReturnValue:&currentDecision];
      });

  std::shared_ptr<santa::santad::process_tree::ProcessTree> processTree;

  SNTExecutionController* controller = [[SNTExecutionController alloc]
           initWithRuleTable:self.mockRuleDatabase
                  eventTable:self.mockEventDatabase
               notifierQueue:mockNotifierQueue
                  syncdQueue:nil
                      logger:loggerBlock
                   ttyWriter:santa::TTYWriter::Create(true)
             policyProcessor:mockPolicyProcessor
         processControlBlock:processControl
                 processTree:processTree
         sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
      pendingExecCoordinator:std::make_shared<PendingExecCoordinator>()];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Track all actions received to verify the flow
  __block NSMutableArray<NSNumber*>* receivedActions = [NSMutableArray array];

  // First execution: should prompt for TouchID (cache is empty)
  currentDecision = [[SNTCachedDecision alloc] init];
  currentDecision.decision = SNTEventStateBlockUnknown;
  currentDecision.holdAndAsk = YES;
  currentDecision.decisionClientMode = SNTClientModeLockdown;
  currentDecision.sha256 = @"cachedsha256";
  currentDecision.touchIDCooldownMinutes = @(5);  // 5 minute cooldown for caching

  {
    Message msg(mockESApi, &esMsg);
    [controller validateExecEvent:msg
                   cachedDecision:nil
                       postAction:^bool(SNTAction action, SNTCachedDecision* cd) {
                         [receivedActions addObject:@(action)];
                         return true;
                       }];
  }

  // First action should be SNTActionRespondHold (process held for TouchID)
  XCTAssertGreaterThanOrEqual(receivedActions.count, 1UL);
  XCTAssertEqual([receivedActions[0] integerValue], SNTActionRespondHold,
                 @"First execution should hold for TouchID");

  XCTAssertNotNil(capturedReplyBlock, @"Reply block should have been captured");
  // Simulate successful TouchID auth
  capturedReplyBlock(YES);

  XCTAssertEqual(currentDecision.decision, SNTEventStateAllowUnknown);
  XCTAssertEqualObjects(currentDecision.decisionExtra, @"TouchID Approved");

  // Now test that a second execution with the same SHA256 uses the cache
  // and skips the TouchID prompt
  capturedReplyBlock = nil;
  [receivedActions removeAllObjects];

  // Create a new holdAndAsk decision for the second execution (same SHA256)
  SNTCachedDecision* secondDecision = [[SNTCachedDecision alloc] init];
  secondDecision.decision = SNTEventStateBlockUnknown;
  secondDecision.holdAndAsk = YES;
  secondDecision.decisionClientMode = SNTClientModeLockdown;
  secondDecision.sha256 = @"cachedsha256";       // Same SHA256 - should hit cache
  secondDecision.touchIDCooldownMinutes = @(5);  // Same cooldown
  currentDecision = secondDecision;

  // Second execution with same controller (cache persists)
  mockESApi->SetExpectationsRetainReleaseMessage();
  {
    Message msg(mockESApi, &esMsg);
    [controller validateExecEvent:msg
                   cachedDecision:nil
                       postAction:^bool(SNTAction action, SNTCachedDecision* cd) {
                         [receivedActions addObject:@(action)];
                         return true;
                       }];
  }

  // Second execution should NOT hold - cache hit should allow immediately
  XCTAssertGreaterThanOrEqual(receivedActions.count, 1UL);
  // Should be SNTActionRespondAllow or SNTActionRespondAllowNoCache (not SNTActionRespondHold)
  SNTAction secondAction = (SNTAction)[receivedActions[0] integerValue];
  XCTAssertTrue(
      secondAction == SNTActionRespondAllow || secondAction == SNTActionRespondAllowNoCache,
      @"Second execution should skip TouchID and allow (got %ld)", (long)secondAction);

  // Verify the decision was updated to show it was cached
  XCTAssertFalse(secondDecision.holdAndAsk, @"holdAndAsk should be cleared by cache hit");
  XCTAssertEqualObjects(secondDecision.decisionExtra, @"TouchID Cached");

  // The notification queue should NOT have been called for the second execution
  XCTAssertNil(capturedReplyBlock, @"No reply block should be captured for cached execution");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockNotifierQueue stopMocking];
  [mockPolicyProcessor stopMocking];
}

// ---------------- Transitive-rule exec hold ----------------
//
// When a brand-new binary is blocked as unknown in lockdown while a compiler is
// active, the execution is held until the compiler's transitive rule lands
// (resume) or a timeout elapses (kill). Mirrors the holdAndAsk machinery above.

// Drives a single unknown/blocked-in-lockdown AUTH_EXEC through the controller
// with a real PendingExecCoordinator and recording ProcessControl/postAction
// blocks. The mock policy processor returns a BlockUnknown decision (the gate's
// only candidate); the target file's birthtime is set to now so the recency
// gate passes. `recordedControl` receives each ProcessControl value (as an int),
// `recordedActions` receives each postAction SNTAction (as an int), and
// `terminalSema` is signaled once a terminal hold action (HoldAllowed/HoldDenied)
// is posted. Returns the decision object so callers can assert its final state.
- (SNTCachedDecision*)runTransitiveHoldWithCoordinator:
                          (std::shared_ptr<santa::PendingExecCoordinator>)coord
                                                waitMs:(uint32_t)waitMs
                                       recordedControl:(NSMutableArray<NSNumber*>*)recordedControl
                                       recordedActions:(NSMutableArray<NSNumber*>*)recordedActions
                                          terminalSema:(dispatch_semaphore_t)terminalSema {
  // Default process control block: every operation succeeds.
  santa::ProcessControlBlock pcb = ^bool(pid_t pid, santa::ProcessControl c) {
    @synchronized(recordedControl) {
      [recordedControl addObject:@((int)c)];
    }
    return true;
  };
  return [self runTransitiveHoldWithCoordinator:coord
                                         waitMs:waitMs
                            processControlBlock:pcb
                                  notifierQueue:nil
                                     syncdQueue:nil
                                recordedControl:recordedControl
                                recordedActions:recordedActions
                                   terminalSema:terminalSema];
}

// As above, but with an injectable process control block (so a failed Suspend
// can be simulated) and optional notifier/syncd queues (so the block
// notification path can be observed).
- (SNTCachedDecision*)runTransitiveHoldWithCoordinator:
                          (std::shared_ptr<santa::PendingExecCoordinator>)coord
                                                waitMs:(uint32_t)waitMs
                                   processControlBlock:(santa::ProcessControlBlock)pcb
                                         notifierQueue:(SNTNotificationQueue*)notifierQueue
                                            syncdQueue:(SNTSyncdQueue*)syncdQueue
                                       recordedControl:(NSMutableArray<NSNumber*>*)recordedControl
                                       recordedActions:(NSMutableArray<NSNumber*>*)recordedActions
                                          terminalSema:(dispatch_semaphore_t)terminalSema {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);
  OCMStub([self.mockConfigurator compilerTransitiveWaitMilliseconds]).andReturn(waitMs);

  LogExecutionBlock loggerBlock = ^(Message esMsg) {
  };

  // The gate's only accepted decision is an unknown block in lockdown.
  id mockPolicyProcessor = OCMClassMock([SNTPolicyProcessor class]);
  SNTCachedDecision* decision = [[SNTCachedDecision alloc] init];
  decision.decision = SNTEventStateBlockUnknown;
  decision.decisionClientMode = SNTClientModeLockdown;

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  // Freshly written: birthtime within the recency window so the gate passes.
  fileExec.stat.st_birthtimespec = {.tv_sec = time(NULL), .tv_nsec = 0};
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  OCMStub([mockPolicyProcessor decisionForFileInfo:OCMOCK_ANY
                                     targetProcess:&procExec
                                       configState:OCMOCK_ANY
                                activationCallback:OCMOCK_ANY
                                    cachedDecision:OCMOCK_ANY])
      .ignoringNonObjectArgs()
      .andReturn(decision);

  SNTExecutionController* controller = [[SNTExecutionController alloc]
           initWithRuleTable:self.mockRuleDatabase
                  eventTable:self.mockEventDatabase
               notifierQueue:notifierQueue
                  syncdQueue:syncdQueue
                      logger:loggerBlock
                   ttyWriter:santa::TTYWriter::Create(true)
             policyProcessor:mockPolicyProcessor
         processControlBlock:pcb
                 processTree:nullptr
         sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
      pendingExecCoordinator:coord];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    Message msg(mockESApi, &esMsg);
    [controller validateExecEvent:msg
                   cachedDecision:nil
                       postAction:^bool(SNTAction action, SNTCachedDecision* cd) {
                         @synchronized(recordedActions) {
                           [recordedActions addObject:@(action)];
                         }
                         if (action == SNTActionHoldAllowed || action == SNTActionHoldDenied ||
                             action == SNTActionRespondDeny) {
                           dispatch_semaphore_signal(terminalSema);
                         }
                         return true;
                       }];
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockPolicyProcessor stopMocking];
  return decision;
}

// A held exec resumes and is allowed (AllowTransitive) once the coordinator is
// notified that the transitive rule was created.
- (void)testHoldsAndAllowsWhenTransitiveRuleArrives {
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);
  coord->RecordCompilerActivity();  // a compiler is active

  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Generous wait so the rule arrives well before any timeout.
  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:5000
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  // The synchronous response is to hold, and the target was suspended.
  XCTAssertGreaterThanOrEqual(recordedActions.count, 1UL);
  XCTAssertEqual([recordedActions[0] integerValue], SNTActionRespondHold);
  @synchronized(recordedControl) {
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Suspend)],
                  @"target should have been suspended");
  }

  // The transitive rule lands -> resume + allow.
  coord->NotifyRuleCreated(SantaVnode{.fsid = 12, .fileid = 34});

  XCTAssertEqual(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 0L, @"hold should have resolved");

  @synchronized(recordedControl) {
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Resume)],
                  @"target should have been resumed");
    XCTAssertFalse([recordedControl containsObject:@((int)santa::ProcessControl::Kill)],
                   @"target should not have been killed");
  }
  XCTAssertEqual([[recordedActions lastObject] integerValue], SNTActionHoldAllowed);
  XCTAssertEqual(cd.decision, SNTEventStateAllowTransitive);
  XCTAssertEqualObjects(cd.decisionExtra, @"Transitive rule created during exec hold");
}

// A held exec resumes and is allowed when the transitive rule was already created
// for this vnode just before the exec: the coordinator resolves the wait
// immediately (still async on its queue), the fast path the synchronous `cd`
// owner must not race.
- (void)testHoldsAndAllowsWhenRuleAlreadyCreated {
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);
  coord->RecordCompilerActivity();  // a compiler is active

  // The rule was committed for this vnode just before the exec, so Wait() takes
  // the recently-created fast path and resolves immediately.
  coord->NotifyRuleCreated(SantaVnode{.fsid = 12, .fileid = 34});

  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:5000
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  XCTAssertEqual(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 0L, @"immediate-resolve hold should have resolved");

  // Even on the immediate-resolve path, the synchronous response is still a hold
  // (and a suspend) before the async resume + allow.
  XCTAssertGreaterThanOrEqual(recordedActions.count, 1UL);
  XCTAssertEqual([recordedActions[0] integerValue], SNTActionRespondHold);
  @synchronized(recordedControl) {
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Suspend)],
                  @"target should have been suspended");
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Resume)],
                  @"target should have been resumed");
    XCTAssertFalse([recordedControl containsObject:@((int)santa::ProcessControl::Kill)],
                   @"target should not have been killed");
  }
  XCTAssertEqual([[recordedActions lastObject] integerValue], SNTActionHoldAllowed);
  XCTAssertEqual(cd.decision, SNTEventStateAllowTransitive);
  XCTAssertEqualObjects(cd.decisionExtra, @"Transitive rule created during exec hold");
}

// A held exec is killed and denied when no transitive rule arrives before the
// timeout elapses.
- (void)testHoldsAndKillsOnTimeout {
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);
  coord->RecordCompilerActivity();  // a compiler is active

  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Short timeout; do NOT notify the coordinator.
  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:50
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  XCTAssertGreaterThanOrEqual(recordedActions.count, 1UL);
  XCTAssertEqual([recordedActions[0] integerValue], SNTActionRespondHold);

  XCTAssertEqual(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 0L, @"hold should have timed out");

  @synchronized(recordedControl) {
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Suspend)],
                  @"target should have been suspended");
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Kill)],
                  @"target should have been killed on timeout");
    XCTAssertFalse([recordedControl containsObject:@((int)santa::ProcessControl::Resume)],
                   @"target should not have been resumed");
  }
  XCTAssertEqual([[recordedActions lastObject] integerValue], SNTActionHoldDenied);
  XCTAssertEqualObjects(cd.decisionExtra, @"No transitive rule created before timeout");
}

// A timed-out (killed) hold notifies the user like any other lockdown block: the
// GUI dialog is shown and the blocked event is uploaded to the sync server, in
// addition to the Kill + SNTActionHoldDenied resolution.
- (void)testTimeoutKillNotifiesLikeLockdownBlock {
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);
  coord->RecordCompilerActivity();  // a compiler is active

  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  santa::ProcessControlBlock pcb = ^bool(pid_t pid, santa::ProcessControl c) {
    @synchronized(recordedControl) {
      [recordedControl addObject:@((int)c)];
    }
    return true;
  };

  // GUI dialog and blocked-event sync upload are both expected on timeout. The
  // transitive hold has no interactive reply, so the reply block is nil.
  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  OCMExpect([mockNotifierQueue addEvent:OCMOCK_ANY
                      withCustomMessage:OCMOCK_ANY
                              customURL:OCMOCK_ANY
                            configState:OCMOCK_ANY
                               andReply:[OCMArg isNil]]);
  id mockSyncdQueue = OCMClassMock([SNTSyncdQueue class]);
  OCMExpect([(SNTSyncdQueue*)mockSyncdQueue addStoredEvent:OCMOCK_ANY]);

  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Short timeout; do NOT notify the coordinator.
  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:50
                                             processControlBlock:pcb
                                                   notifierQueue:mockNotifierQueue
                                                      syncdQueue:mockSyncdQueue
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  XCTAssertEqual(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 0L, @"hold should have timed out");

  @synchronized(recordedControl) {
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Kill)],
                  @"target should have been killed on timeout");
  }
  XCTAssertEqual([[recordedActions lastObject] integerValue], SNTActionHoldDenied);
  XCTAssertEqualObjects(cd.decisionExtra, @"No transitive rule created before timeout");

  // The blocked-event GUI notification and sync upload both fired.
  OCMVerifyAllWithDelay(mockNotifierQueue, 5);
  OCMVerifyAllWithDelay(mockSyncdQueue, 5);
  [mockNotifierQueue stopMocking];
  [mockSyncdQueue stopMocking];
}

// The resume/allow arm (the transitive rule arrived before the timeout) is a
// silent allow: no GUI dialog and no blocked-event upload.
- (void)testRuleArrivedAllowDoesNotNotify {
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);
  coord->RecordCompilerActivity();  // a compiler is active

  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  santa::ProcessControlBlock pcb = ^bool(pid_t pid, santa::ProcessControl c) {
    @synchronized(recordedControl) {
      [recordedControl addObject:@((int)c)];
    }
    return true;
  };

  // Capture rather than reject so an erroneous emission cannot raise on the
  // background resolve queue; the negative assertions run after the hold
  // resolves (the GUI notification, if any, fires synchronously before the
  // terminal action, and the allow arm never dispatches a sync upload).
  __block BOOL guiNotified = NO;
  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  OCMStub([mockNotifierQueue addEvent:OCMOCK_ANY
                    withCustomMessage:OCMOCK_ANY
                            customURL:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        guiNotified = YES;
      });
  __block BOOL syncUploaded = NO;
  id mockSyncdQueue = OCMClassMock([SNTSyncdQueue class]);
  OCMStub([(SNTSyncdQueue*)mockSyncdQueue addStoredEvent:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        syncUploaded = YES;
      });

  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // The rule was committed for this vnode just before the exec, so the wait
  // resolves immediately with an allow.
  coord->NotifyRuleCreated(SantaVnode{.fsid = 12, .fileid = 34});

  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:5000
                                             processControlBlock:pcb
                                                   notifierQueue:mockNotifierQueue
                                                      syncdQueue:mockSyncdQueue
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  XCTAssertEqual(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 0L, @"hold should have resolved");
  XCTAssertEqual([[recordedActions lastObject] integerValue], SNTActionHoldAllowed);
  XCTAssertEqual(cd.decision, SNTEventStateAllowTransitive);

  XCTAssertFalse(guiNotified, @"the allow path must not show a block dialog");
  XCTAssertFalse(syncUploaded, @"the allow path must not upload a blocked event");
  [mockNotifierQueue stopMocking];
  [mockSyncdQueue stopMocking];
}

// With no recent compiler activity the gate does not fire: the unknown binary is
// denied normally (no hold, no suspend).
- (void)testNoHoldWhenCompilerNotActive {
  // Coordinator with NO recorded compiler activity.
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);

  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:5000
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  // Denied normally: a single Deny response, no hold, and the process was never
  // touched by ProcessControl.
  XCTAssertEqual(recordedActions.count, 1UL);
  XCTAssertEqual([recordedActions[0] integerValue], SNTActionRespondDeny);
  XCTAssertFalse([recordedActions containsObject:@(SNTActionRespondHold)]);
  @synchronized(recordedControl) {
    XCTAssertEqual(recordedControl.count, 0UL, @"ProcessControl should not have been invoked");
  }
  XCTAssertEqual(cd.decision, SNTEventStateBlockUnknown);
}

// When suspending the target fails (ProcessControl has already killed it), the
// hold is abandoned and the exec is denied normally: the synchronous response is
// a plain Deny (never Hold or a terminal Hold* action), the wait is never armed
// (the coordinator is never notified, yet the response is terminal), and the
// normal block notification still fires.
- (void)testFailedSuspendDeniesAndNotifies {
  auto coord = std::make_shared<santa::PendingExecCoordinator>(10000);
  coord->RecordCompilerActivity();  // a compiler is active

  // Process control block that reports a failed Suspend (true otherwise), as
  // ProdSuspendResumeBlock does after killing a target it could not suspend.
  NSMutableArray<NSNumber*>* recordedControl = [NSMutableArray array];
  santa::ProcessControlBlock pcb = ^bool(pid_t pid, santa::ProcessControl c) {
    @synchronized(recordedControl) {
      [recordedControl addObject:@((int)c)];
    }
    return c != santa::ProcessControl::Suspend;
  };

  // Mock notifier queue so the block notification can be observed.
  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  OCMExpect([mockNotifierQueue addEvent:OCMOCK_ANY
                      withCustomMessage:OCMOCK_ANY
                              customURL:OCMOCK_ANY
                            configState:OCMOCK_ANY
                               andReply:OCMOCK_ANY]);

  NSMutableArray<NSNumber*>* recordedActions = [NSMutableArray array];
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Generous wait: were a hold (wrongly) armed, it would not time out within the
  // test window, so a terminal action could only come from the deny path.
  SNTCachedDecision* cd = [self runTransitiveHoldWithCoordinator:coord
                                                          waitMs:60000
                                             processControlBlock:pcb
                                                   notifierQueue:mockNotifierQueue
                                                      syncdQueue:nil
                                                 recordedControl:recordedControl
                                                 recordedActions:recordedActions
                                                    terminalSema:sema];

  // The exec is denied normally: a single Deny response, no hold ever posted.
  XCTAssertEqual(recordedActions.count, 1UL);
  XCTAssertEqual([recordedActions[0] integerValue], SNTActionRespondDeny);
  XCTAssertFalse([recordedActions containsObject:@(SNTActionRespondHold)]);
  XCTAssertFalse([recordedActions containsObject:@(SNTActionHoldAllowed)]);
  XCTAssertFalse([recordedActions containsObject:@(SNTActionHoldDenied)]);

  // Suspend was attempted; because it failed the wait was never armed, so the
  // target is neither resumed nor (re-)killed by the resolve path.
  @synchronized(recordedControl) {
    XCTAssertTrue([recordedControl containsObject:@((int)santa::ProcessControl::Suspend)],
                  @"a suspend should have been attempted");
    XCTAssertFalse([recordedControl containsObject:@((int)santa::ProcessControl::Resume)],
                   @"target should not have been resumed");
    XCTAssertFalse([recordedControl containsObject:@((int)santa::ProcessControl::Kill)],
                   @"resolve path should not run, so no kill from it");
  }

  XCTAssertEqual(cd.decision, SNTEventStateBlockUnknown);
  XCTAssertFalse(cd.pendingTransitive, @"the hold must be abandoned on a failed suspend");

  // The normal block notification fired (GUI dialog).
  OCMVerifyAllWithDelay(mockNotifierQueue, 5);
  [mockNotifierQueue stopMocking];
}

// Test that flushTouchIDApprovalCache clears the cache
- (void)testFlushTouchIDApprovalCache {
  SNTExecutionController* controller = [[SNTExecutionController alloc]
           initWithRuleTable:self.mockRuleDatabase
                  eventTable:self.mockEventDatabase
               notifierQueue:nil
                  syncdQueue:nil
                      logger:nullptr
                   ttyWriter:santa::TTYWriter::Create(true)
             policyProcessor:nil
         processControlBlock:santa::ProdSuspendResumeBlock()
                 processTree:nullptr
         sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
      pendingExecCoordinator:std::make_shared<PendingExecCoordinator>()];

  // Just verify that flush doesn't crash - the cache internals are private
  XCTAssertNoThrow([controller flushTouchIDApprovalCache]);
}

- (void)testSeatbeltRuleNoExpectationDenies {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondDeny];
}

// ---------------- Strict mode ----------------

- (void)testSeatbeltRuleStrictHardAllowsOnCDHashMatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  // CS_VALID | CS_HARD causes policy processor to populate cdhash identifier.
  [self stubRule:rule
      forIdentifiers:{.cdhash = @"7777777777777777777777777777777777777777", .binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(201, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD;
               uint8_t cdhash[20];
               memset(cdhash, 0x77, sizeof(cdhash));
               memcpy(msg->event.exec.target->cdhash, cdhash, 20);

               _sandboxExpectations->Register(
                   msg->process->audit_token,
                   MakeSandboxRequest(/*dev=*/0, /*ino=*/0, cdhash, /*sha256=*/nil));
             }];
}

- (void)testSeatbeltRuleStrictKillAllowsOnCDHashMatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  // CS_VALID | CS_KILL causes policy processor to populate cdhash identifier.
  [self stubRule:rule
      forIdentifiers:{.cdhash = @"5555555555555555555555555555555555555555", .binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(202, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL;
               uint8_t cdhash[20];
               memset(cdhash, 0x55, sizeof(cdhash));
               memcpy(msg->event.exec.target->cdhash, cdhash, 20);

               _sandboxExpectations->Register(
                   msg->process->audit_token,
                   MakeSandboxRequest(/*dev=*/0, /*ino=*/0, cdhash, /*sha256=*/nil));
             }];
}

- (void)testSeatbeltRuleStrictDeniesOnCDHashMismatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  // CS_VALID | CS_HARD: binary has cdhash 0xAA... so policy processor looks up by that cdhash.
  [self stubRule:rule
      forIdentifiers:{.cdhash = @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", .binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(203, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD;

               uint8_t cdhashA[20];
               memset(cdhashA, 0xAA, sizeof(cdhashA));
               memcpy(msg->event.exec.target->cdhash, cdhashA, 20);

               uint8_t cdhashB[20];
               memset(cdhashB, 0xBB, sizeof(cdhashB));

               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(0, 0, cdhashB, nil));
             }];
}

// ---------------- Fallback mode ----------------

- (void)testSeatbeltRuleFallbackAllowsOnFullMatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(301, 1);
               msg->event.exec.target->codesigning_flags = 0;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];
}

- (void)testSeatbeltRuleFallbackDeniesOnDevMismatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(302, 1);
               msg->event.exec.target->codesigning_flags = 0;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(
                   msg->process->audit_token,
                   MakeSandboxRequest(/*dev=*/999, /*ino=*/42, cdhash, @"cafebabe"));
             }];
}

- (void)testSeatbeltRuleFallbackDeniesOnInoMismatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(303, 1);
               msg->event.exec.target->codesigning_flags = 0;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(
                   msg->process->audit_token,
                   MakeSandboxRequest(17, /*ino=*/999, cdhash, @"cafebabe"));
             }];
}

- (void)testSeatbeltRuleFallbackDeniesOnSHA256Mismatch {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(304, 1);
               msg->event.exec.target->codesigning_flags = 0;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"deadbeef"));
             }];
}

- (void)testSeatbeltRuleFallbackDeniesWhenCdSHA256IsNil {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(nil);  // cd.sha256 ends up nil

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(305, 1);
               msg->event.exec.target->codesigning_flags = 0;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];
}

- (void)testSeatbeltRuleFallbackDeniesWhenExpectationSHA256IsEmpty {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(306, 1);
               msg->event.exec.target->codesigning_flags = 0;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, /*sha256=*/nil));
             }];
}

- (void)testSeatbeltRuleFallbackWhenStrictFlagsWithoutCSValid {
  // CS_HARD|CS_KILL but missing CS_VALID -> falls to fallback branch.
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(307, 1);
               msg->event.exec.target->codesigning_flags =
                   CS_SIGNED | CS_HARD | CS_KILL;  // no CS_VALID
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];
}

- (void)testSeatbeltRuleAuditTokenMismatchDenies {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(10, 1);

               // Expectation registered under a different token (different pid).
               audit_token_t other = santa::MakeStubAuditToken(20, 1);
               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(other, MakeSandboxRequest(0, 0, cdhash, nil));
             }];
}

// ---------------- Transitive sandbox relaxation (self-exec) ----------------

// A binary launched under seatbelt (expectation path) that re-execs itself is
// allowed without a new expectation: it is recorded as sandboxed, and the
// re-exec is a self-exec.
- (void)testSeatbeltSandboxedSelfExecAllows {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];
  // No cached decision for the instigator -> relaxation uses the (dev, ino) fallback.
  [self stubInstigatorSHA256:nil];

  // Call 1: santactl -> binary authorizes via expectation and records the
  // sandboxed target token (501, 1).
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(500, 1);
               msg->event.exec.target->audit_token = santa::MakeStubAuditToken(501, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];

  // Call 2: the recorded process (now the instigator (501, 1)) re-execs the
  // same binary (matching dev/ino) with no expectation -> relaxed.
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(501, 1);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 17;
               msg->process->executable->stat.st_ino = 42;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;
             }];
}

// Same as above but verifying the strict (cdhash) self-exec comparison.
- (void)testSeatbeltSandboxedSelfExecStrictAllows {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule
      forIdentifiers:{.cdhash = @"7777777777777777777777777777777777777777", .binarySHA256 = @"a"}];

  // Call 1: authorize via strict expectation, recording target token (511, 1).
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               uint8_t cdhash[20];
               memset(cdhash, 0x77, sizeof(cdhash));
               msg->process->audit_token = santa::MakeStubAuditToken(510, 1);
               msg->event.exec.target->audit_token = santa::MakeStubAuditToken(511, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD;
               memcpy(msg->event.exec.target->cdhash, cdhash, 20);

               _sandboxExpectations->Register(
                   msg->process->audit_token,
                   MakeSandboxRequest(/*dev=*/0, /*ino=*/0, cdhash, /*sha256=*/nil));
             }];

  // Call 2: recorded process (511, 1) re-execs the same binary (matching
  // cdhash, both strictly enforced) with no expectation -> relaxed.
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               uint8_t cdhash[20];
               memset(cdhash, 0x77, sizeof(cdhash));
               msg->process->audit_token = santa::MakeStubAuditToken(511, 1);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD;
               memcpy(msg->process->cdhash, cdhash, 20);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD;
               memcpy(msg->event.exec.target->cdhash, cdhash, 20);
             }];
}

// A self-exec from a process Santa never recorded as sandboxed (e.g. launched
// before the seatbelt rule existed) is denied: the transitive guarantee does
// not hold.
- (void)testSeatbeltSelfExecNotTrackedDenies {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(520, 1);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 17;
               msg->process->executable->stat.st_ino = 42;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;
             }];
}

// A recorded sandboxed process exec'ing a *different* seatbelt binary is denied:
// the relaxation is limited to self-exec.
- (void)testSeatbeltSandboxedNonSelfExecDenies {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];
  // No cached decision for the instigator -> relaxation uses the (dev, ino) fallback.
  [self stubInstigatorSHA256:nil];

  // Call 1: record sandboxed target token (531, 1).
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(530, 1);
               msg->event.exec.target->audit_token = santa::MakeStubAuditToken(531, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];

  // Call 2: instigator (531, 1) is recorded, but the target is a different
  // binary (different dev/ino) -> not a self-exec -> denied.
  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(531, 1);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 17;
               msg->process->executable->stat.st_ino = 42;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 99;
               msg->event.exec.target->executable->stat.st_ino = 88;
             }];
}

// A process that forks (possibly several times -- the classic double-fork
// daemonization) from a sandboxed seatbelt process and then re-execs the same
// binary is allowed, even though the forked descendant's own (pid, pidversion)
// was never recorded. The ancestry walk finds the recorded sandboxed ancestor.
- (void)testSeatbeltSandboxedForkedDescendantSelfExecAllows {
  using namespace santa::santad::process_tree;
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::vector<std::unique_ptr<Annotator>>{});
  std::shared_ptr<const Process> init = tree->InsertInit();

  uint64_t eventId = 1;
  // B (600, 1): the sandboxed seatbelt process.
  struct Pid bPid = {.pid = 600, .pidversion = 1};
  tree->HandleFork(eventId++, *init, bPid);
  // B fork -> C (601, 2).
  struct Pid cPid = {.pid = 601, .pidversion = 2};
  tree->HandleFork(eventId++, **tree->Get(bPid), cPid);
  // C fork -> D (602, 3).
  struct Pid dPid = {.pid = 602, .pidversion = 3};
  tree->HandleFork(eventId++, **tree->Get(cPid), dPid);

  self.sut = [self makeControllerWithProcessTree:tree];

  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];
  // No cached decision for the instigator -> relaxation uses the (dev, ino) fallback.
  [self stubInstigatorSHA256:nil];

  // Call 1: B is authorized via expectation; its token (600, 1) is recorded.
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(599, 1);
               msg->event.exec.target->audit_token = santa::MakeStubAuditToken(600, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];

  // Call 2: the double-forked descendant D (602, 3) re-execs the same binary
  // with no expectation -> relaxed via ancestry to recorded B.
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(602, 3);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 17;
               msg->process->executable->stat.st_ino = 42;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;
             }];
}

// A descendant of a process Santa never recorded as sandboxed is denied: the
// ancestry walk finds no recorded ancestor, so the transitive guarantee does
// not hold.
- (void)testSeatbeltForkedDescendantOfUnsandboxedDenies {
  using namespace santa::santad::process_tree;
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::vector<std::unique_ptr<Annotator>>{});
  std::shared_ptr<const Process> init = tree->InsertInit();

  uint64_t eventId = 1;
  struct Pid bPid = {.pid = 700, .pidversion = 1};
  tree->HandleFork(eventId++, *init, bPid);
  struct Pid cPid = {.pid = 701, .pidversion = 2};
  tree->HandleFork(eventId++, **tree->Get(bPid), cPid);

  self.sut = [self makeControllerWithProcessTree:tree];

  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  // No ancestor was recorded -> C (701, 2) self-exec is denied.
  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(701, 2);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 17;
               msg->process->executable->stat.st_ino = 42;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;
             }];
}

// In the fallback (non-strict) mode a matching SHA-256 authorizes the self-exec
// even when (dev, ino) differ, exercising the hash comparison in SameBinary.
- (void)testSeatbeltSandboxedSelfExecAllowsViaSHA256 {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];
  // Cached instigator hash matches the target's SHA-256 (@"cafebabe").
  [self stubInstigatorSHA256:@"cafebabe"];

  // Call 1: record sandboxed target token (701, 1).
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(700, 1);
               msg->event.exec.target->audit_token = santa::MakeStubAuditToken(701, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];

  // Call 2: instigator (701, 1) re-execs with a DIFFERENT (dev, ino) but the same
  // content hash -> relaxed via the SHA-256 comparison rather than (dev, ino).
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(701, 1);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 1;
               msg->process->executable->stat.st_ino = 2;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 99;
               msg->event.exec.target->executable->stat.st_ino = 88;
             }];
}

// After a process exits (forgetSandboxedSeatbeltProc:), a subsequent self-exec of
// the same (pid, pidversion) is no longer relaxed.
- (void)testForgetSandboxedSeatbeltProcDenies {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];

  // Call 1: record sandboxed target token (801, 1).
  [self validateExecEvent:SNTActionRespondAllowNoCache
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(800, 1);
               msg->event.exec.target->audit_token = santa::MakeStubAuditToken(801, 1);
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;

               const uint8_t cdhash[20] = {0};
               _sandboxExpectations->Register(msg->process->audit_token,
                                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
             }];

  // Evict the recorded process, as the tree-aware authorizer does on its exit.
  audit_token_t exited = santa::MakeStubAuditToken(801, 1);
  [self.sut forgetSandboxedSeatbeltProc:exited];

  // Call 2: the now-forgotten (801, 1) re-execs -> no longer relaxed -> denied.
  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->process->audit_token = santa::MakeStubAuditToken(801, 1);
               msg->process->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->process->executable->stat.st_dev = 17;
               msg->process->executable->stat.st_ino = 42;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
               msg->event.exec.target->executable->stat.st_dev = 17;
               msg->event.exec.target->executable->stat.st_ino = 42;
             }];
}

@end
