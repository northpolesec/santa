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

#include <string>
#include <vector>

#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.h"
#include "Source/common/processtree/process_tree_test_helpers.h"

#include "Source/common/AuditUtilities.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSandboxExecRequest.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EntitlementsFilter.h"
#include "Source/santad/ProcessControl.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTPolicyProcessor.h"
#import "Source/santad/SNTTimedRuleKills.h"
#include "Source/santad/SandboxExpectations.h"

using santa::Message;

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

@interface SNTExecutionController (Testing)
- (void)createRuleForStandaloneModeEvent:(SNTStoredExecutionEvent*)se
                      identityMismatched:(BOOL)identityMismatched;
@end

@interface SNTRule ()
// Making these properties readwrite makes some tests much easier to write.
@property(readwrite) SNTRuleState state;
@property(readwrite) SNTRuleType type;
@property(readwrite) NSString* customMsg;
@property(readwrite) NSString* celExpr;
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
  self.sut = [[SNTExecutionController alloc] initWithRuleTable:self.mockRuleDatabase
                                                    eventTable:self.mockEventDatabase
                                                 notifierQueue:nil
                                                    syncdQueue:nil
                                                        logger:nullptr
                                                     ttyWriter:santa::TTYWriter::Create(true)
                                               policyProcessor:policyProcessor
                                           processControlBlock:santa::ProdSuspendResumeBlock()
                                                   processTree:nullptr
                                           sandboxExpectations:_sandboxExpectations
                                                timedRuleKills:nil
                                               believableClock:nil];
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
  BOOL foundField = NO;
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
  [self validateExecEvent:wantAction args:{} messageSetup:messageSetupBlock];
}

- (void)validateExecEvent:(SNTAction)wantAction {
  [self validateExecEvent:wantAction messageSetup:nil];
}

// Like validateExecEvent:messageSetup: but also stubs the argument vector the
// CEL activation sees, so rules using `args` can be exercised.
//
// ExecArgs must be stubbed directly: EndpointSecurityAPI::ExecArgs calls the
// free es_exec_arg_count()/es_exec_arg() functions rather than the virtual
// ExecArgCount()/ExecArg() methods, so stubbing those has no effect here.
- (void)validateExecEvent:(SNTAction)wantAction
                     args:(std::vector<std::string>)args
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
  EXPECT_CALL(*mockESApi, ExecArgs).WillRepeatedly(testing::Return(args));

  {
    Message msg(mockESApi, &esMsg);
    [self.sut validateExecEvent:msg cachedDecision:nil postAction:verifyPostAction(wantAction)];
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

// Stubs the source-process decision lookup used by the seatbelt self-exec
// relaxation (-isSameBinaryAsInstigator:...). Pass nil to simulate no cached
// decision for the instigator (forcing the (dev, ino) fallback), or a SHA-256 to
// simulate a cached hash for the instigator's image.
- (void)stubInstigatorSHA256:(NSString*)sha256 {
  [self stubInstigatorSHA256:sha256 identityMismatched:NO];
}

- (void)stubInstigatorSHA256:(NSString*)sha256 identityMismatched:(BOOL)identityMismatched {
  SNTCachedDecision* dec = nil;
  if (sha256.length) {
    dec = [[SNTCachedDecision alloc] init];
    dec.sha256 = sha256;
    dec.identityMismatched = identityMismatched;
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
  return [[SNTExecutionController alloc] initWithRuleTable:self.mockRuleDatabase
                                                eventTable:self.mockEventDatabase
                                             notifierQueue:nil
                                                syncdQueue:nil
                                                    logger:nullptr
                                                 ttyWriter:santa::TTYWriter::Create(true)
                                           policyProcessor:policyProcessor
                                       processControlBlock:santa::ProdSuspendResumeBlock()
                                               processTree:tree
                                       sandboxExpectations:_sandboxExpectations
                                            timedRuleKills:nil
                                           believableClock:nil];
}

- (void)stubRule:(SNTRule*)rule forIdentifiers:(struct RuleIdentifiers)wantIdentifiers {
  OCMStub([self.mockRuleDatabase executionRuleForIdentifiers:wantIdentifiers useCache:YES])
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

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

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

// ---------------- Contextual (non-cacheable) compiler rules ----------------

// A CEL compiler rule that reads argv authorizes only the invocation it
// matched. It must not produce a terminal, reusable action.
- (void)testCELCompilerRuleBinaryIsNotReusable {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeBinary;
  rule.celExpr = @"size(args) > 1 && args[1] == '--build' ? ALLOWLIST_COMPILER : BLOCKLIST";
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowCompilerNoCache
                     args:{"clang", "--build"}
             messageSetup:nil];
}

- (void)testCELCompilerRuleSigningIDIsNotReusable {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  NSString* signingID = [NSString stringWithFormat:@"%s:%s", kExampleTeamID, kExampleSigningID];

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeSigningID;
  rule.celExpr = @"size(args) > 1 && args[1] == '--build' ? ALLOWLIST_COMPILER : BLOCKLIST";
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"a", .signingID = signingID, .teamID = @(kExampleTeamID)}];

  [self validateExecEvent:SNTActionRespondAllowCompilerNoCache
                     args:{"clang", "--build"}
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
               msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
             }];
}

- (void)testCELCompilerRuleCDHashIsNotReusable {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeCDHash;
  rule.celExpr = @"size(args) > 1 && args[1] == '--build' ? ALLOWLIST_COMPILER : BLOCKLIST";
  [self stubRule:rule
      forIdentifiers:{.cdhash = @"aa00000000000000000000000000000000000000", .binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowCompilerNoCache
                     args:{"clang", "--build"}
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.target->cdhash[0] = 0xaa;
               msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
             }];
}

// The blocked context must still be blocked. Together with the tests above this
// pins both directions of the contextual rule.
- (void)testCELCompilerRuleBlockedContextDenies {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeBinary;
  rule.celExpr = @"size(args) > 1 && args[1] == '--build' ? ALLOWLIST_COMPILER : BLOCKLIST";
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondDeny args:{"clang", "--link"} messageSetup:nil];
}

// Anti-over-fix guard: an ordinary, cacheable ALLOWLIST_COMPILER rule must keep
// producing the terminal action. Without this, a change that simply disabled
// compiler caching entirely would pass every other test in this file.
- (void)testStaticCompilerRuleRemainsReusable {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowCompiler args:{"clang"} messageSetup:nil];
}

// A CEL rule that resolves no dynamic field stays cacheable, so a compiler
// result from it is still reusable.
- (void)testCELCompilerRuleWithoutDynamicFieldsRemainsReusable {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeBinary;
  rule.celExpr = @"target.is_platform_binary == false ? ALLOWLIST_COMPILER : BLOCKLIST";
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self validateExecEvent:SNTActionRespondAllowCompiler args:{"clang"} messageSetup:nil];
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

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

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

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

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
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

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

- (void)testMissingShasumUsesClientModeDefault {
  // No SHA-256 is stubbed; the decision must still complete via the client
  // mode default.
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);

  [self validateExecEvent:SNTActionRespondAllow];
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

- (void)testUnparseableBlockedInLockdownByDefault {
  OCMStub([self.mockFileInfo isMachO]).andReturn(NO);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny];
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockUnknown expected:@1];
}

- (void)testPageZero {
  OCMStub([self.mockConfigurator enablePageZeroProtection]).andReturn(YES);
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo isMissingPageZero]).andReturn(YES);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self validateExecEvent:SNTActionRespondDeny
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.image_cputype = CPU_TYPE_X86;
             }];
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  [self checkMetricCounters:kBlockScope expected:@1];
}

- (void)testPageZeroNotEnforcedForNonI386Image {
  OCMStub([self.mockConfigurator enablePageZeroProtection]).andReturn(YES);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo isMissingPageZero]).andReturn(YES);

  // Same file, but a 64-bit image executed. The kernel enforces __PAGEZERO for
  // those itself, so the file's i386 slice must not block this execution.
  [self validateExecEvent:SNTActionRespondAllow
             messageSetup:^(es_message_t* msg) {
               msg->event.exec.image_cputype = CPU_TYPE_X86_64;
             }];
  [self checkMetricCounters:kAllowUnknown expected:@1];
}

- (void)testAllEventUpload {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  OCMExpect([self.mockConfigurator enableAllEventUpload]).andReturn(YES);
  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

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
  OCMVerify(never(), [self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);
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
                eventDetailButtonText:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained NotificationReplyBlock block;
        [invocation getArgument:&block atIndex:7];
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
                                      imageCPUType:0
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
           timedRuleKills:nil
          believableClock:nil];

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

// When the kernel kills the process for code signature invalidity, a block must
// still be applied and logged but no UI shown, and there's nothing to hold for
// approval.
- (void)validateBlockWithCodesigningFlags:(uint32_t)csFlags
                             imageCPUType:(cpu_type_t)imageCPUType
                           expectedAction:(SNTAction)expectedAction
                                  wantGUI:(BOOL)wantGUI {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  __block BOOL guiShown = NO;
  OCMStub([mockNotifierQueue addEvent:OCMOCK_ANY
                    withCustomMessage:OCMOCK_ANY
                            customURL:OCMOCK_ANY
                eventDetailButtonText:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        guiShown = YES;
      });

  id mockPolicyProcessor = OCMClassMock([SNTPolicyProcessor class]);
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.decision = SNTEventStateBlockSigningID;
  cd.holdAndAsk = YES;
  cd.decisionClientMode = SNTClientModeLockdown;

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t procExec = MakeESProcess(&fileExec);
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = csFlags;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;
  esMsg.event.exec.image_cputype = imageCPUType;

  OCMStub([mockPolicyProcessor decisionForFileInfo:OCMOCK_ANY
                                     targetProcess:&procExec
                                      imageCPUType:imageCPUType
                                       configState:OCMOCK_ANY
                                activationCallback:OCMOCK_ANY
                                    cachedDecision:OCMOCK_ANY])
      .ignoringNonObjectArgs()
      .andReturn(cd);

  LogExecutionBlock loggerBlock = ^(Message esMsg) {
  };
  santa::ProcessControlBlock processControl = ^bool(pid_t pid, santa::ProcessControl control) {
    return true;
  };

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
           timedRuleKills:nil
          believableClock:nil];

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

  XCTAssertEqual(resultAction, expectedAction);
  XCTAssertEqual(guiShown, wantGUI);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockNotifierQueue stopMocking];
  [mockPolicyProcessor stopMocking];
}

- (void)testBlockWithCSKilledIsSilent {
  [self validateBlockWithCodesigningFlags:CS_KILLED
                             imageCPUType:CPU_TYPE_ANY
                           expectedAction:SNTActionRespondDeny
                                  wantGUI:NO];
}

// CS_KILL without CS_VALID is terminal for native arm64, where signing is
// required, but not for x86_64, where unsigned code may execute.
- (void)testBlockWithCSKillOnlyUsesTargetArchitecture {
  [self validateBlockWithCodesigningFlags:CS_KILL
                             imageCPUType:CPU_TYPE_ARM64
                           expectedAction:SNTActionRespondDeny
                                  wantGUI:NO];
  [self validateBlockWithCodesigningFlags:CS_KILL
                             imageCPUType:CPU_TYPE_X86_64
                           expectedAction:SNTActionRespondHold
                                  wantGUI:YES];
}

- (void)testBlockWithValidSignatureShowsGUI {
  [self validateBlockWithCodesigningFlags:CS_SIGNED | CS_VALID | CS_KILL
                             imageCPUType:CPU_TYPE_ARM64
                           expectedAction:SNTActionRespondHold
                                  wantGUI:YES];
}

// Invalid signature but the kernel is not set to kill for it.
- (void)testBlockWithInvalidAndNoCSKillShowsGUI {
  [self validateBlockWithCodesigningFlags:CS_SIGNED
                             imageCPUType:CPU_TYPE_ARM64
                           expectedAction:SNTActionRespondHold
                                  wantGUI:YES];
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
                eventDetailButtonText:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained NotificationReplyBlock block;
        [invocation getArgument:&block atIndex:7];
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
                                      imageCPUType:0
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
           timedRuleKills:nil
          believableClock:nil];

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

#pragma mark Timed rule kills

/// A decision carrying the kill an in-window policy_for_range(...,
/// kill_on_expiry(policy)) asked for, as SNTPolicyProcessor would have left it.
/// Never cacheable: the window edge has to enforce itself on the next exec.
- (SNTCachedDecision*)decisionWithTimedRuleKill:(SNTEventState)state {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.decision = state;
  cd.decisionClientMode = SNTClientModeLockdown;
  cd.sha256 = @"a";
  cd.cacheable = NO;
  cd.timedRuleKillDeadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  cd.timedRuleKillNotifyAt = [NSDate dateWithTimeIntervalSinceNow:3300];
  cd.timedRuleKillRuleType = SNTRuleTypeTeamID;
  cd.timedRuleKillIdentifier = @"ABCDE12345";
  cd.ruleId = 48213;
  cd.timedRuleKillWindowDays = @[ @1, @2, @3, @4, @5 ];
  cd.timedRuleKillWindowStart = @"09:00";
  cd.timedRuleKillWindowEnd = @"17:00";
  cd.timedRuleKillWindowZone = @"America/New_York";
  return cd;
}

- (NSArray<NSDictionary*>*)recordedKillsForDecision:(SNTCachedDecision*)cd
                                       touchIDReply:(NSNumber*)touchIDReply {
  return [self recordedKillsForDecision:cd
                           touchIDReply:touchIDReply
                        suspendSucceeds:YES
                         resumeSucceeds:YES];
}

/// Runs one exec whose policy decision is `cd` through a controller wired to a
/// mocked SNTTimedRuleKills, and returns the kills it recorded, one dictionary
/// per call holding the decision and the pid and pidversion of the token passed.
/// `touchIDReply` is nil unless the decision holds for TouchID, in which case
/// the captured reply block is invoked with it. `suspendSucceeds` and
/// `resumeSucceeds` are what suspending and resuming the held process report
/// back; NO is a hold that could not stop the process, or a resume that failed.
- (NSArray<NSDictionary*>*)recordedKillsForDecision:(SNTCachedDecision*)cd
                                       touchIDReply:(NSNumber*)touchIDReply
                                    suspendSucceeds:(BOOL)suspendSucceeds
                                     resumeSucceeds:(BOOL)resumeSucceeds {
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);

  id mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  __block NotificationReplyBlock capturedReplyBlock = nil;
  OCMStub([mockNotifierQueue addEvent:OCMOCK_ANY
                    withCustomMessage:OCMOCK_ANY
                            customURL:OCMOCK_ANY
                eventDetailButtonText:OCMOCK_ANY
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained NotificationReplyBlock block;
        [invocation getArgument:&block atIndex:7];
        capturedReplyBlock = [block copy];
      });

  NSMutableArray<NSDictionary*>* recorded = [NSMutableArray array];
  id mockTimedRuleKills = OCMClassMock([SNTTimedRuleKills class]);
  audit_token_t anyToken = {};
  OCMStub([mockTimedRuleKills recordKillForDecision:OCMOCK_ANY process:anyToken])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained SNTCachedDecision* decision;
        audit_token_t token;
        [invocation getArgument:&decision atIndex:2];
        [invocation getArgument:&token atIndex:3];
        // Built key by key rather than as a literal: andDo() is a macro, and a
        // comma inside a braced literal would be read as another argument to it.
        NSMutableDictionary* call = [NSMutableDictionary dictionary];
        call[@"decision"] = decision;
        call[@"pid"] = @(audit_token_to_pid(token));
        call[@"pidversion"] = @(audit_token_to_pidversion(token));
        [recorded addObject:call];
      });

  id mockPolicyProcessor = OCMClassMock([SNTPolicyProcessor class]);

  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  // A known token, so both record sites can be shown to forward the exec
  // target's rather than the parent's.
  es_process_t procExec = MakeESProcess(&fileExec, MakeAuditToken(4242, 7));
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &procExec;

  OCMStub([mockPolicyProcessor decisionForFileInfo:OCMOCK_ANY
                                     targetProcess:&procExec
                                      imageCPUType:0
                                       configState:OCMOCK_ANY
                                activationCallback:OCMOCK_ANY
                                    cachedDecision:OCMOCK_ANY])
      .ignoringNonObjectArgs()
      .andReturn(cd);

  SNTExecutionController* controller =
      [[SNTExecutionController alloc] initWithRuleTable:self.mockRuleDatabase
          eventTable:self.mockEventDatabase
          notifierQueue:mockNotifierQueue
          syncdQueue:nil
          logger:^(Message esMsg) {
          }
          ttyWriter:santa::TTYWriter::Create(true)
          policyProcessor:mockPolicyProcessor
          processControlBlock:^bool(pid_t pid, santa::ProcessControl control) {
            switch (control) {
              case santa::ProcessControl::Suspend: return suspendSucceeds;
              case santa::ProcessControl::Resume: return resumeSucceeds;
              case santa::ProcessControl::Kill: return true;
            }
          }
          processTree:nullptr
          sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
          timedRuleKills:mockTimedRuleKills
          believableClock:nil];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  {
    Message msg(mockESApi, &esMsg);
    [controller validateExecEvent:msg
                   cachedDecision:nil
                       postAction:^bool(SNTAction action, SNTCachedDecision* decision) {
                         return true;
                       }];
  }

  if (touchIDReply) {
    XCTAssertNotNil(capturedReplyBlock, @"Reply block should have been captured");
    XCTAssertEqual(recorded.count, 0UL, @"A held execution has not proceeded yet");
    capturedReplyBlock(touchIDReply.boolValue);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockNotifierQueue stopMocking];
  [mockPolicyProcessor stopMocking];
  [mockTimedRuleKills stopMocking];
  return recorded;
}

// An allowed in-window exec records the kill: the decision passed through
// untouched (the identifier especially, which the fire-time re-check looks the
// rule up by, case-sensitively) and the exec target's own audit token.
- (void)testTimedRuleKillRecordedWhenTheExecIsAllowed {
  SNTCachedDecision* cd = [self decisionWithTimedRuleKill:SNTEventStateAllowBinary];
  NSArray<NSDictionary*>* recorded = [self recordedKillsForDecision:cd touchIDReply:nil];

  XCTAssertEqual(recorded.count, 1UL);
  NSDictionary* call = recorded.firstObject;
  SNTCachedDecision* decision = call[@"decision"];
  XCTAssertEqual(decision.timedRuleKillRuleType, SNTRuleTypeTeamID);
  XCTAssertEqualObjects(decision.timedRuleKillIdentifier, @"ABCDE12345");
  XCTAssertEqual(decision.ruleId, 48213LL);
  XCTAssertEqualObjects(decision.timedRuleKillDeadline, cd.timedRuleKillDeadline);
  XCTAssertEqualObjects(decision.timedRuleKillNotifyAt, cd.timedRuleKillNotifyAt);
  XCTAssertEqualObjects(decision.timedRuleKillWindowDays, (@[ @1, @2, @3, @4, @5 ]));
  XCTAssertEqualObjects(decision.timedRuleKillWindowStart, @"09:00");
  XCTAssertEqualObjects(decision.timedRuleKillWindowEnd, @"17:00");
  XCTAssertEqualObjects(decision.timedRuleKillWindowZone, @"America/New_York");
  XCTAssertEqualObjects(call[@"pid"], @4242);
  XCTAssertEqualObjects(call[@"pidversion"], @7);
}

// Everything that stops the kill being recorded, all of it the same condition:
// the execution has to be allowed. A held (TouchID) execution is allowed at the
// approval reply, whatever the suspend or resume reported: a hold that could not
// stop the process left it running, and a resume that failed left it stopped for
// SIGKILL to take at the deadline.
- (void)testTimedRuleKillIsRecordedOnlyWhenTheExecProceeds {
  struct {
    NSString* name;
    SNTEventState state;
    BOOL withDeadline;
    BOOL holdAndAsk;
    NSNumber* touchIDReply;
    BOOL suspendSucceeds;
    BOOL resumeSucceeds;
    NSUInteger expected;
  } cases[] = {
      // In window with the kill asked for, but the policy in the window blocks.
      {@"blocked", SNTEventStateBlockBinary, YES, NO, nil, YES, YES, 0},
      // What both an out-of-window exec and an unwrapped policy leave behind.
      {@"no deadline", SNTEventStateAllowBinary, NO, NO, nil, YES, YES, 0},
      {@"TouchID approves", SNTEventStateBlockSigningID, YES, YES, @YES, YES, YES, 1},
      {@"TouchID denies", SNTEventStateBlockSigningID, YES, YES, @NO, YES, YES, 0},
      // A hold that could not stop the process left it running: recorded.
      {@"suspend failed, approved", SNTEventStateBlockSigningID, YES, YES, @YES, NO, YES, 1},
      // A resume that failed left it stopped, and SIGKILL takes it: recorded.
      {@"resume failed, approved", SNTEventStateBlockSigningID, YES, YES, @YES, YES, NO, 1},
  };

  for (const auto& c : cases) {
    SNTCachedDecision* cd;
    if (c.withDeadline) {
      cd = [self decisionWithTimedRuleKill:c.state];
    } else {
      cd = [[SNTCachedDecision alloc] init];
      cd.decision = c.state;
      cd.sha256 = @"a";
    }
    cd.holdAndAsk = c.holdAndAsk;

    NSArray<NSDictionary*>* recorded = [self recordedKillsForDecision:cd
                                                         touchIDReply:c.touchIDReply
                                                      suspendSucceeds:c.suspendSucceeds
                                                       resumeSucceeds:c.resumeSucceeds];
    XCTAssertEqual(recorded.count, c.expected, @"%@", c.name);
    if (c.expected) {
      // The TouchID site forwards the exec target's token just as the allow
      // site does.
      XCTAssertEqualObjects([recorded.firstObject[@"decision"] timedRuleKillIdentifier],
                            @"ABCDE12345", @"%@", c.name);
      XCTAssertEqualObjects(recorded.firstObject[@"pid"], @4242, @"%@", c.name);
      XCTAssertEqualObjects(recorded.firstObject[@"pidversion"], @7, @"%@", c.name);
    }
  }
}

// An approval that arrives after the window closed neither resumes the process
// nor records a kill: the one it would record is already due.
- (void)testTimedRuleKillTouchIDApprovalAfterDeadlineIsDenied {
  SNTCachedDecision* cd = [self decisionWithTimedRuleKill:SNTEventStateBlockSigningID];
  cd.holdAndAsk = YES;
  cd.timedRuleKillDeadline = [NSDate dateWithTimeIntervalSinceNow:-1];

  NSArray<NSDictionary*>* recorded = [self recordedKillsForDecision:cd touchIDReply:@YES];

  XCTAssertEqual(recorded.count, 0UL);
  XCTAssertEqual(cd.decision, SNTEventStateBlockSigningID);
  XCTAssertEqualObjects(cd.decisionExtra, @"TouchID Approved After Expiry");
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
           timedRuleKills:nil
          believableClock:nil];

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
  tree->HandleFork(eventId++, init, bPid);
  // B fork -> C (601, 2).
  struct Pid cPid = {.pid = 601, .pidversion = 2};
  tree->HandleFork(eventId++, *tree->Get(bPid), cPid);
  // C fork -> D (602, 3).
  struct Pid dPid = {.pid = 602, .pidversion = 3};
  tree->HandleFork(eventId++, *tree->Get(cPid), dPid);

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
  tree->HandleFork(eventId++, init, bPid);
  struct Pid cPid = {.pid = 701, .pidversion = 2};
  tree->HandleFork(eventId++, *tree->Get(bPid), cPid);

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

#pragma mark Executable identity verification

// Like validateExecEvent:messageSetup: but returns the decision the controller
// posted, so tests can assert on its fields.
- (SNTCachedDecision*)postedDecisionForExecEvent:(SNTAction)wantAction
                                  cachedDecision:(SNTCachedDecision*)cachedDecision
                                    messageSetup:(void (^)(es_message_t*))messageSetupBlock {
  __block SNTCachedDecision* posted = nil;
  __block BOOL didPost = NO;

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
  EXPECT_CALL(*mockESApi, ExecArgs).WillRepeatedly(testing::Return(std::vector<std::string>{}));

  {
    Message msg(mockESApi, &esMsg);
    [self.sut validateExecEvent:msg
                 cachedDecision:cachedDecision
                     postAction:^bool(SNTAction gotAction, SNTCachedDecision* cd) {
                       XCTAssertEqual(gotAction, wantAction);
                       posted = cd;
                       didPost = YES;
                       return true;
                     }];
  }

  // The action comparison above lives inside the block, so a controller that
  // returns without posting would run none of it. Assert the block ran rather
  // than that it produced a decision: a posted nil is legitimate, as the
  // fail-closed path with no file info shows.
  XCTAssertTrue(didPost, @"the controller returned without posting an action");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  return posted;
}

// Reports the file read for the target as not confirmed to be the file the
// event described.
- (void)stubUnconfirmedIdentity {
  OCMStub([self.mockFileInfo identityVerification]).andReturn(SNTFileInfoIdentityMismatch);
}

// The on-disk signature reports the same signing identifier the kernel did, so
// only the other conjuncts of the vendor comparison are under test.
- (void)stubMatchingOnDiskSigningID {
  OCMStub([self.mockCodesignChecker signingID]).andReturn(@(kExampleSigningID));
}

- (void)testUnconfirmedIdentityWithMatchingVendorIsAllowedWithoutCaching {
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeTeamID;
  [self stubRule:rule
      forIdentifiers:{.signingID = @"myteamid:example.signing.id", .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* cd = [self
      postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                  cachedDecision:nil
                    messageSetup:^(es_message_t* msg) {
                      msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                    }];

  XCTAssertNotNil(cd);
  XCTAssertTrue(cd.identityMismatched);
  XCTAssertFalse(cd.cacheable);
  XCTAssertNotNil(cd.decisionExtra);
}

- (void)testUnconfirmedIdentityWithNoTeamIDIsDenied {
  // CS_SIGNED and CS_VALID but no signing identifier on either side. Equality
  // alone would treat "absent on both sides" as a match; what denies here is
  // the requirement that both be non-empty.
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  SNTCachedDecision* cd = [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                                            cachedDecision:nil
                                              messageSetup:^(es_message_t* msg) {
                                                msg->event.exec.target->codesigning_flags =
                                                    CS_SIGNED | CS_VALID;
                                              }];

  XCTAssertNotNil(cd);
  XCTAssertEqual(cd.decision, SNTEventStateBlockBinaryMismatch);
  XCTAssertTrue(cd.identityMismatched);
  XCTAssertFalse(cd.cacheable);
  OCMVerify([self.mockDecisionCache cacheDecision:cd]);
  [self checkMetricCounters:kBlockBinaryMismatch expected:@1];
}

- (void)testUnconfirmedIdentityWithTeamIDOnKernelSideOnlyIsDenied {
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      }];
}

- (void)testUnconfirmedIdentityWithTeamIDOnDiskSideOnlyIsDenied {
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce cachedDecision:nil messageSetup:nil];
}

- (void)testUnconfirmedIdentityWithDifferentTeamIDsIsDenied {
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@"BBBBBBBBBB");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->team_id = MakeESStringToken("AAAAAAAAAA");
                      }];
}

- (void)testUnconfirmedIdentityWhenUnsignedIsDenied {
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->codesigning_flags = 0;
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      }];
}

- (void)testUnconfirmedIdentityOnPlatformBinaryIsAllowed {
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker platformBinary]).andReturn(YES);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"a", .signingID = @"platform:example.signing.id"}];

  SNTCachedDecision* cd = [self postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                                            cachedDecision:nil
                                              messageSetup:^(es_message_t* msg) {
                                                msg->event.exec.target->is_platform_binary = true;
                                                msg->event.exec.target->signing_id =
                                                    MakeESStringToken(kExampleSigningID);
                                              }];

  XCTAssertTrue(cd.identityMismatched);
}

- (void)testUnconfirmedIdentityIsDeniedInMonitorMode {
  // Denied regardless of client mode: a tampering condition, which Santa
  // already treats as mode-independent.
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeMonitor);
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  SNTCachedDecision* cd = [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                                            cachedDecision:nil
                                              messageSetup:^(es_message_t* msg) {
                                                msg->event.exec.target->codesigning_flags =
                                                    CS_SIGNED | CS_VALID;
                                              }];

  XCTAssertEqual(cd.decision, SNTEventStateBlockBinaryMismatch);
}

- (void)testUnconfirmedIdentityDropsCompilerStatus {
  // Compiler status cannot follow from evaluating a different file.
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"a",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* cd = [self
      postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                  cachedDecision:nil
                    messageSetup:^(es_message_t* msg) {
                      msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                    }];

  XCTAssertEqual(cd.decision, SNTEventStateAllowBinary);
}

// The mapping that drops compiler status is per rule type, so the binary case
// above does not establish the other two.
- (void)testUnconfirmedIdentityDropsCompilerStatusForASigningIDRule {
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeSigningID;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"a",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* cd = [self
      postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                  cachedDecision:nil
                    messageSetup:^(es_message_t* msg) {
                      msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                    }];

  XCTAssertEqual(cd.decision, SNTEventStateAllowSigningID);
}

- (void)testUnconfirmedIdentityDropsCompilerStatusForACDHashRule {
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllowCompiler;
  rule.type = SNTRuleTypeCDHash;
  [self stubRule:rule
      forIdentifiers:{.cdhash = @"aa00000000000000000000000000000000000000",
                      .binarySHA256 = @"a",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* cd = [self
      postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                  cachedDecision:nil
                    messageSetup:^(es_message_t* msg) {
                      msg->event.exec.target->cdhash[0] = 0xaa;
                      msg->event.exec.target->codesigning_flags =
                          CS_SIGNED | CS_VALID | CS_KILL | CS_HARD;
                      msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                    }];

  XCTAssertEqual(cd.decision, SNTEventStateAllowCDHash);
}

// The gate's note is appended to whatever the evaluation already said. No rule
// is stubbed, so evaluation falls through to the platform branch, which sets a
// note of its own first. The tests above reach the gate through a rule match,
// which returns before it.
- (void)testUnconfirmedIdentityAppendsToAnExistingDecisionNote {
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker platformBinary]).andReturn(YES);

  SNTCachedDecision* cd = [self postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                                            cachedDecision:nil
                                              messageSetup:^(es_message_t* msg) {
                                                msg->event.exec.target->is_platform_binary = true;
                                                msg->event.exec.target->signing_id =
                                                    MakeESStringToken(kExampleSigningID);
                                              }];

  // Pins the setup: without this the note below could be the gate's own, set on
  // a nil value, which is what every other test in this group exercises.
  XCTAssertEqual(cd.decision, SNTEventStateAllowPlatform);
  XCTAssertEqualObjects(cd.decisionExtra,
                        @"Platform Binary; Executable identity confirmed by signing vendor only");
}

- (void)testUnconfirmedIdentityIgnoresExistingDecision {
  // The cached identity describes a different file. Honored, the rule lookup
  // would use its team ID and find nothing.
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeTeamID;
  [self stubRule:rule
      forIdentifiers:{.signingID = @"myteamid:example.signing.id", .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* existing = [[SNTCachedDecision alloc] init];
  existing.teamID = @"OTHERTEAMS";
  existing.signingID = @"OTHERTEAMS:other.signing.id";

  [self postedDecisionForExecEvent:SNTActionRespondAllowNoCache
                    cachedDecision:existing
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                        msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                      }];
}

- (void)testNilFileInfoFromAnIdentityMismatchIsDeniedRegardlessOfFailClosed {
  // The initializer can return nil after determining a mismatch. Without a
  // distinct error code the caller cannot tell that from an ordinary read
  // failure, which takes a different path.
  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);

  // Replace the shared SNTFileInfo mock: OCMock applies the first matching
  // stub, so the one installed in -setUp would otherwise win.
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  NSError* mismatchError = [NSError errorWithDomain:@"com.northpolesec.santa.common"
                                               code:SNTErrorCodeIdentityMismatch
                                           userInfo:nil];
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:mismatchError]])
      .ignoringNonObjectArgs()
      .andReturn(nil);

  SNTCachedDecision* cd = [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                                            cachedDecision:nil
                                              messageSetup:nil];

  XCTAssertNotNil(cd);
  XCTAssertEqual(cd.decision, SNTEventStateBlockBinaryMismatch);
  XCTAssertTrue(cd.identityMismatched);
}

- (void)testSeatbeltRequiredWithUnconfirmedIdentityIsDenied {
  // The fallback comparison is derived from the file that was read, so this is
  // the case the guard exists for: the expectation matches and the exec would
  // otherwise be authorized.
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"cafebabe",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* cd = [self
      postedDecisionForExecEvent:SNTActionRespondDenyOnce
                  cachedDecision:nil
                    messageSetup:^(es_message_t* msg) {
                      msg->process->audit_token = santa::MakeStubAuditToken(701, 1);
                      msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
                      msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                      msg->event.exec.target->executable->stat.st_dev = 17;
                      msg->event.exec.target->executable->stat.st_ino = 42;

                      const uint8_t cdhash[20] = {0};
                      _sandboxExpectations->Register(
                          msg->process->audit_token,
                          MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
                    }];

  XCTAssertEqual(cd.decision, SNTEventStateBlockBinaryMismatch);
  XCTAssertFalse(cd.cacheable);
}

// Registers a seatbelt expectation for (500, 1) and authorizes it, which records
// (501, 1) as a sandboxed seatbelt process. That process is the instigator in
// the self-exec tests below.
- (void)authorizeSandboxedSeatbeltProcess {
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
}

- (void)testInstigatorHashIsIgnoredWhenItsIdentityWasUnconfirmed {
  // The recorded hash describes a different file, so it is unusable. SameBinary
  // then falls back to the kernel-reported identity, which both share here.
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];
  [self stubInstigatorSHA256:@"deadbeef" identityMismatched:YES];

  [self authorizeSandboxedSeatbeltProcess];

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

- (void)testInstigatorHashIsUsedWhenItsIdentityWasConfirmed {
  // Same shape, but the recorded hash is usable and disagrees with the target,
  // so the relaxation must not apply.
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"cafebabe"}];
  [self stubInstigatorSHA256:@"deadbeef" identityMismatched:NO];

  [self authorizeSandboxedSeatbeltProcess];

  [self validateExecEvent:SNTActionRespondDeny
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

- (void)testUnconfirmedIdentityIsNotReusedByALaterExecution {
  // A decision whose identity was never confirmed must not be handed to a later
  // execution as pre-computed identity: the restrictions that applied to the
  // evaluation those values came from do not travel with them.
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeTeamID;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"a",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  SNTCachedDecision* poisoned = [[SNTCachedDecision alloc] init];
  poisoned.identityMismatched = YES;
  poisoned.sha256 = @"unconfirmed-hash";
  poisoned.teamID = @"OTHERTEAMS";
  poisoned.signingID = @"OTHERTEAMS:other.signing.id";

  // This execution is itself fine, so the drift gate never fires; the guard has
  // to key off the incoming decision rather than this execution's state.
  [self postedDecisionForExecEvent:SNTActionRespondAllow
                    cachedDecision:poisoned
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                        msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                      }];
}

- (void)testUnconfirmedIdentityDenialIsReported {
  // A denial that returns early must still produce the stored event that feeds
  // the console and the sync server.
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  __block SNTStoredExecutionEvent* reported = nil;
  OCMExpect([self.mockEventDatabase
      addStoredEvent:[OCMArg checkWithBlock:^BOOL(SNTStoredExecutionEvent* se) {
        reported = se;
        return YES;
      }]]);

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
                      }];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  XCTAssertNotNil(reported);
  XCTAssertEqual(reported.decision, SNTEventStateBlockBinaryMismatch);
}

- (void)testNilFileInfoDenialIsReportedWithAPath {
  // Same, for the denial that has no SNTFileInfo to describe the file with.
  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);

  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  NSError* mismatchError = [NSError errorWithDomain:@"com.northpolesec.santa.common"
                                               code:SNTErrorCodeIdentityMismatch
                                           userInfo:nil];
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:mismatchError]])
      .ignoringNonObjectArgs()
      .andReturn(nil);

  __block SNTStoredExecutionEvent* reported = nil;
  OCMExpect([self.mockEventDatabase
      addStoredEvent:[OCMArg checkWithBlock:^BOOL(SNTStoredExecutionEvent* se) {
        reported = se;
        return YES;
      }]]);

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce cachedDecision:nil messageSetup:nil];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  XCTAssertNotNil(reported);
  XCTAssertEqual(reported.decision, SNTEventStateBlockBinaryMismatch);
  // No SNTFileInfo existed, so the path has to come from the event itself.
  XCTAssertEqualObjects(reported.filePath, @"bar");
}

- (void)testNilFileInfoDenialReportsTheKernelReportedIdentity {
  // No hash: the file could not be read, which is the condition being reported.
  // The kernel-supplied team and signing ID identify the binary instead.
  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);

  // setUp installs a catch-all initWithEndpointSecurityFile: stub and OCMock
  // applies the first match, so the mock has to be rebuilt to return nil here.
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  NSError* mismatchError = [NSError errorWithDomain:@"com.northpolesec.santa.common"
                                               code:SNTErrorCodeIdentityMismatch
                                           userInfo:nil];
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:mismatchError]])
      .ignoringNonObjectArgs()
      .andReturn(nil);

  __block SNTStoredExecutionEvent* reported = nil;
  OCMExpect([self.mockEventDatabase
      addStoredEvent:[OCMArg checkWithBlock:^BOOL(SNTStoredExecutionEvent* se) {
        reported = se;
        return YES;
      }]]);

  // Load-bearing: the default event's tokens are empty and map to nil, so the
  // assertions below would hold vacuously.
  SNTCachedDecision* cd = [self
      postedDecisionForExecEvent:SNTActionRespondDenyOnce
                  cachedDecision:nil
                    messageSetup:^(es_message_t* msg) {
                      msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                      msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                    }];

  // On the decision, which is what the NOTIFY_EXEC telemetry recovers by vnode.
  XCTAssertEqualObjects(cd.teamID, @(kExampleTeamID));
  XCTAssertEqualObjects(cd.signingID, @(kExampleSigningID));
  XCTAssertNil(cd.sha256);

  // And on the stored event, which is what reaches the console and the sync
  // server.
  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
  XCTAssertNotNil(reported);
  XCTAssertEqualObjects(reported.teamID, @(kExampleTeamID));
  XCTAssertEqualObjects(reported.signingID, @(kExampleSigningID));
}

- (void)testSeatbeltDenialForUnconfirmedIdentityIsReported {
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"cafebabe",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  OCMExpect([self.mockEventDatabase addStoredEvent:OCMOCK_ANY]);

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->process->audit_token = santa::MakeStubAuditToken(702, 1);
                        msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                        msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                        msg->event.exec.target->executable->stat.st_dev = 17;
                        msg->event.exec.target->executable->stat.st_ino = 42;

                        const uint8_t cdhash[20] = {0};
                        _sandboxExpectations->Register(
                            msg->process->audit_token,
                            MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
                      }];

  OCMVerifyAllWithDelay(self.mockEventDatabase, 1);
}

#pragma mark Early-denial ordering

// Runs an execution that must take one of the early-denial paths and returns the
// steps it took, in order: `cache` is the decision being stored where NOTIFY_EXEC
// telemetry can recover it by vnode, `respond` is the reply to Endpoint Security.
// The reporting that follows is checked with the event counter, the only part of
// it that is synchronous in this fixture.
- (NSArray<NSString*>*)earlyDenialStepsWithMessageSetup:(void (^)(es_message_t*))messageSetupBlock {
  NSMutableArray<NSString*>* steps = [NSMutableArray array];

  // setUp answers cacheDecision: with a stub and OCMock applies the first
  // matching stub, so the mock is rebuilt here to observe the call instead.
  self.mockDecisionCache = OCMStrictClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache cacheDecision:OCMOCK_ANY]).andDo(^(NSInvocation* invocation) {
    [steps addObject:@"cache"];
  });

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
  EXPECT_CALL(*mockESApi, ExecArgs).WillRepeatedly(testing::Return(std::vector<std::string>{}));

  {
    Message msg(mockESApi, &esMsg);
    [self.sut validateExecEvent:msg
                 cachedDecision:nil
                     postAction:^bool(SNTAction gotAction, SNTCachedDecision* cd) {
                       XCTAssertEqual(gotAction, SNTActionRespondDenyOnce);
                       // Reporting has not started: it must not precede the
                       // response, because it is unbounded work.
                       [self checkMetricCounters:kBlockBinaryMismatch expected:@0];
                       [steps addObject:@"respond"];
                       return true;
                     }];
  }

  // And the reporting did run, after.
  [self checkMetricCounters:kBlockBinaryMismatch expected:@1];

  return steps;
}

- (void)testNilFileInfoDenialRespondsBeforeReporting {
  OCMStub([self.mockConfigurator failClosed]).andReturn(NO);

  // setUp installs a catch-all initWithEndpointSecurityFile: stub and OCMock
  // applies the first match, so the mock has to be rebuilt to return nil here.
  [self.mockFileInfo stopMocking];
  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  NSError* mismatchError = [NSError errorWithDomain:@"com.northpolesec.santa.common"
                                               code:SNTErrorCodeIdentityMismatch
                                           userInfo:nil];
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:mismatchError]])
      .ignoringNonObjectArgs()
      .andReturn(nil);

  XCTAssertEqualObjects([self earlyDenialStepsWithMessageSetup:nil], (@[ @"cache", @"respond" ]));
}

- (void)testUnconfirmedIdentityDenialRespondsBeforeReporting {
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");

  XCTAssertEqualObjects([self earlyDenialStepsWithMessageSetup:^(es_message_t* msg) {
                          msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
                        }],
                        (@[ @"cache", @"respond" ]));
}

- (void)testSeatbeltDenialForUnconfirmedIdentityRespondsBeforeReporting {
  [self stubUnconfirmedIdentity];
  [self stubMatchingOnDiskSigningID];
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"cafebabe");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateSeatbelt;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule
      forIdentifiers:{.binarySHA256 = @"cafebabe",
                      .signingID = @"myteamid:example.signing.id",
                      .teamID = @(kExampleTeamID)}];

  XCTAssertEqualObjects([self earlyDenialStepsWithMessageSetup:^(es_message_t* msg) {
                          msg->process->audit_token = santa::MakeStubAuditToken(703, 1);
                          msg->event.exec.target->codesigning_flags = CS_SIGNED | CS_VALID;
                          msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                          msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                          msg->event.exec.target->executable->stat.st_dev = 17;
                          msg->event.exec.target->executable->stat.st_ino = 42;

                          const uint8_t cdhash[20] = {0};
                          _sandboxExpectations->Register(
                              msg->process->audit_token,
                              MakeSandboxRequest(17, 42, cdhash, @"cafebabe"));
                        }],
                        (@[ @"cache", @"respond" ]));
}

#pragma mark Standalone-mode rule creation

- (SNTStoredExecutionEvent*)standaloneEventWithSigningID:(NSString*)signingID {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.filePath = @"/tmp/example";
  se.fileSHA256 = @"6896d9ea3f73a4434f5832bc65714e7d066f177373f36f34dc8a6f735daa41b1";
  se.signingID = signingID;
  se.signingStatus = signingID ? SNTSigningStatusProduction : SNTSigningStatusUnsigned;
  return se;
}

- (void)testStandaloneRuleStillUsesSigningIDWhenIdentityIsUnconfirmed {
  // The signing ID is reported by the kernel for the image it loaded, so it
  // names the right file no matter what was read from disk. Gating it would
  // lose nothing but the user's approval.
  __block SNTRule* written = nil;
  OCMExpect([self.mockRuleDatabase
                addExecutionRules:[OCMArg checkWithBlock:^BOOL(NSArray<SNTRule*>* rules) {
                  written = rules.firstObject;
                  return YES;
                }]
                      ruleCleanup:SNTRuleCleanupNone
                           errors:[OCMArg anyObjectRef]])
      .andReturn(YES);

  [self.sut createRuleForStandaloneModeEvent:[self standaloneEventWithSigningID:@"ABCDEFGHIJ:app"]
                          identityMismatched:YES];

  XCTAssertTrue(OCMVerifyAll(self.mockRuleDatabase));
  XCTAssertEqual(written.type, SNTRuleTypeSigningID);
  XCTAssertEqualObjects(written.identifier, @"ABCDEFGHIJ:app");
}

- (void)testStandaloneRuleIsNotCreatedFromAnUnconfirmedHash {
  // A content hash names whatever was read. With no signing ID to fall back on
  // there is nothing safe to write, so no rule is created at all.
  OCMReject([self.mockRuleDatabase addExecutionRules:OCMOCK_ANY
                                         ruleCleanup:SNTRuleCleanupNone
                                              errors:[OCMArg anyObjectRef]]);

  [self.sut createRuleForStandaloneModeEvent:[self standaloneEventWithSigningID:nil]
                          identityMismatched:YES];
}

- (void)testStandaloneRuleIsCreatedFromAConfirmedHash {
  // Regression guard: the hash branch must still work normally.
  __block SNTRule* written = nil;
  OCMExpect([self.mockRuleDatabase
                addExecutionRules:[OCMArg checkWithBlock:^BOOL(NSArray<SNTRule*>* rules) {
                  written = rules.firstObject;
                  return YES;
                }]
                      ruleCleanup:SNTRuleCleanupNone
                           errors:[OCMArg anyObjectRef]])
      .andReturn(YES);

  [self.sut createRuleForStandaloneModeEvent:[self standaloneEventWithSigningID:nil]
                          identityMismatched:NO];

  XCTAssertTrue(OCMVerifyAll(self.mockRuleDatabase));
  XCTAssertEqual(written.type, SNTRuleTypeBinary);
  XCTAssertEqualObjects(written.identifier,
                        @"6896d9ea3f73a4434f5832bc65714e7d066f177373f36f34dc8a6f735daa41b1");
}

- (void)testUnconfirmedIdentityWithDifferentSigningIDsIsDenied {
  // Same vendor is not enough. Without this, any binary from a vendor could
  // stand in for any other binary from that vendor, which erases the
  // distinction SigningID, CDHash and Binary rules exist to express.
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));
  OCMStub([self.mockCodesignChecker signingID]).andReturn(@"some.other.product");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                        msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                      }];
}

- (void)testUnconfirmedIdentityWithSigningIDOnKernelSideOnlyIsDenied {
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker teamID]).andReturn(@(kExampleTeamID));

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->team_id = MakeESStringToken(kExampleTeamID);
                        msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                      }];
}

- (void)testUnconfirmedIdentityOnPlatformBinaryWithDifferentSigningIDsIsDenied {
  // The platform arm is reached by system code carrying no team identifier.
  // Cryptex-resident binaries are system protected but sit on a device other
  // than the boot volume group, so they are compared here rather than being
  // accepted without comparison.
  [self stubUnconfirmedIdentity];
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockCodesignChecker platformBinary]).andReturn(YES);
  OCMStub([self.mockCodesignChecker signingID]).andReturn(@"com.apple.something.else");

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateAllow;
  rule.type = SNTRuleTypeBinary;
  [self stubRule:rule forIdentifiers:{.binarySHA256 = @"a"}];

  [self postedDecisionForExecEvent:SNTActionRespondDenyOnce
                    cachedDecision:nil
                      messageSetup:^(es_message_t* msg) {
                        msg->event.exec.target->is_platform_binary = true;
                        msg->event.exec.target->signing_id = MakeESStringToken(kExampleSigningID);
                      }];
}

@end
