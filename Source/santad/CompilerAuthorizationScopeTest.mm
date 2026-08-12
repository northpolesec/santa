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

// Coverage for the seam between SNTEndpointSecurityAuthorizer, the real
// AuthResultCache and the real SNTExecutionController.
//
// A CEL rule may grant compiler status only in a specific context, e.g. only
// when a particular argument is present. Such a decision is non-cacheable: it
// describes the invocation that was evaluated, not the executable. The compiler
// grant therefore scopes to the process that was just authorized, and a later
// execution of the same vnode must have the rule evaluated again on its own
// merits rather than inheriting the earlier answer from the cache.
//
// Every test here drives whole executions through the authorizer and asserts on
// the Endpoint Security response. No test flushes the cache: correct
// enforcement must not depend on a global flush or a daemon restart.

#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>

#include <memory>
#include <string>
#include <vector>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EntitlementsFilter.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#include "Source/santad/ProcessControl.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTExecutionController.h"
#import "Source/santad/SNTPolicyProcessor.h"
#include "Source/santad/SandboxExpectations.h"
#include "Source/santad/TTYWriter.h"

using santa::AuthResultCache;
using santa::Message;

// processMessage: is private to the implementation; exposed here so the test
// can drive a whole execution the way the ES client would.
@interface SNTEndpointSecurityAuthorizer (Testing)
- (void)processMessage:(Message)msg;
@end

// Only argv differs between the matching and the non-matching invocation.
static NSString* const kCompilerCELExpr =
    @"size(args) > 1 && args[1] == '--build' ? ALLOWLIST_COMPILER : BLOCKLIST";

// Named rather than written inline: a braced initializer list inside an
// XCTAssert macro has its comma parsed as a macro argument separator.
static const std::vector<std::string> kAuthorizedArgs = {"clang", "--build"};
static const std::vector<std::string> kBlockedArgs = {"clang", "--link"};

@interface SNTRule ()
@property(readwrite) SNTRuleState state;
@property(readwrite) SNTRuleType type;
@property(readwrite) NSString* celExpr;
@end

@interface CompilerAuthorizationScopeTest : XCTestCase
@property id mockConfigurator;
@property id mockCodesignChecker;
@property id mockDecisionCache;
@property id mockFileInfo;
@property id mockRuleDatabase;
@property id mockEventDatabase;
@property id mockCompilerController;
@property SNTExecutionController* execController;
@property SNTEndpointSecurityAuthorizer* authorizer;
@end

@implementation CompilerAuthorizationScopeTest {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<MockEndpointSecurityAPI> _mockESApi;
}

- (void)setUp {
  [super setUp];

  [[SNTMetricSet sharedInstance] reset];

  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockDecisionCache sharedCache]).andReturn(self.mockDecisionCache);
  OCMStub([self.mockDecisionCache cacheDecision:OCMOCK_ANY]).andReturn(YES);

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator enableTransitiveRules]).andReturn(YES);

  self.mockCodesignChecker = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.mockCodesignChecker alloc]).andReturn(self.mockCodesignChecker);
  OCMStub([self.mockCodesignChecker initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:NULL]])
      .andReturn(self.mockCodesignChecker);

  self.mockFileInfo = OCMClassMock([SNTFileInfo class]);
  OCMStub([self.mockFileInfo alloc]).andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo initWithEndpointSecurityFile:NULL error:[OCMArg setTo:nil]])
      .ignoringNonObjectArgs()
      .andReturn(self.mockFileInfo);
  OCMStub([self.mockFileInfo isMachO]).andReturn(YES);
  OCMStub([self.mockFileInfo SHA256]).andReturn(@"a");
  OCMStub([self.mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]])
      .andReturn(self.mockCodesignChecker);

  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeBinary;
  rule.celExpr = kCompilerCELExpr;

  struct RuleIdentifiers anyIdentifiers = {};
  OCMStub([self.mockRuleDatabase executionRuleForIdentifiers:anyIdentifiers])
      .ignoringNonObjectArgs()
      .andReturn(rule);

  // Strict: any unexpected setProcess:isCompiler: fails the test. That is the
  // assertion that an invocation the rule does not authorize gains no compiler
  // authority.
  self.mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);

  std::shared_ptr<santa::EntitlementsFilter> entitlementsFilter =
      santa::EntitlementsFilter::Create(@[], @[]);
  SNTPolicyProcessor* policyProcessor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:self.mockRuleDatabase
                                 entitlementsFilter:entitlementsFilter];

  self.execController = [[SNTExecutionController alloc]
        initWithRuleTable:self.mockRuleDatabase
               eventTable:self.mockEventDatabase
            notifierQueue:nil
               syncdQueue:nil
                   logger:nullptr
                ttyWriter:santa::TTYWriter::Create(true)
          policyProcessor:policyProcessor
      processControlBlock:santa::ProdSuspendResumeBlock()
              processTree:nullptr
      sandboxExpectations:std::make_shared<santa::SandboxExpectations>()];

  _mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  _mockESApi->SetExpectationsESNewClient();
  _mockESApi->SetExpectationsRetainReleaseMessage();

  // The real cache. This is the component under test alongside the controller.
  _authResultCache = AuthResultCache::Create(_mockESApi, nil);

  self.authorizer =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:_mockESApi
                                                   metrics:nullptr
                                            execController:self.execController
                                        compilerController:self.mockCompilerController
                                           authResultCache:_authResultCache
                                                 ttyWriter:santa::TTYWriter::Create(true)
                                               processTree:nullptr];
}

- (void)tearDown {
  self.authorizer = nil;
  self.execController = nil;
  [self.mockCompilerController stopMocking];
  [super tearDown];
}

// Drives one complete execution through the authorizer and returns the
// Endpoint Security auth result Santa responded with.
//
// `dev`/`ino` select the vnode, which is the AuthResultCache key, so passing
// the same pair twice models re-executing the same binary.
- (es_auth_result_t)runExecWithArgs:(std::vector<std::string>)args
                                dev:(uint64_t)dev
                                ino:(uint64_t)ino {
  es_file_t file = MakeESFile("instigator");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("clang", {.st_dev = (dev_t)dev, .st_ino = ino});
  es_process_t procExec = MakeESProcess(&fileExec, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  procExec.is_platform_binary = false;
  procExec.codesigning_flags = CS_SIGNED | CS_VALID;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc, ActionType::Auth);
  esMsg.event.exec.target = &procExec;

  EXPECT_CALL(*_mockESApi, ExecArgs).WillRepeatedly(testing::Return(args));

  __block es_auth_result_t gotResult = ES_AUTH_RESULT_DENY;
  id mockAuthorizer = OCMPartialMock(self.authorizer);
  OCMStub([mockAuthorizer respondToMessage:Message(_mockESApi, &esMsg)
                            withAuthResult:(es_auth_result_t)0
                                 cacheable:false])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&gotResult atIndex:3];
      });

  {
    Message msg(_mockESApi, &esMsg);
    [mockAuthorizer processMessage:msg];
  }

  [mockAuthorizer stopMocking];
  return gotResult;
}

// The central property, end to end. Authorizing one invocation must not settle
// the answer for a later one.
- (void)testPrimedVnodeStillReEvaluatesBlockedContext {
  // The rule permits this invocation and grants compiler status.
  OCMExpect([self.mockCompilerController setProcess:MakeAuditToken(12, 23) isCompiler:true])
      .ignoringNonObjectArgs();

  XCTAssertEqual([self runExecWithArgs:kAuthorizedArgs dev:12 ino:34], ES_AUTH_RESULT_ALLOW,
                 @"the authorized context must be allowed");
  XCTAssertTrue(OCMVerifyAll(self.mockCompilerController));

  es_file_t cachedFile = MakeESFile("clang", {.st_dev = 12, .st_ino = 34});
  santa::CachedAuthResult cachedResult = _authResultCache->CheckCache(&cachedFile);
  XCTAssertEqual(cachedResult.action, SNTActionRespondAllowNoCache);
  XCTAssertNotNil(cachedResult.cached_decision);
  XCTAssertEqual(cachedResult.cached_decision.codesignValidationState,
                 SNTCodesignValidationStateSuccess,
                 @"non-cacheable CEL policy must retain completed signature validation");

  // Same vnode, context the rule blocks, no cache flush in between. The rule must
  // be evaluated again rather than the earlier allow being reused. The strict mock
  // enforces that no compiler status is conferred.
  XCTAssertEqual([self runExecWithArgs:kBlockedArgs dev:12 ino:34], ES_AUTH_RESULT_DENY,
                 @"a primed vnode must not settle a blocked context");
}

// Priming one vnode must not change the answer for a different one.
- (void)testFreshVnodeControlIsUnaffectedByPriming {
  OCMExpect([self.mockCompilerController setProcess:MakeAuditToken(12, 23) isCompiler:true])
      .ignoringNonObjectArgs();

  XCTAssertEqual([self runExecWithArgs:kAuthorizedArgs dev:12 ino:34], ES_AUTH_RESULT_ALLOW);
  XCTAssertTrue(OCMVerifyAll(self.mockCompilerController));

  XCTAssertEqual([self runExecWithArgs:kBlockedArgs dev:12 ino:99], ES_AUTH_RESULT_DENY,
                 @"a never-primed vnode must be evaluated on its own merits");
}

// The authorized context must keep working on repeat, not just once.
- (void)testAuthorizedContextRemainsAllowedOnRepeat {
  OCMExpect([self.mockCompilerController setProcess:MakeAuditToken(12, 23) isCompiler:true])
      .ignoringNonObjectArgs();
  OCMExpect([self.mockCompilerController setProcess:MakeAuditToken(12, 23) isCompiler:true])
      .ignoringNonObjectArgs();

  XCTAssertEqual([self runExecWithArgs:kAuthorizedArgs dev:12 ino:34], ES_AUTH_RESULT_ALLOW);
  XCTAssertEqual([self runExecWithArgs:kAuthorizedArgs dev:12 ino:34], ES_AUTH_RESULT_ALLOW);

  XCTAssertTrue(OCMVerifyAll(self.mockCompilerController));
}

@end
