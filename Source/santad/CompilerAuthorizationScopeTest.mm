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
// the Endpoint Security response. Contextual decisions re-evaluate without a
// flush. Administrative updates exercise the daemon's cache invalidation.

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
#include "Source/common/SantaVnode.h"
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
#import "Source/santad/SNTDaemonControlController.h"
#import "Source/santad/SNTDatabaseController.h"
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

static NSString* const kCompilerSHA256 =
    @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static NSString* const kCompilerCDHash = @"0000000000000000000000000000000000000000";
static NSString* const kCompilerSigningID = @"ABCDEFGHIJ:com.example.compiler";
static NSString* const kOtherSHA256 =
    @"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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

@interface SNTRuleTable (Testing)
+ (NSArray<NSString*>*)criticalSystemBinaryPaths;
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
  int _staticValidationCount;
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
  OCMStub([self.mockFileInfo SHA256]).andReturn(kCompilerSHA256);
  __weak CompilerAuthorizationScopeTest* weakSelf = self;
  OCMStub([self.mockFileInfo codesignCheckerWithError:[OCMArg setTo:nil]])
      .andDo(^(NSInvocation* inv) {
        CompilerAuthorizationScopeTest* test = weakSelf;
        if (test) test->_staticValidationCount++;
      })
      .andReturn(self.mockCodesignChecker);

  self.mockRuleDatabase = OCMClassMock([SNTRuleTable class]);
  self.mockEventDatabase = OCMClassMock([SNTEventTable class]);

  SNTRule* rule = [[SNTRule alloc] init];
  rule.state = SNTRuleStateCELv2;
  rule.type = SNTRuleTypeBinary;
  rule.celExpr = kCompilerCELExpr;

  struct RuleIdentifiers anyIdentifiers = {};
  OCMStub([self.mockRuleDatabase executionRuleForIdentifiers:anyIdentifiers useCache:YES])
      .ignoringNonObjectArgs()
      .andReturn(rule);

  // Strict: any unexpected setProcess:isCompiler: fails the test. That is the
  // assertion that an invocation the rule does not authorize gains no compiler
  // authority.
  self.mockCompilerController = OCMStrictClassMock([SNTCompilerController class]);

  [self configureExecutionWithRuleTable:self.mockRuleDatabase];
}

- (void)configureExecutionWithRuleTable:(SNTRuleTable*)ruleTable {
  std::shared_ptr<santa::EntitlementsFilter> entitlementsFilter =
      santa::EntitlementsFilter::Create(@[], @[]);
  SNTPolicyProcessor* policyProcessor =
      [[SNTPolicyProcessor alloc] initWithRuleTable:ruleTable
                                 entitlementsFilter:entitlementsFilter];

  self.execController = [[SNTExecutionController alloc]
           initWithRuleTable:ruleTable
                  eventTable:self.mockEventDatabase
               notifierQueue:nil
                  syncdQueue:nil
                      logger:nullptr
                   ttyWriter:santa::TTYWriter::Create(true)
             policyProcessor:policyProcessor
         processControlBlock:santa::ProdSuspendResumeBlock()
                 processTree:nullptr
         sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
              timedRuleKills:nil
             believableClock:nil
      pendingExecCoordinator:nullptr];

  _mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  _mockESApi->SetExpectationsESNewClient();
  _mockESApi->SetExpectationsRetainReleaseMessage();

  // The real cache. This is the component under test alongside the controller.
  _authResultCache = AuthResultCache::Create(
      std::make_shared<santa::ESCacheFlusher>(santa::ESCacheClearStrategy::kEveryClient), nil);

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
// `dev`/`ino` select the vnode. The AuthResultCache is keyed by (vnode, cpu
// slice) and verifies content identity on every hit, so passing the same pair
// twice models re-executing the same binary only because this fixture leaves
// the cpu and identity fields zeroed -- exactly what the value-initialized
// `ExecTarget probe{}` below carries. Setting any of them on the message
// without also setting them on the probe would turn the probe into a miss.
- (es_auth_result_t)runExecWithArgs:(std::vector<std::string>)args
                                dev:(uint64_t)dev
                                ino:(uint64_t)ino {
  return [self runExecWithArgs:args dev:dev ino:ino pid:12];
}

- (es_auth_result_t)runExecWithArgs:(std::vector<std::string>)args
                                dev:(uint64_t)dev
                                ino:(uint64_t)ino
                                pid:(pid_t)pid {
  es_file_t file = MakeESFile("instigator");
  es_process_t proc = MakeESProcess(&file);
  es_file_t fileExec = MakeESFile("clang", {.st_dev = (dev_t)dev, .st_ino = ino});
  es_process_t procExec = MakeESProcess(&fileExec, MakeAuditToken(pid, 23), MakeAuditToken(34, 45));
  procExec.is_platform_binary = false;
  procExec.signing_id = MakeESStringToken("com.example.compiler");
  procExec.team_id = MakeESStringToken("ABCDEFGHIJ");
  procExec.codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL;
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

  // The non-cacheable entry must retain the completed validation. The mock
  // checker has no leaf certificate, so certSHA256 is nil — the shape that
  // previously forced a full re-validation on the next execution.
  santa::ExecTarget probe{};
  probe.key.vnode = SantaVnode{.fsid = 12, .fileid = 34};
  santa::CachedAuthResult cachedResult = _authResultCache->CheckCache(probe);
  XCTAssertEqual(cachedResult.action, SNTActionRespondAllowNoCache);
  XCTAssertNotNil(cachedResult.cached_decision);
  XCTAssertNil(cachedResult.cached_decision.certSHA256);
  XCTAssertEqualObjects(cachedResult.cached_decision.codesignValidationStatus, @(errSecSuccess),
                        @"non-cacheable CEL policy must retain completed signature validation");
  int validationsAfterFirstExec = _staticValidationCount;

  // Same vnode, context the rule blocks, no cache flush in between. The rule must
  // be evaluated again rather than the earlier allow being reused. The strict mock
  // enforces that no compiler status is conferred.
  XCTAssertEqual([self runExecWithArgs:kBlockedArgs dev:12 ino:34], ES_AUTH_RESULT_DENY,
                 @"a primed vnode must not settle a blocked context");
  XCTAssertEqual(_staticValidationCount, validationsAfterFirstExec,
                 @"a primed vnode must not repeat static signature validation");
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

// Rule matching, persistence, policy evaluation and invalidation are real. Only
// host identity/ES inputs and the compiler-mark sink use the fixture's mocks.
- (void)testAdministrativeRuleUpdatesReevaluateCompilerPermission {
  OCMStub([self.mockRuleDatabase criticalSystemBinaryPaths]).andReturn(@[]);
  SNTRuleTable* ruleTable =
      [[SNTRuleTable alloc] initWithDatabaseQueue:[[FMDatabaseQueue alloc] init]];
  [self configureExecutionWithRuleTable:ruleTable];

  id mockDatabaseController = OCMClassMock([SNTDatabaseController class]);
  OCMStub([mockDatabaseController ruleTable]).andReturn(ruleTable);
  [self addTeardownBlock:^{
    [mockDatabaseController stopMocking];
  }];

  auto cache = _authResultCache;
  SNTDaemonControlController* daemon = [[SNTDaemonControlController alloc]
      initWithNotificationQueue:nil
                     syncdQueue:nil
              netExtensionQueue:nil
                         logger:nullptr
                     watchItems:nullptr
            sandboxExpectations:std::make_shared<santa::SandboxExpectations>()
                flushCacheBlock:^(santa::FlushCacheMode mode, santa::FlushCacheReason reason) {
                  cache->FlushCache(mode, reason);
                }
                cacheCountBlock:nil
                checkCacheBlock:nil
             metricsExportBlock:nil
         binaryUploadController:nullptr];

  void (^addRules)(NSArray<SNTRule*>*, SNTRuleCleanup) =
      ^(NSArray<SNTRule*>* rules, SNTRuleCleanup cleanup) {
        __block BOOL replied = NO;
        [daemon databaseRuleAddExecutionRules:rules
                              fileAccessRules:@[]
                             networkFlowRules:@[]
                                      signals:@[]
                                  ruleCleanup:cleanup
                                       source:SNTRuleAddSourceSyncService
                                        reply:^(BOOL success, NSArray<NSError*>* errors) {
                                          XCTAssertTrue(success);
                                          XCTAssertEqual(errors.count, 0);
                                          replied = YES;
                                        }];
        XCTAssertTrue(replied);
      };

  NSMutableArray<NSNumber*>* compilerPids = [NSMutableArray array];
  OCMStub([self.mockCompilerController setProcess:MakeAuditToken(0, 0) isCompiler:true])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        const audit_token_t* token;
        bool isCompiler;
        [inv getArgument:&token atIndex:2];
        [inv getArgument:&isCompiler atIndex:3];
        XCTAssertTrue(isCompiler);
        [compilerPids addObject:@(audit_token_to_pid(*token))];
      });

  const struct {
    SNTRuleType compilerType;
    SNTRuleState compilerState;
    SNTRuleType newAllowType;
    bool remainsCompiler;
  } cases[] = {
      {SNTRuleTypeSigningID, SNTRuleStateAllowCompiler, SNTRuleTypeBinary, false},
      {SNTRuleTypeSigningID, SNTRuleStateAllowCompiler, SNTRuleTypeCDHash, false},
      {SNTRuleTypeBinary, SNTRuleStateAllowCompiler, SNTRuleTypeCDHash, false},
      {SNTRuleTypeBinary, SNTRuleStateAllowCompiler, SNTRuleTypeBinary, false},
      {SNTRuleTypeBinary, SNTRuleStateCEL, SNTRuleTypeBinary, false},
      {SNTRuleTypeBinary, SNTRuleStateCELv2, SNTRuleTypeBinary, false},
      {SNTRuleTypeSigningID, SNTRuleStateAllowCompiler, SNTRuleTypeBinary, true},
  };
  NSDictionary<NSNumber*, NSString*>* identifiers = @{
    @(SNTRuleTypeCDHash) : kCompilerCDHash,
    @(SNTRuleTypeBinary) : kCompilerSHA256,
    @(SNTRuleTypeSigningID) : kCompilerSigningID,
  };
  santa::ExecTarget probe{};
  probe.key.vnode = SantaVnode{.fsid = 12, .fileid = 34};

  pid_t pid = 100;
  for (const auto& testCase : cases) {
    [compilerPids removeAllObjects];
    NSString* expression =
        (testCase.compilerState == SNTRuleStateCEL || testCase.compilerState == SNTRuleStateCELv2)
            ? @"ALLOWLIST_COMPILER"
            : nil;
    SNTRule* compilerRule =
        [[SNTRule alloc] initWithIdentifier:identifiers[@(testCase.compilerType)]
                                      state:testCase.compilerState
                                       type:testCase.compilerType
                                  customMsg:nil
                                  customURL:nil
                      eventDetailButtonText:nil
                                    celExpr:expression
                             seatbeltPolicy:nil
                                     ruleId:0];
    XCTAssertNotNil(compilerRule);
    addRules(@[ compilerRule ], SNTRuleCleanupAll);

    pid_t warmPid = pid++;
    XCTAssertEqual([self runExecWithArgs:kAuthorizedArgs dev:12 ino:34 pid:warmPid],
                   ES_AUTH_RESULT_ALLOW);
    XCTAssertEqualObjects(compilerPids, (@[ @(warmPid) ]));
    XCTAssertEqual(cache->CheckCache(probe).action, SNTActionRespondAllowCompiler);

    SNTRule* allowRule = [[SNTRule alloc]
        initWithIdentifier:testCase.remainsCompiler ? kOtherSHA256
                                                    : identifiers[@(testCase.newAllowType)]
                     state:SNTRuleStateAllow
                      type:testCase.newAllowType];
    addRules(@[ allowRule ], SNTRuleCleanupNone);

    pid_t freshPid = pid++;
    int validationsBeforeExec = _staticValidationCount;
    XCTAssertEqual([self runExecWithArgs:kAuthorizedArgs dev:12 ino:34 pid:freshPid],
                   ES_AUTH_RESULT_ALLOW);
    NSArray<NSNumber*>* expectedCompilerPids =
        testCase.remainsCompiler ? @[ @(warmPid), @(freshPid) ] : @[ @(warmPid) ];
    XCTAssertEqualObjects(compilerPids, expectedCompilerPids);
    XCTAssertEqual(cache->CheckCache(probe).action, testCase.remainsCompiler
                                                        ? SNTActionRespondAllowCompiler
                                                        : SNTActionRespondAllow);
    XCTAssertGreaterThan(_staticValidationCount, validationsBeforeExec,
                         @"the administrative update must cause a fresh policy evaluation");
  }
}

@end
