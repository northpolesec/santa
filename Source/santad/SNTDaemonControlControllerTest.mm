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

#import "Source/common/SNTConfigurator.h"
#import "Source/santad/SNTDaemonControlController.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>

#include <memory>
#include <utility>
#include <vector>

#import "Source/common/AuditUtilities.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigBundle.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTNetworkFlowRule.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSandboxExecRequest.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/Logs/EndpointSecurity/MockLogger.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "Source/santad/SandboxExpectations.h"

using santa::SandboxExpectations;

// A valid 64-char lowercase hex string; SNTRule's initializer enforces this
// shape for binary-type identifiers.
static NSString* const kBinarySHA256 =
    @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static NSString* const kTeamID = @"ABCDEFGHIJ";
static NSString* const kSigningID = @"ABCDEFGHIJ:com.example.tool";
static NSString* const kCDHash = @"0102030405060708090a0b0c0d0e0f1011121314";

// Expose rule fields so tests can exercise invalid policies and expressions.
@interface SNTRule ()
@property(readwrite) NSString* seatbeltPolicy;
@property(readwrite) NSString* celExpr;
@end

// Expose the bundle's private backing properties so tests can build a bundle
// carrying exactly the fields under test.
@interface SNTConfigBundle (Testing)
@property NSNumber* clientMode;
@property NSNumber* executableIntegrityPolicy;
@property NSNumber* disableExecutableIntegrityRecheck;
@property NSString* bannedBlockMessage;
@property NSString* unknownBlockMessage;
@property NSString* bannedUSBBlockMessage;
@property NSString* remountUSBBlockMessage;
@end

@interface SNTDaemonControlController (Testing)
- (BOOL)shouldRejectManualRuleChangeAddingRules:(BOOL)addingRules;
@property(readonly) dispatch_queue_t binaryUploadQ;
@property(readonly) dispatch_queue_t packageInventoryQ;
@property(copy) void (^flushCacheBlock)(santa::FlushCacheMode, santa::FlushCacheReason);
@end

@interface SNTDaemonControlControllerTest : XCTestCase
@property id mockDatabaseController;
@property id mockRuleTable;
@property id mockMOLXPC;
@property id mockRuleConfigurator;
@property SNTDaemonControlController* sut;
@end

@implementation SNTDaemonControlControllerTest {
  std::shared_ptr<SandboxExpectations> _sandboxExpectations;
}

- (void)setUp {
  [super setUp];
  _sandboxExpectations = std::make_shared<SandboxExpectations>();

  self.mockDatabaseController = OCMClassMock([SNTDatabaseController class]);
  self.mockRuleTable = OCMClassMock([SNTRuleTable class]);
  OCMStub([self.mockDatabaseController ruleTable]).andReturn(self.mockRuleTable);

  // Class-mocked so positive-path tests can stub `currentPeerAuditToken` to
  // return a non-zero token. Unstubbed calls fall through to the real
  // implementation, which returns a zeroed audit token when no XPC
  // connection is currently dispatching (the default in unit tests).
  self.mockMOLXPC = OCMClassMock([MOLXPCConnection class]);

  self.sut = [self controllerWithLogger:nullptr];
}

- (SNTDaemonControlController*)controllerWithLogger:(std::shared_ptr<santa::Logger>)logger {
  return [[SNTDaemonControlController alloc] initWithNotificationQueue:nil
      syncdQueue:nil
      netExtensionQueue:nil
      logger:logger
      watchItems:nullptr
      sandboxExpectations:_sandboxExpectations
      flushCacheBlock:^(santa::FlushCacheMode, santa::FlushCacheReason) {
      }
      cacheCountBlock:^NSArray<NSNumber*>*() {
        return @[];
      }
      checkCacheBlock:^SNTAction(SantaVnode) {
        return SNTActionRespondAllow;
      }
      metricsExportBlock:^(void (^)(BOOL)) {
      }
      binaryUploadController:nullptr];
}

- (void)testSyncBundleEventStoresTheBundleHashedEvent {
  // A real logger, because syncBundleEvent: logs the related events.
  SNTDaemonControlController* sut = [self controllerWithLogger:std::make_shared<MockLogger>()];
  SNTEventTable* mockEventTable = OCMClassMock([SNTEventTable class]);
  OCMStub([self.mockDatabaseController eventTable]).andReturn(mockEventTable);

  SNTStoredExecutionEvent* event = [[SNTStoredExecutionEvent alloc] init];
  event.fileSHA256 = @"abc123";
  event.fileBundleHash = @"bundlehash";
  OCMExpect([mockEventTable storeBundleHashedEvent:event]);

  [sut syncBundleEvent:event relatedEvents:@[]];

  OCMVerifyAll((id)mockEventTable);
}

- (void)tearDown {
  self.sut = nil;
  [self.mockDatabaseController stopMocking];
  [self.mockRuleTable stopMocking];
  [self.mockMOLXPC stopMocking];
  [self.mockRuleConfigurator stopMocking];
  [super tearDown];
}

- (SNTRuleTable*)useInMemoryRuleTable {
  // Keep database initialization independent of the host's managed configuration.
  self.mockRuleConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockRuleConfigurator configurator]).andReturn(self.mockRuleConfigurator);
  [self.mockRuleTable stopMocking];
  self.mockRuleTable = nil;
  SNTRuleTable* ruleTable =
      [[SNTRuleTable alloc] initWithDatabaseQueue:[[FMDatabaseQueue alloc] init]];
  [self.mockDatabaseController stopMocking];
  self.mockDatabaseController = OCMClassMock([SNTDatabaseController class]);
  OCMStub([self.mockDatabaseController ruleTable]).andReturn(ruleTable);
  return ruleTable;
}

// Build a request with valid shape: identifiers set.
- (SNTSandboxExecRequest*)makeRequest {
  SNTRuleIdentifiers* ids = [[SNTRuleIdentifiers alloc]
      initWithRuleIdentifiers:{.cdhash = @"0102030405060708090a0b0c0d0e0f1011121314",
                               .binarySHA256 = kBinarySHA256}];
  return [[SNTSandboxExecRequest alloc] initWithIdentifiers:ids
                                                      fsDev:17
                                                      fsIno:42
                                               resolvedPath:@"/usr/local/bin/foo"];
}

- (SNTRule*)makeSeatbeltRuleWithPolicy:(NSString*)policy {
  // SNTRule's initializer rejects empty seatbelt policies, so construct
  // with a valid placeholder and overwrite via the readwrite category above
  // when the caller wants the empty-policy case.
  SNTRule* r = [[SNTRule alloc] initWithIdentifier:kBinarySHA256
                                             state:SNTRuleStateSeatbelt
                                              type:SNTRuleTypeBinary
                                         customMsg:nil
                                         customURL:nil
                             eventDetailButtonText:nil
                                         timestamp:0
                                           comment:nil
                                           celExpr:nil
                                    seatbeltPolicy:@"(version 1)"
                                            ruleId:0
                                             error:nil];
  r.seatbeltPolicy = policy;
  return r;
}

- (void)stubRuleLookupReturns:(SNTRule*)rule {
  OCMStub([self.mockRuleTable executionRuleForIdentifiers:(struct RuleIdentifiers){}])
      .ignoringNonObjectArgs()
      .andReturn(rule);
}

- (void)stubPeerAuditTokenPid:(pid_t)pid pidver:(int)pidver {
  audit_token_t tok = santa::MakeStubAuditToken(pid, pidver);
  OCMStub([self.mockMOLXPC currentPeerAuditToken]).andReturn(tok);
}

- (void)testPackageInventoryUsesDedicatedQueue {
  XCTAssertNotNil(self.sut.binaryUploadQ);
  XCTAssertNotNil(self.sut.packageInventoryQ);
  XCTAssertNotEqual(self.sut.binaryUploadQ, self.sut.packageInventoryQ);
}

// ---- Shape validation ------------------------------------------------

- (void)testRejectsNilRequest {
  __block NSString* gotProfile = @"unset";
  __block NSError* gotErr = nil;
  [self.sut prepareSandboxExec:nil
                         reply:^(NSString* p, NSError* e) {
                           gotProfile = p;
                           gotErr = e;
                         }];
  XCTAssertNil(gotProfile);
  XCTAssertEqualObjects(gotErr.domain, SantaErrorDomain);
  XCTAssertEqual(gotErr.code, SNTErrorCodeSandboxInvalidRequest);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 0u);
}

- (void)testRegistersUnsignedBinaryWithoutCdhash {
  // Unsigned binaries have no cdhash; registration should still succeed.
  // AUTH_EXEC enforcement falls back to (dev, ino, sha256) for these.
  [self stubRuleLookupReturns:[self makeSeatbeltRuleWithPolicy:@"(version 1)"]];
  [self stubPeerAuditTokenPid:5555 pidver:1];

  SNTRuleIdentifiers* ids =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{.binarySHA256 = kBinarySHA256}];
  SNTSandboxExecRequest* r = [[SNTSandboxExecRequest alloc] initWithIdentifiers:ids
                                                                          fsDev:17
                                                                          fsIno:42
                                                                   resolvedPath:nil];

  __block NSError* gotErr = nil;
  __block NSString* gotProfile = nil;
  [self.sut prepareSandboxExec:r
                         reply:^(NSString* p, NSError* e) {
                           gotProfile = p;
                           gotErr = e;
                         }];
  XCTAssertNil(gotErr);
  XCTAssertNotNil(gotProfile);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 1u);
}

// ---- Rule-lookup outcomes --------------------------------------------

- (void)testReturnsErrorWhenNoMatchingRule {
  [self stubRuleLookupReturns:nil];

  __block NSString* gotProfile = @"unset";
  __block NSError* gotErr = nil;
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString* p, NSError* e) {
                           gotProfile = p;
                           gotErr = e;
                         }];
  XCTAssertNil(gotProfile);
  XCTAssertEqual(gotErr.code, SNTErrorCodeSandboxRuleNotFound);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 0u);
}

- (void)testReturnsErrorWhenMatchingRuleIsNotSeatbelt {
  [self stubRuleLookupReturns:[[SNTRule alloc] initWithIdentifier:kBinarySHA256
                                                            state:SNTRuleStateBlock
                                                             type:SNTRuleTypeBinary]];

  __block NSError* gotErr = nil;
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString*, NSError* e) {
                           gotErr = e;
                         }];
  XCTAssertEqual(gotErr.code, SNTErrorCodeSandboxRuleNotSeatbelt);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 0u);
}

- (void)testReturnsErrorWhenSeatbeltPolicyIsEmpty {
  [self stubRuleLookupReturns:[self makeSeatbeltRuleWithPolicy:@""]];

  __block NSError* gotErr = nil;
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString*, NSError* e) {
                           gotErr = e;
                         }];
  XCTAssertEqual(gotErr.code, SNTErrorCodeSandboxRuleNotSeatbelt);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 0u);
}

// ---- Peer audit token -------------------------------------------------

- (void)testReturnsErrorWhenPeerAuditTokenPidIsZero {
  [self stubRuleLookupReturns:[self makeSeatbeltRuleWithPolicy:@"(version 1)"]];
  // Do not stub currentPeerAuditToken — the real implementation returns
  // a zero token when no XPC message is currently dispatching.

  __block NSError* gotErr = nil;
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString*, NSError* e) {
                           gotErr = e;
                         }];
  XCTAssertEqual(gotErr.code, SNTErrorCodeSandboxInternal);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 0u);
}

// ---- Success and dedupe ----------------------------------------------

- (void)testRegistersAndReturnsPolicyOnSuccess {
  NSString* policyStr = @"(version 1) (deny default)";
  [self stubRuleLookupReturns:[self makeSeatbeltRuleWithPolicy:policyStr]];
  [self stubPeerAuditTokenPid:9876 pidver:3];

  __block NSString* gotProfile = nil;
  __block NSError* gotErr = nil;
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString* p, NSError* e) {
                           gotProfile = p;
                           gotErr = e;
                         }];
  XCTAssertNil(gotErr);
  XCTAssertEqualObjects(gotProfile, policyStr);
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 1u);

  // Consume and confirm the expectation was populated from the request.
  auto consumed = _sandboxExpectations->Consume(santa::MakeStubAuditToken(9876, 3));
  XCTAssertTrue(consumed.has_value());
  XCTAssertEqual(consumed->dev, 17u);
  XCTAssertEqual(consumed->ino, 42u);
  XCTAssertTrue(consumed->sha256 == kBinarySHA256.UTF8String);
}

- (void)testRejectsDuplicateRegistration {
  [self stubRuleLookupReturns:[self makeSeatbeltRuleWithPolicy:@"(version 1)"]];
  [self stubPeerAuditTokenPid:4242 pidver:1];

  __block NSError* firstErr = nil;
  __block NSString* firstProfile = nil;
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString* p, NSError* e) {
                           firstProfile = p;
                           firstErr = e;
                         }];
  XCTAssertNil(firstErr);
  XCTAssertNotNil(firstProfile);

  __block NSError* secondErr = nil;
  __block NSString* secondProfile = @"unset";
  [self.sut prepareSandboxExec:[self makeRequest]
                         reply:^(NSString* p, NSError* e) {
                           secondProfile = p;
                           secondErr = e;
                         }];
  XCTAssertNil(secondProfile);
  XCTAssertEqual(secondErr.code, SNTErrorCodeSandboxAlreadyPending);

  // Original entry survives the duplicate rejection.
  XCTAssertEqual(_sandboxExpectations->CountForTesting(), 1u);
}

// ---- Rule add: network flow rules pass-through -----------------------

- (void)testRuleAddForwardsNetworkFlowRules {
  NSData* blob = [@"blob" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkFlowRule* nfRule = [[SNTNetworkFlowRule alloc] initAddRuleWithName:@"rule-101"
                                                                        ruleId:101
                                                                     protoBlob:blob];

  __block NSArray<SNTNetworkFlowRule*>* forwarded = nil;
  OCMStub([self.mockRuleTable addExecutionRules:OCMOCK_ANY
                                fileAccessRules:OCMOCK_ANY
                               networkFlowRules:OCMOCK_ANY
                                        signals:OCMOCK_ANY
                                    ruleCleanup:SNTRuleCleanupNone
                                         errors:[OCMArg anyObjectRef]])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSArray<SNTNetworkFlowRule*>* captured = nil;
        [inv getArgument:&captured atIndex:4];  // NSInvocation index for the networkFlowRules arg
        forwarded = captured;
      })
      .andReturn(YES);

  __block BOOL replySuccess = NO;
  [self.sut databaseRuleAddExecutionRules:@[]
                          fileAccessRules:@[]
                         networkFlowRules:@[ nfRule ]
                                  signals:@[]
                              ruleCleanup:SNTRuleCleanupNone
                                   source:SNTRuleAddSourceSyncService
                                    reply:^(BOOL success, NSArray<NSError*>* errors) {
                                      replySuccess = success;
                                    }];

  XCTAssertTrue(replySuccess);
  XCTAssertEqual(forwarded.count, 1u);
  XCTAssertEqualObjects(forwarded.firstObject.ruleName, @"rule-101");
  XCTAssertEqual(forwarded.firstObject.ruleId, 101);
}

- (void)testExecutionRuleUpdatesInvalidateAfterCommitBeforeReply {
  using santa::FlushCacheMode;
  using santa::FlushCacheReason;
  SNTRuleTable* ruleTable = [self useInMemoryRuleTable];
  auto makeRule = [](SNTRuleType type, SNTRuleState state) {
    NSString* identifier = type == SNTRuleTypeBinary   ? kBinarySHA256
                           : type == SNTRuleTypeCDHash ? kCDHash
                                                       : kSigningID;
    return
        [[SNTRule alloc] initWithIdentifier:identifier
                                      state:state
                                       type:type
                                  customMsg:nil
                                  customURL:nil
                      eventDetailButtonText:nil
                                  timestamp:0
                                    comment:nil
                                    celExpr:(state == SNTRuleStateCEL || state == SNTRuleStateCELv2)
                                                ? @"ALLOWLIST_COMPILER"
                                                : nil
                             seatbeltPolicy:nil
                                     ruleId:0
                                      error:nil];
  };
  const struct {
    SNTRuleType oldType;
    SNTRuleState oldState;
    SNTRuleType newType;
    SNTRuleState newState;
    FlushCacheMode mode;
  } cases[] = {
      {SNTRuleTypeSigningID, SNTRuleStateAllowCompiler, SNTRuleTypeBinary, SNTRuleStateAllow,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeSigningID, SNTRuleStateAllowCompiler, SNTRuleTypeCDHash, SNTRuleStateAllow,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeBinary, SNTRuleStateAllowCompiler, SNTRuleTypeCDHash, SNTRuleStateAllow,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeBinary, SNTRuleStateAllowCompiler, SNTRuleTypeBinary, SNTRuleStateAllow,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeBinary, SNTRuleStateCEL, SNTRuleTypeBinary, SNTRuleStateAllow,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeSigningID, SNTRuleStateCELv2, SNTRuleTypeSigningID, SNTRuleStateAllow,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeBinary, SNTRuleStateBlock, SNTRuleTypeBinary, SNTRuleStateBlock,
       FlushCacheMode::kCompilerDecisionsOnly},
      {SNTRuleTypeBinary, SNTRuleStateAllow, SNTRuleTypeBinary, SNTRuleStateBlock,
       FlushCacheMode::kAllCaches},
      {SNTRuleTypeBinary, SNTRuleStateAllowCompiler, SNTRuleTypeBinary, SNTRuleStateRemove,
       FlushCacheMode::kAllCaches},
  };
  for (const auto& testCase : cases) {
    NSArray<NSError*>* errors;
    XCTAssertTrue([ruleTable addExecutionRules:@[ makeRule(testCase.oldType, testCase.oldState) ]
                                   ruleCleanup:SNTRuleCleanupAll
                                        errors:&errors]);
    XCTAssertNil(errors);
    SNTRule* newRule = makeRule(testCase.newType, testCase.newState);
    __block NSUInteger flushCount = 0;
    __block BOOL replied = NO;
    self.sut.flushCacheBlock = ^(FlushCacheMode mode, FlushCacheReason reason) {
      ++flushCount;
      XCTAssertFalse(replied);
      XCTAssertEqual(mode, testCase.mode);
      XCTAssertEqual(reason, FlushCacheReason::kRulesChanged);
      SNTRule* stored = [ruleTable executionRuleForIdentifiers:{.cdhash = kCDHash,
                                                                .binarySHA256 = kBinarySHA256,
                                                                .signingID = kSigningID}];
      if (testCase.newState == SNTRuleStateRemove) {
        XCTAssertNil(stored);
      } else {
        XCTAssertEqual(stored.type, newRule.type);
        XCTAssertEqual(stored.state, newRule.state);
        XCTAssertEqualObjects(stored.identifier, newRule.identifier);
      }
    };
    [self.sut databaseRuleAddExecutionRules:@[ newRule ]
                            fileAccessRules:@[]
                           networkFlowRules:@[]
                                    signals:@[]
                                ruleCleanup:SNTRuleCleanupNone
                                     source:SNTRuleAddSourceSyncService
                                      reply:^(BOOL success, NSArray<NSError*>* writeErrors) {
                                        XCTAssertTrue(success);
                                        XCTAssertNil(writeErrors);
                                        XCTAssertEqual(flushCount, 1u);
                                        replied = YES;
                                      }];
    XCTAssertTrue(replied);
    XCTAssertEqual(flushCount, 1u);
  }
}

- (void)testRuleUpdatesWithoutExecutionRulesKeepExistingFlushTriggers {
  [self useInMemoryRuleTable];
  const struct {
    NSArray<SNTFileAccessRule*>* fileAccessRules;
    NSArray<SNTNetworkFlowRule*>* networkRules;
    NSArray<SNTSignal*>* signals;
    SNTRuleCleanup cleanup;
    BOOL flush;
    BOOL success;
  } cases[] = {
      {@[], @[], @[], SNTRuleCleanupNone, NO, NO},
      {@[ [[SNTFileAccessRule alloc] initRemoveRuleWithName:@"unused"] ], @[], @[],
       SNTRuleCleanupNone, YES, YES},
      {@[], @[ [[SNTNetworkFlowRule alloc] initRemoveRuleWithName:@"unused"] ], @[],
       SNTRuleCleanupNone, NO, YES},
      {@[], @[], @[ [[SNTSignal alloc] initRemoveRuleWithName:@"unused"] ], SNTRuleCleanupNone, NO,
       YES},
      {@[], @[], @[], SNTRuleCleanupAll, YES, YES},
  };
  for (const auto& testCase : cases) {
    __block NSUInteger flushCount = 0;
    self.sut.flushCacheBlock = ^(santa::FlushCacheMode mode, santa::FlushCacheReason reason) {
      ++flushCount;
      XCTAssertEqual(mode, santa::FlushCacheMode::kAllCaches);
      XCTAssertEqual(reason, santa::FlushCacheReason::kRulesChanged);
    };
    __block BOOL replied = NO;
    [self.sut databaseRuleAddExecutionRules:@[]
                            fileAccessRules:testCase.fileAccessRules
                           networkFlowRules:testCase.networkRules
                                    signals:testCase.signals
                                ruleCleanup:testCase.cleanup
                                     source:SNTRuleAddSourceSyncService
                                      reply:^(BOOL success, NSArray<NSError*>* errors) {
                                        XCTAssertEqual(success, testCase.success);
                                        if (success) {
                                          XCTAssertNil(errors);
                                        } else {
                                          XCTAssertEqual(errors.count, 1u);
                                          XCTAssertEqual(errors.firstObject.code,
                                                         SNTErrorCodeEmptyRuleArray);
                                        }
                                        XCTAssertEqual(flushCount, testCase.flush ? 1u : 0u);
                                        replied = YES;
                                      }];
    XCTAssertTrue(replied);
  }
}

- (void)testFailedAndPartiallyAcceptedUpdatesStillInvalidate {
  using santa::FlushCacheMode;
  SNTRuleTable* ruleTable = [self useInMemoryRuleTable];
  SNTRule* oldRule = [self binaryRuleWithState:SNTRuleStateAllowCompiler seatbeltPolicy:nil];
  SNTRule* allowRule = [self binaryRuleWithState:SNTRuleStateAllow seatbeltPolicy:nil];
  SNTRule* blockRule = [self binaryRuleWithState:SNTRuleStateBlock seatbeltPolicy:nil];
  SNTRule* invalidCEL = [self binaryRuleWithState:SNTRuleStateCEL seatbeltPolicy:nil];
  invalidCEL.celExpr = @"(";
  SNTNetworkFlowRule* invalidNetwork =
      [[SNTNetworkFlowRule alloc] initAddRuleWithName:@"invalid" ruleId:1 protoBlob:[NSData data]];
  const struct {
    NSArray<SNTRule*>* executionRules;
    NSArray<SNTNetworkFlowRule*>* networkRules;
    BOOL success;
    SNTErrorCode error;
    SNTRuleState storedState;
    FlushCacheMode mode;
  } cases[] = {
      {@[ allowRule ], @[ invalidNetwork ], NO, SNTErrorCodeRuleInvalid, SNTRuleStateAllowCompiler,
       FlushCacheMode::kCompilerDecisionsOnly},
      {@[ blockRule ], @[ invalidNetwork ], NO, SNTErrorCodeRuleInvalid, SNTRuleStateAllowCompiler,
       FlushCacheMode::kAllCaches},
      {@[ allowRule, invalidCEL ], @[], YES, SNTErrorCodeRuleInvalidCELExpression,
       SNTRuleStateAllow, FlushCacheMode::kAllCaches},
  };
  for (const auto& testCase : cases) {
    NSArray<NSError*>* errors;
    XCTAssertTrue([ruleTable addExecutionRules:@[ oldRule ]
                                   ruleCleanup:SNTRuleCleanupAll
                                        errors:&errors]);
    XCTAssertNil(errors);
    __block NSUInteger flushCount = 0;
    self.sut.flushCacheBlock = ^(FlushCacheMode mode, santa::FlushCacheReason reason) {
      ++flushCount;
      XCTAssertEqual(mode, testCase.mode);
      XCTAssertEqual(reason, santa::FlushCacheReason::kRulesChanged);
      SNTRule* stored = [ruleTable executionRuleForIdentifiers:{.binarySHA256 = kBinarySHA256}];
      XCTAssertEqual(stored.state, testCase.storedState);
    };
    __block BOOL replied = NO;
    [self.sut
        databaseRuleAddExecutionRules:testCase.executionRules
                      fileAccessRules:@[]
                     networkFlowRules:testCase.networkRules
                              signals:@[]
                          ruleCleanup:SNTRuleCleanupNone
                               source:SNTRuleAddSourceSyncService
                                reply:^(BOOL success, NSArray<NSError*>* writeErrors) {
                                  XCTAssertEqual(success, testCase.success);
                                  XCTAssertEqual(writeErrors.count, 1u);
                                  XCTAssertEqual(writeErrors.firstObject.code, testCase.error);
                                  XCTAssertEqual(flushCount, 1u);
                                  replied = YES;
                                }];
    XCTAssertTrue(replied);
  }
}

// ---- databaseRulesHash: returns four hashes --------------------------

- (void)testDatabaseRulesHashReturnsFourHashes {
  id mockHash = OCMClassMock([SNTRuleTableRulesHash class]);
  OCMStub([mockHash executionRulesHash]).andReturn(@"exec-hash");
  OCMStub([mockHash fileAccessRulesHash]).andReturn(@"faa-hash");
  OCMStub([mockHash networkFlowRulesHash]).andReturn(@"nf-hash");
  OCMStub([mockHash signalRulesHash]).andReturn(@"signal-hash");
  OCMStub([self.mockRuleTable hashOfHashes]).andReturn(mockHash);

  __block NSString* gotExec = nil;
  __block NSString* gotFAA = nil;
  __block NSString* gotNF = nil;
  __block NSString* gotSignal = nil;
  [self.sut databaseRulesHash:^(NSString* exec, NSString* faa, NSString* nf, NSString* signal) {
    gotExec = exec;
    gotFAA = faa;
    gotNF = nf;
    gotSignal = signal;
  }];

  XCTAssertEqualObjects(gotExec, @"exec-hash");
  XCTAssertEqualObjects(gotFAA, @"faa-hash");
  XCTAssertEqualObjects(gotNF, @"nf-hash");
  XCTAssertEqualObjects(gotSignal, @"signal-hash");
  [mockHash stopMocking];
}

// ---- databaseRuleCounts: includes networkFlow ------------------------

- (void)testDatabaseRuleCountsIncludesNetworkFlow {
  OCMStub([self.mockRuleTable networkFlowRuleCount]).andReturn(7);
  OCMStub([self.mockRuleTable cachedStaticRules]).andReturn(@{});

  __block struct RuleCounts got = {};
  [self.sut databaseRuleCounts:^(struct RuleCounts counts) {
    got = counts;
  }];

  XCTAssertEqual(got.networkFlow, 7);
}

// ---- staticDecisionForFilePath (santactl fileinfo) -------------------

- (id)mockConfiguratorForStaticDecisionWithTransitiveRules:(BOOL)enableTransitiveRules {
  id cfg = OCMClassMock([SNTConfigurator class]);
  OCMStub([cfg configurator]).andReturn(cfg);
  OCMStub([cfg enableTransitiveRules]).andReturn(enableTransitiveRules);
  OCMStub([(SNTConfigurator*)cfg clientMode]).andReturn(SNTClientModeLockdown);
  return cfg;
}

- (SNTRule*)binaryRuleWithState:(SNTRuleState)state seatbeltPolicy:(NSString*)seatbeltPolicy {
  BOOL isCEL = state == SNTRuleStateCEL || state == SNTRuleStateCELv2;
  return [[SNTRule alloc] initWithIdentifier:kBinarySHA256
                                       state:state
                                        type:SNTRuleTypeBinary
                                   customMsg:nil
                                   customURL:nil
                       eventDetailButtonText:nil
                                   timestamp:0
                                     comment:nil
                                     celExpr:isCEL ? @"true" : nil
                              seatbeltPolicy:seatbeltPolicy
                                      ruleId:0
                                       error:nil];
}

- (NSString*)staticDecision {
  __block NSString* got;
  SNTRuleIdentifiers* ids =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{.binarySHA256 = kBinarySHA256}];
  [self.sut staticDecisionForFilePath:@"/nonexistent/santa-test-binary"
                          identifiers:ids
                                reply:^(SNTRule*, NSString* decision) {
                                  got = decision;
                                }];
  return got;
}

- (void)testStaticDecisionForMatchedRules {
  id cfg = [self mockConfiguratorForStaticDecisionWithTransitiveRules:YES];

  __block SNTRule* matchedRule;
  OCMStub([self.mockRuleTable executionRuleForIdentifiers:(struct RuleIdentifiers){}])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        SNTRule* rule = matchedRule;
        [invocation setReturnValue:&rule];
      });

  NSString* const kNoRule = @"Blocked (Unknown, Lockdown mode)";
  std::vector<std::pair<SNTRule*, NSString*>> cases = {
      {[self binaryRuleWithState:SNTRuleStateAllow seatbeltPolicy:nil], @"Allowed by rule"},
      {[self binaryRuleWithState:SNTRuleStateAllowCompiler seatbeltPolicy:nil], @"Allowed by rule"},
      {[self binaryRuleWithState:SNTRuleStateAllowTransitive seatbeltPolicy:nil],
       @"Allowed by rule"},
      {[self binaryRuleWithState:SNTRuleStateAllowLocalBinary seatbeltPolicy:nil],
       @"Allowed by rule"},
      {[self binaryRuleWithState:SNTRuleStateBlock seatbeltPolicy:nil], @"Denied by rule"},
      {[self binaryRuleWithState:SNTRuleStateSilentBlockTTY seatbeltPolicy:nil], @"Denied by rule"},
      {[self binaryRuleWithState:SNTRuleStateSeatbelt seatbeltPolicy:@"(version 1)"],
       @"Blocked unless run with santactl sandbox"},
      {[self binaryRuleWithState:SNTRuleStateCEL seatbeltPolicy:nil],
       @"Unknown - CEL rule cannot be evaluated statically"},
      {[self binaryRuleWithState:SNTRuleStateCELv2 seatbeltPolicy:nil],
       @"Unknown - CEL rule cannot be evaluated statically"},
      {[self binaryRuleWithState:SNTRuleStateCELv2 seatbeltPolicy:@"(version 1)"],
       @"Unknown - CEL rule cannot be evaluated statically (may require santactl sandbox)"},
      {[[SNTRule alloc] initWithIdentifier:kSigningID
                                     state:SNTRuleStateAllowCompiler
                                      type:SNTRuleTypeSigningID],
       @"Allowed by rule"},
      {[[SNTRule alloc] initWithIdentifier:kSigningID
                                     state:SNTRuleStateAllowLocalSigningID
                                      type:SNTRuleTypeSigningID],
       @"Allowed by rule"},
      // States and type/state pairs the policy processor treats as no rule.
      {[self binaryRuleWithState:SNTRuleStateRemove seatbeltPolicy:nil], kNoRule},
      {[self binaryRuleWithState:(SNTRuleState)99 seatbeltPolicy:nil], kNoRule},
      {[[SNTRule alloc] initWithIdentifier:kTeamID
                                     state:SNTRuleStateAllowCompiler
                                      type:SNTRuleTypeTeamID],
       kNoRule},
      {[[SNTRule alloc] initWithIdentifier:kTeamID
                                     state:SNTRuleStateAllowLocalBinary
                                      type:SNTRuleTypeTeamID],
       kNoRule},
      {[self binaryRuleWithState:SNTRuleStateAllowLocalSigningID seatbeltPolicy:nil], kNoRule},
      {[[SNTRule alloc] initWithIdentifier:kSigningID
                                     state:SNTRuleStateAllowTransitive
                                      type:SNTRuleTypeSigningID],
       kNoRule},
      {nil, kNoRule},
  };

  for (const auto& [rule, want] : cases) {
    matchedRule = rule;
    XCTAssertEqualObjects([self staticDecision], want, @"rule: %@", rule);
  }

  [cfg stopMocking];
}

- (void)testStaticDecisionIgnoresTransitiveRuleWhenTransitiveRulesAreDisabled {
  id cfg = [self mockConfiguratorForStaticDecisionWithTransitiveRules:NO];
  [self stubRuleLookupReturns:[self binaryRuleWithState:SNTRuleStateAllowTransitive
                                         seatbeltPolicy:nil]];

  XCTAssertEqualObjects([self staticDecision], @"Blocked (Unknown, Lockdown mode)");

  [cfg stopMocking];
}

// ---- Manual (santactl) rule change gate ------------------------------
//
// Enforcement itself is release-only (#ifndef DEBUG), so these cover the decision directly.

- (void)testManualRuleChangesAreRefusedWhileASyncServerOwnsTheRuleDatabase {
  id cfg = OCMClassMock([SNTConfigurator class]);
  OCMStub([cfg configurator]).andReturn(cfg);
  OCMStub([cfg syncBaseURL]).andReturn([NSURL URLWithString:@"https://example.com/"]);

  XCTAssertTrue([self.sut shouldRejectManualRuleChangeAddingRules:YES],
                @"A sync server owns the rule database, so manual additions must be refused");
  XCTAssertTrue([self.sut shouldRejectManualRuleChangeAddingRules:NO],
                @"Clearing is the sync server's job too: a clean sync is the supported reset");

  [cfg stopMocking];
}

- (void)testManualRuleClearingIsAllowedWithStaticRulesButAddingIsNot {
  id cfg = OCMClassMock([SNTConfigurator class]);
  OCMStub([cfg configurator]).andReturn(cfg);
  OCMStub([cfg syncBaseURL]).andReturn(nil);
  OCMStub([cfg staticRules]).andReturn(@[ @{@"identifier" : @"abc"} ]);

  XCTAssertTrue([self.sut shouldRejectManualRuleChangeAddingRules:YES],
                @"Static rules are managed policy, so manual additions must still be refused");
  XCTAssertFalse([self.sut shouldRejectManualRuleChangeAddingRules:NO],
                 @"Clearing must stay possible, or a host moving to profile-only management is "
                 @"stuck with a departed sync server's rules");

  [cfg stopMocking];
}

- (void)testManualRuleChangesAreAllowedWhenNothingElseManagesPolicy {
  id cfg = OCMClassMock([SNTConfigurator class]);
  OCMStub([cfg configurator]).andReturn(cfg);
  OCMStub([cfg syncBaseURL]).andReturn(nil);
  OCMStub([cfg staticRules]).andReturn(@[]);

  XCTAssertFalse([self.sut shouldRejectManualRuleChangeAddingRules:YES]);
  XCTAssertFalse([self.sut shouldRejectManualRuleChangeAddingRules:NO]);

  [cfg stopMocking];
}

- (id)mockConfiguratorForSyncSettings {
  id cfg = OCMClassMock([SNTConfigurator class]);
  OCMStub([cfg configurator]).andReturn(cfg);
  OCMStub([cfg performSyncStateBatch:[OCMArg invokeBlock]]).andReturn(NO);
  return cfg;
}

- (void)testUpdateSyncSettingsAppliesExecutableIntegrityPolicy {
  id cfg = [self mockConfiguratorForSyncSettings];
  OCMExpect([cfg setSyncServerExecutableIntegrityPolicy:SNTExecutableIntegrityPolicyReport]);

  SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
  bundle.executableIntegrityPolicy = @(SNTExecutableIntegrityPolicyReport);

  __block BOOL replied = NO;
  [self.sut updateSyncSettings:bundle
                         reply:^{
                           replied = YES;
                         }];

  XCTAssertTrue(replied);
  OCMVerifyAll(cfg);
  [cfg stopMocking];
}

- (void)testUpdateSyncSettingsPassesUnknownExecutableIntegrityPolicyToClearIt {
  id cfg = [self mockConfiguratorForSyncSettings];
  OCMExpect([cfg setSyncServerExecutableIntegrityPolicy:SNTExecutableIntegrityPolicyUnknown]);

  SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
  bundle.executableIntegrityPolicy = @(SNTExecutableIntegrityPolicyUnknown);

  __block BOOL replied = NO;
  [self.sut updateSyncSettings:bundle
                         reply:^{
                           replied = YES;
                         }];

  XCTAssertTrue(replied);
  OCMVerifyAll(cfg);
  [cfg stopMocking];
}

- (void)testUpdateSyncSettingsWithoutExecutableIntegrityPolicyLeavesItAlone {
  id cfg = [self mockConfiguratorForSyncSettings];
  OCMReject([cfg setSyncServerExecutableIntegrityPolicy:SNTExecutableIntegrityPolicyUnknown])
      .ignoringNonObjectArgs();
  // The bundle still carries another key, so the batch demonstrably ran.
  OCMExpect([cfg setSyncServerClientMode:SNTClientModeLockdown]);

  SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
  bundle.clientMode = @(SNTClientModeLockdown);

  __block BOOL replied = NO;
  [self.sut updateSyncSettings:bundle
                         reply:^{
                           replied = YES;
                         }];

  XCTAssertTrue(replied);
  OCMVerifyAll(cfg);
  [cfg stopMocking];
}

- (void)testUpdateSyncSettingsAppliesDisableExecutableIntegrityRecheck {
  for (NSNumber* value in @[ @(SNTSyncedBoolUnset), @(SNTSyncedBoolFalse), @(SNTSyncedBoolTrue) ]) {
    id cfg = [self mockConfiguratorForSyncSettings];
    OCMExpect(
        [cfg setSyncServerDisableExecutableIntegrityRecheck:(SNTSyncedBool)value.integerValue]);

    SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
    bundle.disableExecutableIntegrityRecheck = value;

    __block BOOL replied = NO;
    [self.sut updateSyncSettings:bundle
                           reply:^{
                             replied = YES;
                           }];

    XCTAssertTrue(replied);
    OCMVerifyAll(cfg);
    [cfg stopMocking];
  }
}

- (void)testUpdateSyncSettingsAppliesBlockMessages {
  id cfg = [self mockConfiguratorForSyncSettings];
  OCMExpect([cfg setSyncServerBannedBlockMessage:@"Ask IT before installing apps"]);
  OCMExpect([cfg setSyncServerUnknownBlockMessage:@"Request approval for new apps"]);

  SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
  bundle.bannedBlockMessage = @"Ask IT before installing apps";
  bundle.unknownBlockMessage = @"Request approval for new apps";

  __block BOOL replied = NO;
  [self.sut updateSyncSettings:bundle
                         reply:^{
                           replied = YES;
                         }];

  XCTAssertTrue(replied);
  OCMVerifyAll(cfg);
  [cfg stopMocking];
}

- (void)testUpdateSyncSettingsAppliesUSBBlockMessages {
  id cfg = [self mockConfiguratorForSyncSettings];
  OCMExpect([cfg setSyncServerBannedUSBBlockMessage:@"USB storage is blocked"]);
  // An empty message is passed through so the configurator can remove the synced value.
  OCMExpect([cfg setSyncServerRemountUSBBlockMessage:@""]);

  SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
  bundle.bannedUSBBlockMessage = @"USB storage is blocked";
  bundle.remountUSBBlockMessage = @"";

  __block BOOL replied = NO;
  [self.sut updateSyncSettings:bundle
                         reply:^{
                           replied = YES;
                         }];

  XCTAssertTrue(replied);
  OCMVerifyAll(cfg);
  [cfg stopMocking];
}

- (void)testUpdateSyncSettingsWithoutUSBBlockMessagesLeavesThemAlone {
  id cfg = [self mockConfiguratorForSyncSettings];
  OCMReject([cfg setSyncServerBannedBlockMessage:[OCMArg any]]);
  OCMReject([cfg setSyncServerUnknownBlockMessage:[OCMArg any]]);
  OCMReject([cfg setSyncServerBannedUSBBlockMessage:[OCMArg any]]);
  OCMReject([cfg setSyncServerRemountUSBBlockMessage:[OCMArg any]]);
  // The bundle still carries another key, so the batch demonstrably ran.
  OCMExpect([cfg setSyncServerClientMode:SNTClientModeLockdown]);

  SNTConfigBundle* bundle = [[SNTConfigBundle alloc] init];
  bundle.clientMode = @(SNTClientModeLockdown);

  __block BOOL replied = NO;
  [self.sut updateSyncSettings:bundle
                         reply:^{
                           replied = YES;
                         }];

  XCTAssertTrue(replied);
  OCMVerifyAll(cfg);
  [cfg stopMocking];
}

#pragma mark - Temporary Admin Mode: requester / approver binding

// An audit token whose uid fields all name `uid`. MakeStubAuditToken only sets
// pid/pidversion, which reads as euid 0 and is refused as "already an
// administrator" before any prompt.
static audit_token_t MakeAuditTokenForUID(uid_t uid, pid_t pid) {
  return audit_token_t{
      .val = {uid, uid, 20, uid, 20, (unsigned int)pid, 100, 1},
  };
}

// A uid that no account on a developer machine resolves to, so the real
// admin-group read in RequestMinutes answers "not a member" and the request
// reaches the authorization step.
static const uid_t kUnknownLocalUser = 0x7fff1001;

- (id)mockConfiguratorWithOnDemandAdminPolicy {
  id cfg = OCMClassMock([SNTConfigurator class]);
  OCMStub([cfg configurator]).andReturn(cfg);
  OCMStub([cfg temporaryAdminPolicy])
      .andReturn([[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                      defaultDuration:5
                                                 requireJustification:NO]);
  OCMStub([cfg isSyncV2Enabled]).andReturn(YES);
  OCMStub([cfg syncBaseURL]).andReturn([NSURL URLWithString:@"https://foo.workshop.cloud"]);
  return cfg;
}

- (SNTDaemonControlController*)controllerWithNotificationQueue:(SNTNotificationQueue*)queue {
  return [[SNTDaemonControlController alloc] initWithNotificationQueue:queue
      syncdQueue:nil
      netExtensionQueue:nil
      logger:nullptr
      watchItems:nullptr
      sandboxExpectations:_sandboxExpectations
      flushCacheBlock:^(santa::FlushCacheMode, santa::FlushCacheReason) {
      }
      cacheCountBlock:^NSArray<NSNumber*>*() {
        return @[];
      }
      checkCacheBlock:^SNTAction(SantaVnode) {
        return SNTActionRespondAllow;
      }
      metricsExportBlock:^(void (^)(BOOL)) {
      }
      binaryUploadController:nullptr];
}

// A GUI notifier that records whether it was asked to authorize Admin Mode and
// always denies, so no test can reach the real admin-group write even on a
// build where the request is wrongly let through.
- (id)denyingNotifierRecordingAsked:(BOOL*)asked {
  id notifier = OCMProtocolMock(@protocol(SNTNotifierXPC));
  OCMStub([notifier authorizeTemporaryAdminModeRequiringJustification:NO reply:[OCMArg any]])
      .andDo(^(NSInvocation* inv) {
        *asked = YES;
        __unsafe_unretained void (^reply)(BOOL, NSString*) = nil;
        [inv getArgument:&reply atIndex:3];
        reply(NO, @"");
      });
  return notifier;
}

- (SNTNotificationQueue*)queueWithNotifierConnection:(id)connection ownerUID:(uid_t)uid {
  SNTNotificationQueue* queue = [[SNTNotificationQueue alloc]
      initWithRingBuffer:std::make_unique<santa::RingBuffer<NSMutableDictionary*>>(3)];
  [queue setNotifierConnection:connection ownerUID:uid];
  return queue;
}

// The notifier connection. Reuses the one MOLXPCConnection class mock: a second
// class mock of the same class would take over its class-method stubs, and the
// peer audit token stub with them.
- (id)connectionVendingNotifier:(id)notifier {
  OCMStub([self.mockMOLXPC synchronousRemoteObjectProxy]).andReturn(notifier);
  OCMStub([self.mockMOLXPC remoteObjectProxy]).andReturn(notifier);
  return self.mockMOLXPC;
}

// The daemon elevates the uid of the XPC peer that sent the request, and the
// authorization prompt is shown by the GUI registered in one user's session. A
// request from any other uid is refused before that GUI is asked.
- (void)testTemporaryAdminModeRequestFromAnotherUserIsRefusedBeforeTheGUIIsAsked {
  // Stays active until the test ends; OCMock stops the class mock itself.
  id cfg __attribute__((unused)) = [self mockConfiguratorWithOnDemandAdminPolicy];

  // The GUI registered from the console user's session (uid 501).
  BOOL guiAsked = NO;
  id notifierConn = [self connectionVendingNotifier:[self denyingNotifierRecordingAsked:&guiAsked]];
  SNTDaemonControlController* dc = [self
      controllerWithNotificationQueue:[self queueWithNotifierConnection:notifierConn ownerUID:501]];

  // The request arrives from a different, non-admin local account.
  audit_token_t tok = MakeAuditTokenForUID(kUnknownLocalUser, 4242);
  OCMStub([self.mockMOLXPC currentPeerAuditToken]).andReturn(tok);

  __block uint32_t gotMinutes = 99;
  __block NSError* gotErr = nil;
  [dc requestTemporaryAdminModeWithDurationMinutes:@5
                                             reply:^(uint32_t minutes, NSError* err) {
                                               gotMinutes = minutes;
                                               gotErr = err;
                                             }];

  XCTAssertFalse(guiAsked, @"the console user's GUI was asked to approve uid %u's request",
                 kUnknownLocalUser);
  XCTAssertEqual(gotMinutes, 0u);
  XCTAssertEqual(gotErr.code, SNTErrorCodeTAMRequesterMismatch, @"%@", gotErr);

  // The controller's timed sessions observe `cfg` through KVO, so it is torn down here, while
  // the mock is still active.
  dc = nil;
}

// The self-service case still works: the user whose session registered the GUI is the one
// asking, so the GUI is asked. (The stub denies, so the real group write is never reached.)
- (void)testTemporaryAdminModeRequestFromTheGUIOwnerReachesTheGUI {
  id cfg __attribute__((unused)) = [self mockConfiguratorWithOnDemandAdminPolicy];

  BOOL guiAsked = NO;
  id notifierConn = [self connectionVendingNotifier:[self denyingNotifierRecordingAsked:&guiAsked]];
  SNTDaemonControlController* dc =
      [self controllerWithNotificationQueue:[self queueWithNotifierConnection:notifierConn
                                                                     ownerUID:kUnknownLocalUser]];

  audit_token_t tok = MakeAuditTokenForUID(kUnknownLocalUser, 4242);
  OCMStub([self.mockMOLXPC currentPeerAuditToken]).andReturn(tok);

  __block NSError* gotErr = nil;
  [dc requestTemporaryAdminModeWithDurationMinutes:@5
                                             reply:^(uint32_t minutes, NSError* err) {
                                               gotErr = err;
                                             }];

  XCTAssertTrue(guiAsked);
  XCTAssertEqual(gotErr.code, SNTErrorCodeTAMAuthFailed, @"%@", gotErr);

  dc = nil;
}

// Registering the GUI listener records the registering peer's euid as the owner the prompts
// will vouch for. (The connection to the dummy endpoint times out after two seconds; the
// recording does not depend on it succeeding.)
- (void)testSetNotificationListenerRecordsThePeerUIDAsTheNotifierOwner {
  id queue = OCMClassMock([SNTNotificationQueue class]);
  SNTDaemonControlController* dc = [self controllerWithNotificationQueue:queue];

  audit_token_t tok = MakeAuditTokenForUID(501, 4242);
  OCMStub([self.mockMOLXPC currentPeerAuditToken]).andReturn(tok);

  [dc setNotificationListener:[NSXPCListener anonymousListener].endpoint];

  OCMVerify([queue setNotifierConnection:[OCMArg isNotNil] ownerUID:501]);
}

// Without a peer audit token (the real currentPeerAuditToken returns a zeroed token when no XPC
// connection is dispatching, as here), the connection is recorded with no owner rather than as
// root's, so nothing relies on uid 0 being refused elsewhere.
- (void)testSetNotificationListenerWithoutPeerTokenRecordsNoOwner {
  id queue = OCMClassMock([SNTNotificationQueue class]);
  SNTDaemonControlController* dc = [self controllerWithNotificationQueue:queue];

  [dc setNotificationListener:[NSXPCListener anonymousListener].endpoint];

  OCMVerify([queue setNotifierConnection:[OCMArg isNotNil] ownerUID:kSNTNotifierNoOwner]);
}

@end
