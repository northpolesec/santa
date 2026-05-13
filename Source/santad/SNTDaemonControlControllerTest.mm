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

#import "Source/santad/SNTDaemonControlController.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>

#include <memory>

#import "Source/common/AuditUtilities.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSandboxExecRequest.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"
#include "Source/santad/SandboxExpectations.h"

using santa::SandboxExpectations;

// A valid 64-char lowercase hex string; SNTRule's initializer enforces this
// shape for binary-type identifiers.
static NSString* const kBinarySHA256 =
    @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// Expose seatbeltPolicy readwrite so tests can simulate the (technically
// unreachable-from-prod) "SEATBELT rule with empty policy" state.
@interface SNTRule ()
@property(readwrite) NSString* seatbeltPolicy;
@end

@interface SNTDaemonControlControllerTest : XCTestCase
@property id mockDatabaseController;
@property id mockRuleTable;
@property id mockMOLXPC;
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

  self.sut = [[SNTDaemonControlController alloc] initWithNotificationQueue:nil
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
      metricsExportBlock:^(void (^)(BOOL)){
      }];
}

- (void)tearDown {
  self.sut = nil;
  [self.mockDatabaseController stopMocking];
  [self.mockRuleTable stopMocking];
  [self.mockMOLXPC stopMocking];
  [super tearDown];
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

@end
