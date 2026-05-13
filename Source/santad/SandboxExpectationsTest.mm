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

#import "Source/santad/SandboxExpectations.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>
#include <string.h>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTSandboxExecRequest.h"

using santa::SandboxExpectations;
using RegisterResult = santa::SandboxExpectations::RegisterResult;

// Builds a hex string of |CS_CDHASH_LEN * 2| chars by repeating each nibble of
// |fill|. Keeps the tests' "single byte fill value" convention readable.
static NSString* HexCdhashFromFill(uint8_t fill) {
  NSMutableString* s = [NSMutableString stringWithCapacity:CS_CDHASH_LEN * 2];
  for (size_t i = 0; i < CS_CDHASH_LEN; i++) {
    [s appendFormat:@"%02x", fill];
  }
  return s;
}

static SNTSandboxExecRequest* MakeStubRequest(uint64_t dev, uint64_t ino, uint8_t cdhashFill,
                                              NSString* sha256) {
  SNTRuleIdentifiers* ids = [[SNTRuleIdentifiers alloc]
      initWithRuleIdentifiers:{.cdhash = HexCdhashFromFill(cdhashFill), .binarySHA256 = sha256}];
  return [[SNTSandboxExecRequest alloc] initWithIdentifiers:ids
                                                      fsDev:dev
                                                      fsIno:ino
                                               resolvedPath:nil];
}

@interface SandboxExpectationsTest : XCTestCase
@end

@implementation SandboxExpectationsTest

- (void)testConsumeMissingReturnsNullopt {
  SandboxExpectations exp;
  audit_token_t token = santa::MakeStubAuditToken(4242, 1);
  XCTAssertFalse(exp.Consume(token).has_value());
}

- (void)testConsumeIsOneShot {
  SandboxExpectations exp;
  audit_token_t token = santa::MakeStubAuditToken(9, 9);
  XCTAssertEqual(exp.Register(token, MakeStubRequest(0, 0, 0, nil)), RegisterResult::kOk);
  XCTAssertTrue(exp.Consume(token).has_value());
  XCTAssertFalse(exp.Consume(token).has_value());
}

- (void)testDoubleRegisterSameTokenRejected {
  SandboxExpectations exp;
  audit_token_t token = santa::MakeStubAuditToken(11, 1);

  XCTAssertEqual(exp.Register(token, MakeStubRequest(0, 0, 0x11, nil)), RegisterResult::kOk);
  XCTAssertEqual(exp.Register(token, MakeStubRequest(0, 0, 0x22, nil)), RegisterResult::kDuplicate);

  // Original entry survives.
  auto got = exp.Consume(token);
  XCTAssertTrue(got.has_value());
  XCTAssertEqual(got->cdhash[0], 0x11);
}

- (void)testExpiryOnConsume {
  uint64_t now = 1000;
  SandboxExpectations exp([&now] { return now; });

  audit_token_t token = santa::MakeStubAuditToken(42, 1);
  XCTAssertEqual(exp.Register(token, MakeStubRequest(0, 0, 0, nil)), RegisterResult::kOk);

  now += SandboxExpectations::kTTLNanos + 1;
  XCTAssertFalse(exp.Consume(token).has_value());
}

- (void)testSweepRemovesExpiredOnRegister {
  uint64_t now = 0;
  SandboxExpectations exp([&now] { return now; });

  audit_token_t stale = santa::MakeStubAuditToken(1, 1);
  audit_token_t fresh = santa::MakeStubAuditToken(2, 1);

  XCTAssertEqual(exp.Register(stale, MakeStubRequest(0, 0, 0, nil)), RegisterResult::kOk);
  now += SandboxExpectations::kTTLNanos + 1;
  XCTAssertEqual(exp.Register(fresh, MakeStubRequest(0, 0, 0, nil)), RegisterResult::kOk);
  XCTAssertEqual(exp.CountForTesting(), 1u);
  XCTAssertFalse(exp.Consume(stale).has_value());
  XCTAssertTrue(exp.Consume(fresh).has_value());
}

- (void)testCapRejectsOverflow {
  SandboxExpectations exp;

  // Fill the map to the cap.
  for (size_t i = 0; i < SandboxExpectations::kMaxEntries; ++i) {
    audit_token_t t = santa::MakeStubAuditToken(10000 + (int)i, 1);
    XCTAssertEqual(exp.Register(t, MakeStubRequest(0, 0, 0, nil)), RegisterResult::kOk);
  }

  // One more — rejected with capacity-exceeded (not duplicate).
  audit_token_t overflow = santa::MakeStubAuditToken(9999, 1);
  XCTAssertEqual(exp.Register(overflow, MakeStubRequest(0, 0, 0, nil)),
                 RegisterResult::kCapacityExceeded);

  // Freeing a slot allows a new registration.
  audit_token_t inMap = santa::MakeStubAuditToken(10000, 1);
  (void)exp.Consume(inMap);
  XCTAssertEqual(exp.Register(overflow, MakeStubRequest(0, 0, 0, nil)), RegisterResult::kOk);
}

- (void)testRegisterWithMissingCdhashSucceedsForUnsignedBinary {
  // Unsigned binaries have no cdhash. Register should succeed — the strict
  // AUTH_EXEC branch never fires for them, and the fallback branch uses
  // (dev, ino, sha256). The stored cdhash ends up zero-initialized.
  SandboxExpectations exp;
  audit_token_t token = santa::MakeStubAuditToken(77, 1);

  SNTRuleIdentifiers* ids =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{.binarySHA256 = @"abc"}];
  SNTSandboxExecRequest* r = [[SNTSandboxExecRequest alloc] initWithIdentifiers:ids
                                                                          fsDev:1
                                                                          fsIno:2
                                                                   resolvedPath:nil];

  XCTAssertEqual(exp.Register(token, r), RegisterResult::kOk);
  auto got = exp.Consume(token);
  XCTAssertTrue(got.has_value());
  XCTAssertEqual(got->cdhash[0], 0);
  XCTAssertEqual(got->cdhash[19], 0);
}

- (void)testRegisterThenConsumeReturnsExpectation {
  SandboxExpectations exp;
  audit_token_t token = santa::MakeStubAuditToken(1234, 7);

  XCTAssertEqual(exp.Register(token, MakeStubRequest(42, 99, 0xAB, @"feedface")),
                 RegisterResult::kOk);

  auto got = exp.Consume(token);
  XCTAssertTrue(got.has_value());
  XCTAssertEqual(got->dev, 42u);
  XCTAssertEqual(got->ino, 99u);
  XCTAssertEqual(got->cdhash[0], 0xAB);
  XCTAssertEqual(got->cdhash[19], 0xAB);
  XCTAssertEqual(got->sha256, std::string("feedface"));
}

- (void)testRegisterWithNilSHA256LeavesExpectationSha256Empty {
  SandboxExpectations exp;
  audit_token_t token = santa::MakeStubAuditToken(5678, 1);

  XCTAssertEqual(exp.Register(token, MakeStubRequest(1, 2, 0xCD, nil)), RegisterResult::kOk);

  auto got = exp.Consume(token);
  XCTAssertTrue(got.has_value());
  XCTAssertEqual(got->dev, 1u);
  XCTAssertEqual(got->ino, 2u);
  XCTAssertTrue(got->sha256.empty());
}

@end
