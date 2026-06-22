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

#include "Source/common/AuditUtilities.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <optional>
#include <type_traits>

#include "absl/container/flat_hash_map.h"

using santa::AuditTokenFromData;
using santa::ProcessID;

// ProcessID must stay an aggregate with trivial copy/move so it works as a
// braced initializer and a flat_hash_map key.
static_assert(std::is_trivially_copyable_v<ProcessID>);
static_assert(std::is_aggregate_v<ProcessID>);

@interface AuditUtilitiesTest : XCTestCase
@end

@implementation AuditUtilitiesTest

- (void)setUp {
  self.continueAfterFailure = NO;
}

- (void)testFromToken {
  audit_token_t tok = santa::MakeStubAuditToken(42, 7);
  ProcessID proc = ProcessID::FromToken(tok);
  XCTAssertEqual(proc.pid, 42);
  XCTAssertEqual(proc.pidversion, 7);
}

- (void)testFromTokenDataValid {
  audit_token_t tok = santa::MakeStubAuditToken(1234, 9);
  NSData* data = [NSData dataWithBytes:&tok length:sizeof(tok)];
  std::optional<ProcessID> proc = ProcessID::FromTokenData(data);
  XCTAssertTrue(proc.has_value());
  XCTAssertEqual(proc->pid, 1234);
  XCTAssertEqual(proc->pidversion, 9);
}

- (void)testFromTokenDataTooShortIsNullopt {
  uint8_t shortBytes[sizeof(audit_token_t) - 1] = {0};
  NSData* data = [NSData dataWithBytes:shortBytes length:sizeof(shortBytes)];
  XCTAssertFalse(ProcessID::FromTokenData(data).has_value());
}

- (void)testFromTokenDataNilIsNullopt {
  XCTAssertFalse(ProcessID::FromTokenData(nil).has_value());
}

- (void)testAuditTokenFromDataValid {
  audit_token_t tok = santa::MakeStubAuditToken(1234, 9);
  NSData* data = [NSData dataWithBytes:&tok length:sizeof(tok)];
  std::optional<audit_token_t> got = AuditTokenFromData(data);
  XCTAssertTrue(got.has_value());
  XCTAssertEqual(santa::Pid(*got), 1234);
  XCTAssertEqual(santa::Pidversion(*got), 9);
}

- (void)testAuditTokenFromDataTooShortIsNullopt {
  uint8_t shortBytes[sizeof(audit_token_t) - 1] = {0};
  NSData* data = [NSData dataWithBytes:shortBytes length:sizeof(shortBytes)];
  XCTAssertFalse(AuditTokenFromData(data).has_value());
}

- (void)testAuditTokenFromDataNilIsNullopt {
  XCTAssertFalse(AuditTokenFromData(nil).has_value());
}

- (void)testPackedScheme {
  ProcessID proc{42, 7};
  XCTAssertEqual(proc.Packed(), ((uint64_t)42 << 32) | 7);
}

- (void)testPackedRoundTripsThroughToken {
  audit_token_t tok = santa::MakeStubAuditToken(100, 3);
  ProcessID proc = ProcessID::FromToken(tok);
  XCTAssertEqual(proc.Packed(), ((uint64_t)100 << 32) | 3);
}

- (void)testEquality {
  XCTAssertTrue((ProcessID{5, 1} == ProcessID{5, 1}));
  XCTAssertFalse((ProcessID{5, 1} == ProcessID{5, 2}));
  XCTAssertFalse((ProcessID{6, 1} == ProcessID{5, 1}));
}

- (void)testUsableAsFlatHashMapKey {
  absl::flat_hash_map<ProcessID, NSString*> m;
  m[ProcessID{42, 7}] = @"a";
  m[ProcessID{42, 8}] = @"b";  // same pid, different pidversion: distinct key

  XCTAssertEqualObjects(m[(ProcessID{42, 7})], @"a");
  XCTAssertEqualObjects(m[(ProcessID{42, 8})], @"b");
  XCTAssertEqual(m.size(), 2u);

  audit_token_t tok = santa::MakeStubAuditToken(42, 7);
  XCTAssertEqualObjects(m[ProcessID::FromToken(tok)], @"a");
}

@end
