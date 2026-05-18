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

#import "Source/santad/SandboxedLineage.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>

#include "Source/common/AuditUtilities.h"

using santa::SandboxedLineage;

@interface SandboxedLineageTest : XCTestCase
@end

@implementation SandboxedLineageTest

- (void)testContainsMissingIsFalse {
  SandboxedLineage lineage;
  XCTAssertFalse(lineage.Contains(santa::MakeStubAuditToken(100, 1)));
}

- (void)testMarkThenContains {
  SandboxedLineage lineage;
  audit_token_t t = santa::MakeStubAuditToken(100, 1);
  XCTAssertTrue(lineage.Mark(t));
  XCTAssertTrue(lineage.Contains(t));
}

- (void)testMarkIsIdempotent {
  SandboxedLineage lineage;
  audit_token_t t = santa::MakeStubAuditToken(100, 1);
  XCTAssertTrue(lineage.Mark(t));
  XCTAssertTrue(lineage.Mark(t));
  XCTAssertEqual(lineage.CountForTesting(), 1u);
}

- (void)testForgetRemoves {
  SandboxedLineage lineage;
  audit_token_t t = santa::MakeStubAuditToken(100, 1);
  lineage.Mark(t);
  lineage.Forget(t);
  XCTAssertFalse(lineage.Contains(t));
}

- (void)testForgetMissingIsNoop {
  SandboxedLineage lineage;
  // Just must not crash or insert.
  lineage.Forget(santa::MakeStubAuditToken(100, 1));
  XCTAssertEqual(lineage.CountForTesting(), 0u);
}

- (void)testPidVersionDiscriminatesEntries {
  SandboxedLineage lineage;
  audit_token_t v1 = santa::MakeStubAuditToken(100, 1);
  audit_token_t v2 = santa::MakeStubAuditToken(100, 2);
  lineage.Mark(v1);
  XCTAssertTrue(lineage.Contains(v1));
  XCTAssertFalse(lineage.Contains(v2));
}

- (void)testPropagateOnForkWhenParentMarked {
  SandboxedLineage lineage;
  audit_token_t parent = santa::MakeStubAuditToken(100, 1);
  audit_token_t child = santa::MakeStubAuditToken(101, 1);
  lineage.Mark(parent);
  XCTAssertTrue(lineage.PropagateOnFork(parent, child));
  XCTAssertTrue(lineage.Contains(child));
  // Parent membership is preserved (process keeps living after fork).
  XCTAssertTrue(lineage.Contains(parent));
}

- (void)testPropagateOnForkWhenParentNotMarked {
  SandboxedLineage lineage;
  audit_token_t parent = santa::MakeStubAuditToken(100, 1);
  audit_token_t child = santa::MakeStubAuditToken(101, 1);
  XCTAssertFalse(lineage.PropagateOnFork(parent, child));
  XCTAssertFalse(lineage.Contains(child));
}

- (void)testOnExecShiftsMembership {
  SandboxedLineage lineage;
  audit_token_t pre = santa::MakeStubAuditToken(100, 1);
  audit_token_t post = santa::MakeStubAuditToken(100, 2);
  lineage.Mark(pre);

  XCTAssertTrue(lineage.OnExec(pre, post));
  XCTAssertFalse(lineage.Contains(pre));
  XCTAssertTrue(lineage.Contains(post));
  XCTAssertEqual(lineage.CountForTesting(), 1u);
}

- (void)testOnExecWhenPreNotMarkedIsNoop {
  SandboxedLineage lineage;
  audit_token_t pre = santa::MakeStubAuditToken(100, 1);
  audit_token_t post = santa::MakeStubAuditToken(100, 2);
  XCTAssertFalse(lineage.OnExec(pre, post));
  XCTAssertFalse(lineage.Contains(post));
  XCTAssertEqual(lineage.CountForTesting(), 0u);
}

- (void)testCapacityRejectsBeyondMax {
  SandboxedLineage lineage;
  for (size_t i = 0; i < SandboxedLineage::kMaxEntries; ++i) {
    XCTAssertTrue(lineage.Mark(santa::MakeStubAuditToken(10000 + (pid_t)i, 1)));
  }
  XCTAssertEqual(lineage.CountForTesting(), SandboxedLineage::kMaxEntries);

  audit_token_t overflow = santa::MakeStubAuditToken(99999, 1);
  XCTAssertFalse(lineage.Mark(overflow));
  XCTAssertFalse(lineage.Contains(overflow));

  // Freeing a slot allows insertion.
  lineage.Forget(santa::MakeStubAuditToken(10000, 1));
  XCTAssertTrue(lineage.Mark(overflow));
}

- (void)testCapacityIdempotentMarkOfExistingTokenSucceeds {
  SandboxedLineage lineage;
  audit_token_t known = santa::MakeStubAuditToken(7, 7);
  XCTAssertTrue(lineage.Mark(known));
  // Fill remaining capacity.
  for (size_t i = 0; i < SandboxedLineage::kMaxEntries - 1; ++i) {
    XCTAssertTrue(lineage.Mark(santa::MakeStubAuditToken(20000 + (pid_t)i, 1)));
  }
  // Re-marking the existing token must still succeed at capacity (it's a no-op
  // insert, no new slot consumed).
  XCTAssertTrue(lineage.Mark(known));
  XCTAssertEqual(lineage.CountForTesting(), SandboxedLineage::kMaxEntries);
}

- (void)testPropagateOnForkAtCapacity {
  SandboxedLineage lineage;
  audit_token_t parent = santa::MakeStubAuditToken(7, 1);
  XCTAssertTrue(lineage.Mark(parent));
  // Fill the rest.
  for (size_t i = 0; i < SandboxedLineage::kMaxEntries - 1; ++i) {
    XCTAssertTrue(lineage.Mark(santa::MakeStubAuditToken(30000 + (pid_t)i, 1)));
  }

  audit_token_t child = santa::MakeStubAuditToken(8, 1);
  XCTAssertFalse(lineage.PropagateOnFork(parent, child));
  XCTAssertFalse(lineage.Contains(child));
}

@end
