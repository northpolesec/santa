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

#import <XCTest/XCTest.h>
#import "Source/common/SNTTemporaryAdminPolicy.h"

@interface SNTTemporaryAdminPolicyTest : XCTestCase
@end

@implementation SNTTemporaryAdminPolicyTest

- (void)testOnDemandClampsAndDefaults {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                                    defaultDuration:30
                                                               requireJustification:YES];
  XCTAssertEqual(p.type, SNTTemporaryAdminPolicyTypeOnDemand);
  XCTAssertEqualObjects(p.maxMinutes, @60);
  XCTAssertEqualObjects(p.defaultDurationMinutes, @30);
  XCTAssertTrue(p.requireJustification);
  XCTAssertEqual([p getDurationMinutes:@0], 30u);
  XCTAssertEqual([p getDurationMinutes:@1000], 60u);
  XCTAssertEqual([p getDurationMinutes:@45], 45u);
}

// A double above 2^64 wraps under -unsignedLongLongValue but saturates under
// -unsignedIntValue, so deciding with one and returning the other leaked.
- (void)testOversizedRequestCannotExceedMax {
  // Production cap: the wrapped value only slips under a cap above it.
  SNTTemporaryAdminPolicy* p =
      [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:kMaxTemporaryAdminMinutes
                                           defaultDuration:30
                                      requireJustification:NO];

  // Must be computed, not a literal: a folded constant converts differently and
  // would make this test vacuous.
  volatile double computed = 12810238940076099.0 * 86400.0 / 60.0;
  NSNumber* oversized = @((double)computed);

  XCTAssertLessThanOrEqual([oversized unsignedLongLongValue], [p.maxMinutes unsignedLongLongValue],
                           @"fixture no longer passes the limit check");
  XCTAssertGreaterThan([oversized unsignedIntValue], [p.maxMinutes unsignedIntValue],
                       @"fixture no longer reads as oversized");

  XCTAssertLessThanOrEqual([p getDurationMinutes:oversized], [p.maxMinutes unsignedIntValue]);
}

- (void)testDefaultDurationClampedToMax {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:10
                                                                    defaultDuration:9999
                                                               requireJustification:NO];
  XCTAssertEqualObjects(p.defaultDurationMinutes, @10);
}

- (void)testZeroMinutesIsNil {
  XCTAssertNil([[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:0
                                                    defaultDuration:0
                                               requireJustification:YES]);
}

- (void)testRevocation {
  XCTAssertEqual([[SNTTemporaryAdminPolicy alloc] initRevocation].type,
                 SNTTemporaryAdminPolicyTypeRevoke);
}

- (void)testRevocationRoundTripPreservesNilFields {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initRevocation];
  SNTTemporaryAdminPolicy* r = [SNTTemporaryAdminPolicy deserialize:[p serialize]];
  XCTAssertEqual(r.type, SNTTemporaryAdminPolicyTypeRevoke);
  // Revoke policies have no duration fields; clamping must not synthesize defaults.
  XCTAssertNil(r.maxMinutes);
  XCTAssertNil(r.defaultDurationMinutes);
}

- (void)testSecureCodingRoundTripPreservesFlags {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:120
                                                                    defaultDuration:15
                                                               requireJustification:NO];
  SNTTemporaryAdminPolicy* r = [SNTTemporaryAdminPolicy deserialize:[p serialize]];
  XCTAssertEqual(r.type, SNTTemporaryAdminPolicyTypeOnDemand);
  XCTAssertEqualObjects(r.maxMinutes, @120);
  XCTAssertEqualObjects(r.defaultDurationMinutes, @15);
  XCTAssertFalse(r.requireJustification);
}

- (void)testDeserializeNilReturnsNil {
  XCTAssertNil([SNTTemporaryAdminPolicy deserialize:nil]);
}

@end
