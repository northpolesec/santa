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
