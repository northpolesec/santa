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

- (void)testAllowlistAbsentMeansNoEnforcement {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                                    defaultDuration:5
                                                               requireJustification:NO
                                                                      allowedAdmins:nil];
  XCTAssertFalse(p.enforcesAdminGroup);
  XCTAssertNil(p.allowedAdminUsernames);
}

- (void)testEmptyAllowlistEnforcesWithNobodyAllowed {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                                    defaultDuration:5
                                                               requireJustification:NO
                                                                      allowedAdmins:@[]];
  XCTAssertTrue(p.enforcesAdminGroup);
  XCTAssertNotNil(p.allowedAdminUsernames);
  XCTAssertEqual(p.allowedAdminUsernames.count, 0u);
}

- (void)testAllowlistIsNormalized {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc]
       initOnDemandMinutes:60
           defaultDuration:5
      requireJustification:NO
             allowedAdmins:@[ @"  Kandji_Admin ", @"ladmin", @"", @"   ", @"uid:503", @"LADMIN" ]];
  NSSet* want = [NSSet setWithObjects:@"kandji_admin", @"ladmin", nil];
  XCTAssertEqualObjects(p.allowedAdminUsernames, want);
}

- (void)testAllowlistSurvivesSerialization {
  SNTTemporaryAdminPolicy* p =
      [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                           defaultDuration:5
                                      requireJustification:NO
                                             allowedAdmins:@[ @"kandji_admin" ]];
  SNTTemporaryAdminPolicy* got = [SNTTemporaryAdminPolicy deserialize:[p serialize]];
  XCTAssertTrue(got.enforcesAdminGroup);
  XCTAssertEqualObjects(got.allowedAdminUsernames, [NSSet setWithObject:@"kandji_admin"]);
}

- (void)testNonEnforcingPolicySurvivesSerialization {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                                    defaultDuration:5
                                                               requireJustification:NO];
  SNTTemporaryAdminPolicy* got = [SNTTemporaryAdminPolicy deserialize:[p serialize]];
  XCTAssertFalse(got.enforcesAdminGroup);
  XCTAssertNil(got.allowedAdminUsernames);
}

- (void)testRevocationPolicyDoesNotEnforce {
  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initRevocation];
  XCTAssertFalse(p.enforcesAdminGroup);
  XCTAssertNil(p.allowedAdminUsernames);
}

- (void)testOldArchiveWithNeitherKeyDecodesToNonEnforcing {
  // Simulates an archive written by a build that predates
  // enforcesAdminGroup/allowedAdminUsernames: only the four original keys are
  // present. Landing on "enforcing, nobody allowed" here instead of "not
  // enforcing" would demote every admin in the fleet the first time an old
  // cached policy is read by a new build.
  NSKeyedArchiver* archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
  [archiver encodeObject:@(SNTTemporaryAdminPolicyTypeOnDemand) forKey:@"type"];
  [archiver encodeObject:@60 forKey:@"maxMinutes"];
  [archiver encodeObject:@5 forKey:@"defaultDurationMinutes"];
  [archiver encodeObject:@NO forKey:@"requireJustification"];
  [archiver finishEncoding];

  NSError* error;
  NSKeyedUnarchiver* unarchiver =
      [[NSKeyedUnarchiver alloc] initForReadingFromData:archiver.encodedData error:&error];
  XCTAssertNil(error);
  unarchiver.requiresSecureCoding = YES;
  SNTTemporaryAdminPolicy* got = [[SNTTemporaryAdminPolicy alloc] initWithCoder:unarchiver];
  [unarchiver finishDecoding];

  XCTAssertFalse(got.enforcesAdminGroup);
  XCTAssertNil(got.allowedAdminUsernames);
}

- (void)testAllowlistMatchesAcrossUnicodeCompositions {
  // "josé" written with a combining acute (NFD), as a directory may report it.
  NSString* decomposed = @"josé";
  // The same name precomposed (NFC), as a browser form typically submits it.
  NSString* composed = @"josé";
  XCTAssertNotEqualObjects(decomposed, composed);  // different bytes, same name

  SNTTemporaryAdminPolicy* p = [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                                    defaultDuration:5
                                                               requireJustification:NO
                                                                      allowedAdmins:@[ composed ]];
  // Both forms must land on the same key, or the account is demoted anyway with
  // nothing logged and nothing visible in the UI.
  XCTAssertTrue([p.allowedAdminUsernames
      containsObject:[SNTTemporaryAdminPolicy normalizedUsername:decomposed]]);
}

@end
