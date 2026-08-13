/// Copyright 2022 Google Inc. All rights reserved.
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

#import <Security/Security.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCachedDecision.h"
#include "Source/common/TestUtils.h"

@interface SNTCachedDecisionTest : XCTestCase
@end

@implementation SNTCachedDecisionTest

- (void)testSNTCachedDecisionInit {
  // Ensure the vnodeId field is properly set from the es_file_t
  struct stat sb = MakeStat();
  es_file_t file = MakeESFile("foo", sb);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] initWithEndpointSecurityFile:&file];

  XCTAssertEqual(sb.st_ino, cd.vnodeId.fileid);
  XCTAssertEqual(sb.st_dev, cd.vnodeId.fsid);
}

- (void)testCachedIdentityCarriesSuccessfulValidationWithoutCertificate {
  SNTCachedDecision* previous = [[SNTCachedDecision alloc] init];
  previous.sha256 = @"aabbccdd";
  // Ad-hoc and linker-signed binaries validate successfully with no
  // certificate. This is the case a certSHA256 check cannot distinguish from
  // "validation has not run yet".
  previous.codesignValidationStatus = @(errSecSuccess);

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] initWithCachedIdentity:previous];

  XCTAssertEqualObjects(cached.codesignValidationStatus, @(errSecSuccess));
  XCTAssertNil(cached.certSHA256);
}

- (void)testCachedIdentityCarriesValidationFailure {
  SNTCachedDecision* previous = [[SNTCachedDecision alloc] init];
  previous.sha256 = @"aabbccdd";
  previous.codesignValidationStatus = @(errSecCSUnsigned);

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] initWithCachedIdentity:previous];

  XCTAssertEqualObjects(cached.codesignValidationStatus, @(errSecCSUnsigned));
}

- (void)testCachedIdentityLeavesValidationStatusNilWhenNeverValidated {
  SNTCachedDecision* previous = [[SNTCachedDecision alloc] init];
  previous.sha256 = @"aabbccdd";

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] initWithCachedIdentity:previous];

  XCTAssertNil(cached.codesignValidationStatus);
}

- (void)testCopyCarriesValidationStatus {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.codesignValidationStatus = @(errSecCSUnsigned);

  SNTCachedDecision* copy = [cd copy];

  XCTAssertEqualObjects(copy.codesignValidationStatus, @(errSecCSUnsigned));
}

@end
