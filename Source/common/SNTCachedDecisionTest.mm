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

- (void)testCachedIdentityPreservesUnsignedCodesignValidationResult {
  SNTCachedDecision* previous = [[SNTCachedDecision alloc] init];
  previous.sha256 = @"aabbccdd";
  previous.codesignValidationState = SNTCodesignValidationStateUnsigned;

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] initWithCachedIdentity:previous];

  XCTAssertEqual(cached.codesignValidationState, SNTCodesignValidationStateUnsigned);
}

- (void)testCachedIdentityPreservesSuccessfulAdhocValidationWithoutCertificate {
  SNTCachedDecision* previous = [[SNTCachedDecision alloc] init];
  previous.sha256 = @"aabbccdd";
  previous.certSHA256 = nil;
  previous.codesignValidationState = SNTCodesignValidationStateSuccess;

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] initWithCachedIdentity:previous];

  XCTAssertEqual(cached.codesignValidationState, SNTCodesignValidationStateSuccess);
  XCTAssertNil(cached.certSHA256);
}

- (void)testCachedIdentityPreservesNeedsValidationCodesignState {
  SNTCachedDecision* previous = [[SNTCachedDecision alloc] init];
  previous.sha256 = @"aabbccdd";

  SNTCachedDecision* cached = [[SNTCachedDecision alloc] initWithCachedIdentity:previous];

  XCTAssertEqual(cached.codesignValidationState, SNTCodesignValidationStateNeedsValidation);
}

- (void)testCodesignValidationErrorCatalog {
  NSArray<NSNumber*>* reusableErrors = @[
    @(errSecCSUnsigned),
    @(errSecCSSignatureFailed),
    @(errSecCSSignatureUnsupported),
    @(errSecCSReqInvalid),
    @(errSecCSReqUnsupported),
    @(errSecCSBadObjectFormat),
    @(errSecCSSignatureInvalid),
    @(errSecCSTooBig),
    @(errSecCSUnsupportedDigestAlgorithm),
    @(errSecCSInvalidTeamIdentifier),
    @(errSecCSBadTeamIdentifier),
    @(errSecMultipleExecSegments),
    @(errSecCSInvalidEntitlements),
    @(errSecCSInvalidRuntimeVersion),
  ];

  for (NSNumber* error in reusableErrors) {
    OSStatus status = (OSStatus)error.intValue;
    SNTCodesignValidationState state = SNTCodesignValidationStateForError(status);
    XCTAssertNotEqual(state, SNTCodesignValidationStateNeedsValidation);
    XCTAssertEqual(SNTCodesignValidationErrorForState(state), status);
  }
}

- (void)testMutableCodesignValidationErrorsRequireRetry {
  NSArray<NSNumber*>* retryableErrors = @[
    @(errSecCSSignatureNotVerifiable),
    @(errSecCSBadDictionaryFormat),
    @(errSecCSStaticCodeChanged),
    @(errSecCSStaticCodeNotFound),
    @(errSecCSDBAccess),
    @(errSecCSInternalError),
    @(errSecCSInfoPlistFailed),
    @(errSecCSUnsignedNestedCode),
    @(errSecCSBadNestedCode),
    @(errSecCSBadMainExecutable),
    @(errSecCSCancelled),
    @(errSecCSInvalidAssociatedFileData),
    @(errSecCSSignatureUntrusted),
    @(errSecCSRevokedNotarization),
  ];

  for (NSNumber* error in retryableErrors) {
    XCTAssertEqual(SNTCodesignValidationStateForError((OSStatus)error.intValue),
                   SNTCodesignValidationStateNeedsValidation);
  }
}

- (void)testUnknownCodesignValidationStateFailsClosed {
  XCTAssertEqual(SNTCodesignValidationErrorForState((SNTCodesignValidationState)NSIntegerMax),
                 errSecCSInternalError);
}

@end
