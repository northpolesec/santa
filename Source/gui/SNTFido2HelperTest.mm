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

#import "Source/common/SNTError.h"
#import "Source/gui/SNTAuthorizationHelper.h"
#import "Source/gui/SNTFido2Helper.h"

@interface SNTFido2HelperTest : XCTestCase
@end

@implementation SNTFido2HelperTest

- (void)setUp {
  [super setUp];
  fclose(stdout);
}

// An authorization method this build does not recognize must be refused rather
// than fall back to Touch ID, which could approve a hold that asked for
// something else.
//
// The assertion is on the error, not the boolean: a headless test has no Touch
// ID either, so a Touch ID fallback would also answer NO. Only the error says
// which path produced it -- LocalAuthentication's own domain, or ours.
- (void)testUnknownAuthorizationMethodIsRefused {
  NSError* error;
  XCTAssertFalse([SNTAuthorizationHelper canAuthorizeWithMethod:(SNTAuthorizationMethod)999
                                                          error:&error]);
  XCTAssertEqualObjects(error.domain, SantaErrorDomain);
  XCTAssertEqual(error.code, SNTErrorCodeAuthorizationMethodUnavailable);
}

// Whether a key is attached cannot be answered without IOKit, which must not run
// on the main thread these are called from. Both answer YES so the user is
// offered the prompt and can still plug one in.
- (void)testKeyCapableMethodsAreAlwaysOffered {
  XCTAssertTrue([SNTAuthorizationHelper canAuthorizeWithMethod:SNTAuthorizationMethodSecurityKey
                                                         error:NULL]);
  XCTAssertTrue([SNTAuthorizationHelper canAuthorizeWithMethod:SNTAuthorizationMethodPresence
                                                         error:NULL]);
}

@end
