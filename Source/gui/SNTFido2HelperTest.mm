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

#import <Cocoa/Cocoa.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTError.h"
#import "Source/gui/SNTAuthorizationHelper.h"
#import "Source/gui/SNTFido2Helper.h"

@interface SNTFido2Request : NSObject
@property(atomic) BOOL abandoned;
@end

@interface SNTFido2Helper (Testing)
+ (NSWindow*)showPromptWindowWithReason:(NSString*)reason
                           offerTouchID:(BOOL)offerTouchID
                                request:(SNTFido2Request*)request
                             replyBlock:(void (^)(SNTFido2Result))replyBlock;
@end

@interface SNTFido2HelperTest : XCTestCase
@end

@implementation SNTFido2HelperTest {
  BOOL _claimedWhenAbandoned;
}

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

// The touch wait has no deadline, so closing the prompt without its buttons must
// still deny and stop the device loop, or the key and the queue stay held.
- (void)testClosingPromptDenies {
  SNTFido2Request* request = [[NSClassFromString(@"SNTFido2Request") alloc] init];
  XCTestExpectation* replied = [self expectationWithDescription:@"reply"];
  __block SNTFido2Result got = SNTFido2ResultApproved;

  NSWindow* window = [SNTFido2Helper showPromptWindowWithReason:@"test"
                                                   offerTouchID:NO
                                                        request:request
                                                     replyBlock:^(SNTFido2Result result) {
                                                       got = result;
                                                       [replied fulfill];
                                                     }];
  [window close];

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
  XCTAssertEqual(got, SNTFido2ResultDenied);
  XCTAssertTrue(request.abandoned);
}

- (void)observeValueForKeyPath:(NSString*)keyPath
                      ofObject:(id)object
                        change:(NSDictionary*)change
                       context:(void*)context {
  _claimedWhenAbandoned = [[object valueForKey:@"claimed"] boolValue];
}

// The device loop answers Denied as soon as it sees abandoned, so the prompt
// must claim the request first. Otherwise the loop can claim it in between and
// "Use Touch ID" is lost.
- (void)testPromptClaimsBeforeAbandoning {
  SNTFido2Request* request = [[NSClassFromString(@"SNTFido2Request") alloc] init];
  [request addObserver:self forKeyPath:@"abandoned" options:0 context:NULL];
  XCTestExpectation* replied = [self expectationWithDescription:@"reply"];

  NSWindow* window = [SNTFido2Helper showPromptWindowWithReason:@"test"
                                                   offerTouchID:NO
                                                        request:request
                                                     replyBlock:^(SNTFido2Result result) {
                                                       [replied fulfill];
                                                     }];
  [window close];

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
  [request removeObserver:self forKeyPath:@"abandoned"];
  XCTAssertTrue(request.abandoned);
  XCTAssertTrue(_claimedWhenAbandoned);
}

@end
