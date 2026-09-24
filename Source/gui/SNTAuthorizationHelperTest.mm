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

#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/gui/SNTAuthorizationHelper.h"

@interface SNTAuthorizationHelperTest : XCTestCase
@end

@implementation SNTAuthorizationHelperTest

- (SNTStoredExecutionEvent*)eventWithBundleName:(NSString*)bundleName {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.fileBundleName = bundleName;
  se.filePath = @"/Applications/Slack.app/Contents/MacOS/Slack";
  return se;
}

- (void)testReasonUsesTheBundleNameForAVerifiedRead {
  NSString* got = [SNTAuthorizationHelper
      executionAuthorizationReasonForEvent:[self eventWithBundleName:@"Slack"]];
  XCTAssertEqualObjects(got, @"authorize execution of the application Slack");
}

- (void)testReasonDropsTheBundleNameAndWarnsForAnUnverifiedRead {
  SNTStoredExecutionEvent* se = [self eventWithBundleName:@"Other App"];
  se.identityUnverified = YES;
  se.identityVendorMatched = NO;

  NSString* got = [SNTAuthorizationHelper executionAuthorizationReasonForEvent:se];
  XCTAssertEqualObjects(got, @"authorize execution of Slack, whose identity could not be verified");
}

- (void)testReasonIsUnchangedForAVendorMatchedRead {
  SNTStoredExecutionEvent* se = [self eventWithBundleName:@"Slack"];
  se.identityUnverified = YES;
  se.identityVendorMatched = YES;

  NSString* got = [SNTAuthorizationHelper executionAuthorizationReasonForEvent:se];
  XCTAssertEqualObjects(got, @"authorize execution of the application Slack");
}

- (void)testReasonWithoutAPathStillWarnsForAnUnverifiedRead {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.identityUnverified = YES;

  NSString* got = [SNTAuthorizationHelper executionAuthorizationReasonForEvent:se];
  XCTAssertEqualObjects(
      got, @"authorize execution of an application whose identity could not be verified");
}

@end
