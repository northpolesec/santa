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

#import "Source/common/SNTTimedRuleKillDetails.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRuleTimeWindow.h"

@interface SNTTimedRuleKillDetailsTest : XCTestCase
@end

@implementation SNTTimedRuleKillDetailsTest

- (void)testSecureCodingRoundTrip {
  SNTRuleTimeWindow* window = [[SNTRuleTimeWindow alloc] init];
  window.days = @[ @1, @2, @3, @4, @5 ];
  window.startOfDay = @"09:00";
  window.endOfDay = @"17:00";
  window.zoneName = @"America/New_York";

  SNTTimedRuleKillDetails* details = [[SNTTimedRuleKillDetails alloc] init];
  details.application = @"Google Chrome";
  details.deadline = [NSDate dateWithTimeIntervalSince1970:1735819200];
  details.ruleType = SNTRuleTypeSigningID;
  details.publisher = @"Google LLC";
  details.user = @"nobody";
  details.path = @"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  details.signingID = @"EQHXZ8M8AV:com.google.Chrome";
  details.cdhash = @"a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3e4f5a0b1";
  details.parentName = @"launchd";
  details.ppid = @1;
  details.timeWindow = window;

  NSError* error = nil;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:details
                                       requiringSecureCoding:YES
                                                       error:&error];
  XCTAssertNil(error);
  SNTTimedRuleKillDetails* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTTimedRuleKillDetails class]
                                        fromData:data
                                           error:&error];
  XCTAssertNil(error);

  XCTAssertEqualObjects(decoded.application, details.application);
  XCTAssertEqualObjects(decoded.deadline, details.deadline);
  XCTAssertEqual(decoded.ruleType, details.ruleType);
  XCTAssertEqualObjects(decoded.publisher, details.publisher);
  XCTAssertEqualObjects(decoded.user, details.user);
  XCTAssertEqualObjects(decoded.path, details.path);
  XCTAssertEqualObjects(decoded.signingID, details.signingID);
  XCTAssertEqualObjects(decoded.cdhash, details.cdhash);
  XCTAssertEqualObjects(decoded.parentName, details.parentName);
  XCTAssertEqualObjects(decoded.ppid, details.ppid);
  XCTAssertEqualObjects(decoded.timeWindow.days, window.days);
  XCTAssertEqualObjects(decoded.timeWindow.startOfDay, window.startOfDay);
  XCTAssertEqualObjects(decoded.timeWindow.endOfDay, window.endOfDay);
  XCTAssertEqualObjects(decoded.timeWindow.zoneName, window.zoneName);
}

@end
