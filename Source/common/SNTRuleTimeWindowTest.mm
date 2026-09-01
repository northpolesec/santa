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

#import "Source/common/SNTRuleTimeWindow.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

// ICU writes U+202F NARROW NO-BREAK SPACE before AM/PM; the expectations below
// are written with a plain space.
static NSString* Plain(NSString* s) {
  NSString* narrow = [NSString stringWithFormat:@"%C", (unichar)0x202F];
  return [s stringByReplacingOccurrencesOfString:narrow withString:@" "];
}

@interface SNTRuleTimeWindowTest : XCTestCase
@end

@implementation SNTRuleTimeWindowTest

- (void)testDisplayStringWithLocale {
  NSLocale* locale = [NSLocale localeWithLocaleIdentifier:@"en_US"];

  SNTRuleTimeWindow* (^recurring)(NSArray<NSNumber*>*, NSString*, NSString*, NSString*) =
      ^(NSArray<NSNumber*>* days, NSString* start, NSString* end, NSString* zone) {
        SNTRuleTimeWindow* window = [[SNTRuleTimeWindow alloc] init];
        window.days = days;
        window.startOfDay = start;
        window.endOfDay = end;
        window.zoneName = zone;
        return window;
      };

  SNTRuleTimeWindow* absolute = [[SNTRuleTimeWindow alloc] init];
  absolute.startDate = [NSDate dateWithTimeIntervalSince1970:1735732800];
  absolute.endDate = [NSDate dateWithTimeIntervalSince1970:1735819200];

  // The absolute form renders in the reader's zone, so the expectation is built
  // from the same medium date plus short time styles rather than hardcoded.
  NSDateFormatter* df = [[NSDateFormatter alloc] init];
  df.locale = locale;
  df.dateStyle = NSDateFormatterMediumStyle;
  df.timeStyle = NSDateFormatterShortStyle;
  NSString* absoluteExpected =
      [NSString stringWithFormat:@"%@ to %@", [df stringFromDate:absolute.startDate],
                                 [df stringFromDate:absolute.endDate]];

  NSArray<NSArray*>* cases = @[
    @[
      recurring((@[ @1, @2, @3, @4, @5 ]), @"09:00", @"17:00", @"local"),
      @"9:00 AM to 5:00 PM, Mon to Fri"
    ],
    @[
      recurring((@[ @0, @1, @2, @3, @4, @5, @6 ]), @"07:00", @"22:00", @"America/New_York"),
      @"7:00 AM to 10:00 PM every day (America/New_York)"
    ],
    @[
      recurring((@[ @1, @3, @5 ]), @"09:00", @"17:00", @"local"),
      @"9:00 AM to 5:00 PM, Mon, Wed, Fri"
    ],
    @[ recurring(@[ @6 ], @"09:00", @"09:00", @"+05:30"), @"9:00 AM to 9:00 AM, Sat (+05:30)" ],
    @[ absolute, absoluteExpected ],
    @[
      recurring((@[ @1, @2, @3, @4, @5 ]), @"9:00", @"17:00", @"local"),
      @"9:00 to 5:00 PM, Mon to Fri"
    ],
  ];

  [cases enumerateObjectsUsingBlock:^(NSArray* testCase, NSUInteger index, BOOL* stop) {
    SNTRuleTimeWindow* window = testCase[0];
    XCTAssertEqualObjects(Plain([window displayStringWithLocale:locale]), Plain(testCase[1]),
                          @"case %lu", (unsigned long)index);
  }];
}

- (void)testSecureCodingRoundTrip {
  SNTRuleTimeWindow* window = [[SNTRuleTimeWindow alloc] init];
  window.days = @[ @1, @3 ];
  window.startOfDay = @"09:00";
  window.endOfDay = @"17:00";
  window.zoneName = @"America/New_York";
  window.startDate = [NSDate dateWithTimeIntervalSince1970:1735732800];
  window.endDate = [NSDate dateWithTimeIntervalSince1970:1735819200];
  window.open = YES;

  NSError* error = nil;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:window
                                       requiringSecureCoding:YES
                                                       error:&error];
  XCTAssertNil(error);
  SNTRuleTimeWindow* decoded = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTRuleTimeWindow class]
                                                                 fromData:data
                                                                    error:&error];
  XCTAssertNil(error);

  XCTAssertEqualObjects(decoded.days, window.days);
  XCTAssertEqualObjects(decoded.startOfDay, window.startOfDay);
  XCTAssertEqualObjects(decoded.endOfDay, window.endOfDay);
  XCTAssertEqualObjects(decoded.zoneName, window.zoneName);
  XCTAssertEqualObjects(decoded.startDate, window.startDate);
  XCTAssertEqualObjects(decoded.endDate, window.endDate);
  XCTAssertEqual(decoded.open, window.open);
}

@end
