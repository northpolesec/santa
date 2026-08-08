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

#include <cstring>

#import "Source/common/SNTError.h"

// Defined in SNTCommandMonitorMode.mm. Declared here rather than in a header so
// the command's internals stay private, matching SNTCommandDoctorTest.mm.
extern NSNumber* SNTMonitorModeDurationMinutes(NSString* arg, NSError** error);

@interface SNTCommandMonitorModeTest : XCTestCase
@end

@implementation SNTCommandMonitorModeTest

- (void)assertMinutes:(NSString*)input equals:(int64_t)expected {
  NSError* err = nil;
  NSNumber* got = SNTMonitorModeDurationMinutes(input, &err);
  XCTAssertNotNil(got, @"\"%@\" was rejected: %@", input, err.localizedDescription);
  XCTAssertEqual(got.longLongValue, expected, @"\"%@\"", input);
  // Integer-backed: the daemon's two unsigned accessors disagree for a double.
  XCTAssertEqual(strcmp(got.objCType, @encode(long long)), 0, @"\"%@\" is not integer-backed",
                 input);
}

- (void)assertRejected:(NSString*)input messageContains:(NSString*)needle {
  NSError* err = nil;
  XCTAssertNil(SNTMonitorModeDurationMinutes(input, &err), @"\"%@\" was accepted", input);
  XCTAssertEqualObjects(err.domain, SantaErrorDomain);
  XCTAssertEqual(err.code, SNTErrorCodeInvalidDuration);
  XCTAssertTrue([err.localizedDescription containsString:needle], @"\"%@\": %@ lacks \"%@\"", input,
                err.localizedDescription, needle);
}

// Covers only what this command adds on top of the shared parser: the minutes
// default unit, the conversion, and the constraints the parser leaves to callers.
- (void)testDurationArgumentResolvesToWholeMinutes {
  [self assertMinutes:@"10" equals:10];   // bare integer means minutes
  [self assertMinutes:@"2h" equals:120];  // suffixed durations convert
  [self assertMinutes:@"120s" equals:2];  // seconds are fine on a minute boundary

  // The parser accepts all three of these; this command cannot use them.
  [self assertRejected:@"30s" messageContains:@"whole number of minutes"];
  [self assertRejected:@"0" messageContains:@"greater than zero"];
  [self assertRejected:@"-5m" messageContains:@"greater than zero"];

  // A syntax error reaches the caller rather than being swallowed or reworded.
  [self assertRejected:@"10x" messageContains:@"unknown unit 'x'"];

  // Rejected before it can become an NSNumber that slips past the policy cap.
  [self assertRejected:@"12810238940076099d" messageContains:@"out of range"];
}

@end
