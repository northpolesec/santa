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

#include <optional>

#import "Source/common/SNTError.h"
#import "Source/santactl/SNTCommand.h"

@interface SNTCommandTest : XCTestCase
@end

@implementation SNTCommandTest

#pragma mark - parseTimeInterval:defaultUnit:error:

// Not prefixed "test", so XCTest does not run them as cases.
- (void)assertDuration:(NSString*)input unit:(SNTDurationUnit)unit equals:(int64_t)expected {
  NSError* err = nil;
  std::optional<int64_t> got = [SNTCommand parseTimeInterval:input defaultUnit:unit error:&err];
  XCTAssertTrue(got.has_value(), @"\"%@\" failed to parse: %@", input, err.localizedDescription);
  if (got.has_value()) {
    XCTAssertEqual(*got, expected, @"\"%@\"", input);
  }
}

- (void)assertDurationInvalid:(NSString*)input
                         unit:(SNTDurationUnit)unit
              messageContains:(NSString*)needle {
  NSError* err = nil;
  std::optional<int64_t> got = [SNTCommand parseTimeInterval:input defaultUnit:unit error:&err];
  XCTAssertFalse(got.has_value(), @"\"%@\" unexpectedly parsed", input);
  XCTAssertEqualObjects(err.domain, SantaErrorDomain);
  XCTAssertEqual(err.code, SNTErrorCodeInvalidDuration);
  XCTAssertTrue([err.localizedDescription containsString:needle], @"\"%@\": %@ lacks \"%@\"", input,
                err.localizedDescription, needle);
}

- (void)testParseDurationUnitSuffixes {
  [self assertDuration:@"10s" unit:SNTDurationUnitNone equals:10];
  [self assertDuration:@"10m" unit:SNTDurationUnitNone equals:600];
  [self assertDuration:@"2h" unit:SNTDurationUnitNone equals:7200];
  [self assertDuration:@"3d" unit:SNTDurationUnitNone equals:259200];
}

// Guard against the minutes constraint creeping back in: these values are only
// correct if the return unit is seconds.
- (void)testParseDurationHasNoNotionOfMinutes {
  [self assertDuration:@"1h" unit:SNTDurationUnitNone equals:3600];
  [self assertDuration:@"1d" unit:SNTDurationUnitNone equals:86400];
}

- (void)testParseDurationDefaultUnitAppliedToBareInteger {
  [self assertDuration:@"10" unit:SNTDurationUnitSeconds equals:10];
  [self assertDuration:@"10" unit:SNTDurationUnitMinutes equals:600];
  [self assertDuration:@"10" unit:SNTDurationUnitHours equals:36000];
  [self assertDuration:@"10" unit:SNTDurationUnitDays equals:864000];
}

- (void)testParseDurationExplicitUnitOverridesDefault {
  [self assertDuration:@"10s" unit:SNTDurationUnitDays equals:10];
}

- (void)testParseDurationBareIntegerRequiresADefaultUnit {
  [self assertDurationInvalid:@"10" unit:SNTDurationUnitNone messageContains:@"a unit is required"];
}

// A defaultUnit outside the enum (e.g. an errant cast) must fail the parse
// rather than silently resolving to a multiplier of zero.
- (void)testParseDurationRejectsAnOutOfRangeDefaultUnit {
  [self assertDurationInvalid:@"10" unit:(SNTDurationUnit)99 messageContains:@"unsupported unit"];
}

// Zero parses successfully. Whether zero is *allowed* is the caller's business.
- (void)testParseDurationZeroIsValid {
  [self assertDuration:@"0s" unit:SNTDurationUnitNone equals:0];
  [self assertDuration:@"0m" unit:SNTDurationUnitNone equals:0];
  [self assertDuration:@"0" unit:SNTDurationUnitMinutes equals:0];
}

// A signed duration is syntactically well-formed. Callers reject non-positive values.
- (void)testParseDurationSignedValuesAreValid {
  [self assertDuration:@"-5m" unit:SNTDurationUnitNone equals:-300];
  [self assertDuration:@"+5m" unit:SNTDurationUnitNone equals:300];
}

- (void)testParseDurationEmptyIsInvalid {
  [self assertDurationInvalid:@"" unit:SNTDurationUnitNone messageContains:@"empty string"];
}

- (void)testParseDurationNilIsInvalid {
  [self assertDurationInvalid:nil unit:SNTDurationUnitNone messageContains:@"empty string"];
}

- (void)testParseDurationNonNumericIsInvalid {
  [self assertDurationInvalid:@"abc" unit:SNTDurationUnitNone messageContains:@"expected a number"];
}

- (void)testParseDurationUnknownUnitIsInvalid {
  [self assertDurationInvalid:@"10x" unit:SNTDurationUnitNone messageContains:@"unknown unit 'x'"];
}

- (void)testParseDurationMultiCharUnitIsInvalid {
  [self assertDurationInvalid:@"10mm" unit:SNTDurationUnitNone messageContains:@"single character"];
}

- (void)testParseDurationTrailingContentIsInvalid {
  [self assertDurationInvalid:@"10m5" unit:SNTDurationUnitNone messageContains:@"trailing content"];
}

// charactersToBeSkipped = nil is what makes these whitespace-containing inputs
// fail rather than silently parsing as if the whitespace weren't there.
- (void)testParseDurationRejectsWhitespace {
  [self assertDurationInvalid:@"10 s" unit:SNTDurationUnitNone messageContains:@"unknown unit"];
  [self assertDurationInvalid:@" 10s"
                         unit:SNTDurationUnitNone
              messageContains:@"expected a number"];
  [self assertDurationInvalid:@"10 " unit:SNTDurationUnitNone messageContains:@"unknown unit"];
}

// scanInteger saturates at NSIntegerMax/Min and still reports success, so a
// saturated value is input the scanner could not read faithfully.
- (void)testParseDurationOutOfRangeIsInvalid {
  [self assertDurationInvalid:@"99999999999999999999d"
                         unit:SNTDurationUnitNone
              messageContains:@"out of range"];
  [self assertDurationInvalid:@"9223372036854775807"
                         unit:SNTDurationUnitMinutes
              messageContains:@"out of range"];
  // Multiplier of 1, so the overflow check cannot fire: this isolates the
  // saturation guard.
  [self assertDurationInvalid:@"99999999999999999999s"
                         unit:SNTDurationUnitNone
              messageContains:@"out of range"];
}

// The scanned integer fitting is not enough -- the product must too, or an
// unrepresentable duration reaches callers and can slip past a policy limit.
- (void)testParseDurationRejectsAProductThatOverflows {
  // Scans cleanly; only the multiply overflows.
  [self assertDurationInvalid:@"12810238940076099d"
                         unit:SNTDurationUnitNone
              messageContains:@"out of range"];
  [self assertDurationInvalid:@"9223372036854775806"
                         unit:SNTDurationUnitDays
              messageContains:@"out of range"];
  // Just under the boundary, so it still parses.
  [self assertDuration:@"106751991167300d" unit:SNTDurationUnitNone equals:9223372036854720000];
}

- (void)testParseDurationNullErrorOutParamIsSafe {
  std::optional<int64_t> got = [SNTCommand parseTimeInterval:@"nope"
                                                 defaultUnit:SNTDurationUnitNone
                                                       error:NULL];
  XCTAssertFalse(got.has_value());
}

@end
