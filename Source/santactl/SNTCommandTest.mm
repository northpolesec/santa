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

#include <cstdint>
#include <cstring>
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

// Also guards the minutes constraint creeping back in: these values are only
// correct if the return unit is seconds.
- (void)testParseDurationUnitSuffixes {
  [self assertDuration:@"10s" unit:SNTDurationUnitNone equals:10];
  [self assertDuration:@"10m" unit:SNTDurationUnitNone equals:600];
  [self assertDuration:@"2h" unit:SNTDurationUnitNone equals:7200];
  [self assertDuration:@"3d" unit:SNTDurationUnitNone equals:259200];
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

- (void)testParseDurationTrailingContentIsInvalid {
  [self assertDurationInvalid:@"10m5" unit:SNTDurationUnitNone messageContains:@"trailing content"];
  [self assertDurationInvalid:@"10mm" unit:SNTDurationUnitNone messageContains:@"trailing content"];
}

// strtoll skips leading whitespace, so the parser rejects it explicitly rather
// than letting " 10s" parse as if the space were not there.
- (void)testParseDurationRejectsWhitespace {
  [self assertDurationInvalid:@" 10s"
                         unit:SNTDurationUnitNone
              messageContains:@"leading whitespace"];
  [self assertDurationInvalid:@"\t10s"
                         unit:SNTDurationUnitNone
              messageContains:@"leading whitespace"];
  [self assertDurationInvalid:@"10 s" unit:SNTDurationUnitNone messageContains:@"trailing content"];
  [self assertDurationInvalid:@"10 " unit:SNTDurationUnitNone messageContains:@"unknown unit"];
}

// strtoll reports ERANGE for a value it cannot represent. Seconds have a
// multiplier of 1, so the overflow check cannot fire: this isolates that path.
- (void)testParseDurationOutOfRangeIsInvalid {
  [self assertDurationInvalid:@"99999999999999999999s"
                         unit:SNTDurationUnitNone
              messageContains:@"out of range"];
}

// ERANGE distinguishes an unreadable value from a genuine boundary one, so the
// exact int64 limits parse rather than being rejected as collateral.
- (void)testParseDurationAcceptsTheExactInt64Limits {
  [self assertDuration:@"9223372036854775807s" unit:SNTDurationUnitNone equals:INT64_MAX];
  [self assertDuration:@"-9223372036854775808s" unit:SNTDurationUnitNone equals:INT64_MIN];
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
  // Underflow as well: a one-sided check against INT64_MAX would miss this.
  [self assertDurationInvalid:@"-106751991167301d"
                         unit:SNTDurationUnitNone
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

#pragma mark - parseWholeMinutes:error:

- (void)assertMinutes:(NSString*)input equals:(int64_t)expected {
  NSError* err = nil;
  NSNumber* got = [SNTCommand parseWholeMinutes:input error:&err];
  XCTAssertNotNil(got, @"\"%@\" was rejected: %@", input, err.localizedDescription);
  XCTAssertEqual(got.longLongValue, expected, @"\"%@\"", input);
  // Integer-backed: the daemon's two unsigned accessors disagree for a double.
  XCTAssertEqual(strcmp(got.objCType, @encode(long long)), 0, @"\"%@\" is not integer-backed",
                 input);
}

- (void)assertMinutesRejected:(NSString*)input messageContains:(NSString*)needle {
  NSError* err = nil;
  XCTAssertNil([SNTCommand parseWholeMinutes:input error:&err], @"\"%@\" was accepted", input);
  XCTAssertEqualObjects(err.domain, SantaErrorDomain);
  XCTAssertEqual(err.code, SNTErrorCodeInvalidDuration);
  XCTAssertTrue([err.localizedDescription containsString:needle], @"\"%@\": %@ lacks \"%@\"", input,
                err.localizedDescription, needle);
}

// Covers what this adds on top of the parser: the minutes default unit, the
// conversion, and the constraints the parser deliberately leaves to callers.
- (void)testParseWholeMinutes {
  [self assertMinutes:@"10" equals:10];   // bare integer means minutes
  [self assertMinutes:@"2h" equals:120];  // suffixed durations convert
  [self assertMinutes:@"120s" equals:2];  // seconds are fine on a minute boundary

  // The parser accepts both of these; a minutes-based caller cannot use them.
  [self assertMinutesRejected:@"30s" messageContains:@"whole number of minutes"];
  [self assertMinutesRejected:@"0" messageContains:@"greater than zero"];

  // A syntax error reaches the caller rather than being swallowed or reworded.
  [self assertMinutesRejected:@"10x" messageContains:@"unknown unit 'x'"];
}

@end
