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

#import "Source/santactl/SNTCommand.h"

@interface SNTCommandTest : XCTestCase
@property SNTCommand* command;
@end

@implementation SNTCommandTest

- (void)setUp {
  self.command = [[SNTCommand alloc] initWithDaemonConnection:nil];
}

- (void)testParseTimeIntervalBareInteger {
  XCTAssertEqual([self.command parseTimeInterval:@"10"], 10);
}

- (void)testParseTimeIntervalMinutes {
  XCTAssertEqual([self.command parseTimeInterval:@"10m"], 10);
}

- (void)testParseTimeIntervalHours {
  XCTAssertEqual([self.command parseTimeInterval:@"2h"], 120);
}

- (void)testParseTimeIntervalDays {
  XCTAssertEqual([self.command parseTimeInterval:@"3d"], 4320);
}

- (void)testParseTimeIntervalZero {
  XCTAssertEqual([self.command parseTimeInterval:@"0"], 0);
}

- (void)testParseTimeIntervalEmptyStringIsInvalid {
  XCTAssertEqual([self.command parseTimeInterval:@""], 0);
}

- (void)testParseTimeIntervalNonNumericIsInvalid {
  XCTAssertEqual([self.command parseTimeInterval:@"abc"], 0);
}

- (void)testParseTimeIntervalUnknownUnitIsInvalid {
  XCTAssertEqual([self.command parseTimeInterval:@"10x"], 0);
}

- (void)testParseTimeIntervalSecondsUnitIsInvalid {
  // 's' is in the scanner's unit charset but has no branch, so it is rejected
  // like any other unsupported unit.
  XCTAssertEqual([self.command parseTimeInterval:@"10s"], 0);
}

- (void)testParseTimeIntervalMultiCharUnitIsInvalid {
  XCTAssertEqual([self.command parseTimeInterval:@"10mm"], 0);
}

- (void)testParseTimeIntervalTrailingContentIsInvalid {
  XCTAssertEqual([self.command parseTimeInterval:@"10m5"], 0);
}

@end
