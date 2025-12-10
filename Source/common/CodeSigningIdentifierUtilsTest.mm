/// Copyright 2025 North Pole Security, Inc.
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

#include "Source/common/CodeSigningIdentifierUtils.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface CodeSigningIdentifierUtilsTest : XCTestCase
@end

@implementation CodeSigningIdentifierUtilsTest

#pragma mark - IsValidTeamID Tests

- (void)testIsValidTeamID {
  // Valid IDs
  XCTAssertTrue(santa::IsValidTeamID(@"ABCDE12345"));
  XCTAssertTrue(santa::IsValidTeamID(@"1234567890"));
  XCTAssertTrue(santa::IsValidTeamID(@"abcdefghij"));

  // Invalid - Too short
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE1234"));
  XCTAssertFalse(santa::IsValidTeamID(@""));
  XCTAssertFalse(santa::IsValidTeamID(@"A"));

  // Invalid - Too long
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE123456"));
  XCTAssertFalse(santa::IsValidTeamID(@"12345678901234567890"));

  // Invalid - Bad chars
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE-1234"));
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE 1234"));
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE.1234"));
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE:1234"));
  XCTAssertFalse(santa::IsValidTeamID(@"ABCDE@1234"));

  // Invalid - nil
  XCTAssertFalse(santa::IsValidTeamID(nil));

  // Invalid - Empty
  XCTAssertFalse(santa::IsValidTeamID(@""));
}

- (void)testIsValidSigningID {
  // Valid TID:SID
  XCTAssertTrue(santa::IsValidSigningID(@"ABCDE12345:com.example.app"));
  XCTAssertTrue(santa::IsValidSigningID(@"1234567890:com.test.app"));
  XCTAssertTrue(santa::IsValidSigningID(@"ABC1DEF2GH:app.id"));

  // Valid platform:SID
  XCTAssertTrue(santa::IsValidSigningID(@"platform:com.apple.system"));
  XCTAssertTrue(santa::IsValidSigningID(@"platform:WindowServer"));
  XCTAssertTrue(santa::IsValidSigningID(@"platform:a"));

  // Invalid TeamID
  XCTAssertFalse(santa::IsValidSigningID(@"ABCDE1234:com.example.app"));
  XCTAssertFalse(santa::IsValidSigningID(@"ABCDE123456:com.example.app"));
  XCTAssertFalse(santa::IsValidSigningID(@"ABCDE-1234:com.example.app"));

  // Invalid - Missing colon
  XCTAssertFalse(santa::IsValidSigningID(@"ABCDE12345com.example.app"));
  XCTAssertFalse(santa::IsValidSigningID(@"platformcom.example.app"));

  // Invalid - Only colon {
  XCTAssertFalse(santa::IsValidSigningID(@":"));
  XCTAssertFalse(santa::IsValidSigningID(@"::"));

  // Invalid - Empty SID component
  XCTAssertFalse(santa::IsValidSigningID(@"ABCDE12345:"));
  XCTAssertFalse(santa::IsValidSigningID(@"platform:"));

  // Invalid - nil
  XCTAssertFalse(santa::IsValidSigningID(nil));

  // Invalid - Empty
  XCTAssertFalse(santa::IsValidSigningID(@""));
}

- (void)testIsValidCDHash {
  // Valid
  XCTAssertTrue(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef01234567"));
  XCTAssertTrue(santa::IsValidCDHash(@"ABCDEF0123456789ABCDEF0123456789ABCDEF01"));

  // Invalid - Too short
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef0123456"));
  XCTAssertFalse(santa::IsValidCDHash(@""));

  // Invalid - Too long
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef012345678"));
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef0123456789abcdef"));

  // Invalid - Bad chars
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef0123456g"));
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef0123456-"));
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef0123456 "));
  XCTAssertFalse(santa::IsValidCDHash(@"0123456789abcdef0123456789abcdef0123456:"));

  // Invalid - nil
  XCTAssertFalse(santa::IsValidCDHash(nil));

  // Invalid - Empty
  XCTAssertFalse(santa::IsValidCDHash(@""));
}

- (void)testSplitSigningID {
  // Valid TID:SID
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"ABCDE12345:com.example.app");
    XCTAssertEqualObjects(teamID, @"ABCDE12345");
    XCTAssertEqualObjects(signingID, @"com.example.app");
  }

  // Valid platform:SID
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"platform:com.apple.system");
    XCTAssertEqualObjects(teamID, @"platform");
    XCTAssertEqualObjects(signingID, @"com.apple.system");
  }

  // Valid - short ID
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"platform:a");
    XCTAssertEqualObjects(teamID, @"platform");
    XCTAssertEqualObjects(signingID, @"a");
  }

  // Valid - Mixed case
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"AbCdE12345:com.test.app");
    XCTAssertEqualObjects(teamID, @"AbCdE12345");
    XCTAssertEqualObjects(signingID, @"com.test.app");
  }

  // Invalid TID
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"ABCDE1234:com.example.app");  // Too short
    XCTAssertNil(teamID);
    XCTAssertNil(signingID);
  }

  // Invalid - Missing colon
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"ABCDE12345com.example.app");
    XCTAssertNil(teamID);
    XCTAssertNil(signingID);
  }

  // Invalid - No SID
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"ABCDE12345:");
    XCTAssertNil(teamID);
    XCTAssertNil(signingID);
  }

  // Invalid - nil
  {
    auto [teamID, signingID] = santa::SplitSigningID(nil);
    XCTAssertNil(teamID);
    XCTAssertNil(signingID);
  }

  // Invalid - Empty
  {
    auto [teamID, signingID] = santa::SplitSigningID(@"");
    XCTAssertNil(teamID);
    XCTAssertNil(signingID);
  }
}

@end
