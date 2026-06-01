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

#include "Source/common/CodeSigningIdentifierUtils.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <string_view>

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

  // "platform" sentinel via the NSString overload + PlatformSentinel
  XCTAssertFalse(santa::IsValidTeamID(@"platform"));  // strict by default
  XCTAssertFalse(santa::IsValidTeamID(@"platform", santa::PlatformSentinel::kDisallowed));
  XCTAssertTrue(santa::IsValidTeamID(@"platform", santa::PlatformSentinel::kAllowed));
  // A real team ID is still accepted with kAllowed; nil still rejected.
  XCTAssertTrue(santa::IsValidTeamID(@"ABCDE12345", santa::PlatformSentinel::kAllowed));
  XCTAssertFalse(santa::IsValidTeamID(nil, santa::PlatformSentinel::kAllowed));
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

#pragma mark - string_view overload Tests

- (void)testIsValidTeamIDStringView {
  // Valid - 10 alphanumeric (strict default)
  XCTAssertTrue(santa::IsValidTeamID(std::string_view("ABCDE12345")));
  XCTAssertTrue(santa::IsValidTeamID(std::string_view("1234567890")));
  XCTAssertTrue(santa::IsValidTeamID(std::string_view("abcdefghij")));

  // Invalid - wrong length / bad chars / empty
  XCTAssertFalse(santa::IsValidTeamID(std::string_view("ABCDE1234")));
  XCTAssertFalse(santa::IsValidTeamID(std::string_view("ABCDE123456")));
  XCTAssertFalse(santa::IsValidTeamID(std::string_view("ABCDE-1234")));
  XCTAssertFalse(santa::IsValidTeamID(std::string_view("")));

  // "platform" rejected by default (strict), accepted with kAllowed
  XCTAssertFalse(santa::IsValidTeamID(std::string_view("platform")));
  XCTAssertFalse(
      santa::IsValidTeamID(std::string_view("platform"), santa::PlatformSentinel::kDisallowed));
  XCTAssertTrue(
      santa::IsValidTeamID(std::string_view("platform"), santa::PlatformSentinel::kAllowed));

  // kAllowed still rejects non-"platform" invalid tokens, still accepts valid team IDs
  XCTAssertFalse(
      santa::IsValidTeamID(std::string_view("platformX"), santa::PlatformSentinel::kAllowed));
  XCTAssertFalse(
      santa::IsValidTeamID(std::string_view("ABCDE-1234"), santa::PlatformSentinel::kAllowed));
  XCTAssertTrue(
      santa::IsValidTeamID(std::string_view("ABCDE12345"), santa::PlatformSentinel::kAllowed));
}

- (void)testIsValidCDHashStringView {
  // Valid
  XCTAssertTrue(santa::IsValidCDHash(std::string_view("0123456789abcdef0123456789abcdef01234567")));
  XCTAssertTrue(santa::IsValidCDHash(std::string_view("ABCDEF0123456789ABCDEF0123456789ABCDEF01")));

  // Invalid - length
  XCTAssertFalse(santa::IsValidCDHash(std::string_view("0123456789abcdef0123456789abcdef0123456")));
  XCTAssertFalse(
      santa::IsValidCDHash(std::string_view("0123456789abcdef0123456789abcdef012345678")));
  XCTAssertFalse(santa::IsValidCDHash(std::string_view("")));

  // Invalid - bad chars
  XCTAssertFalse(
      santa::IsValidCDHash(std::string_view("0123456789abcdef0123456789abcdef0123456g")));
}

- (void)testIsValidSigningIDStringView {
  // Valid TID:SID and platform:SID
  XCTAssertTrue(santa::IsValidSigningID(std::string_view("ABCDE12345:com.example.app")));
  XCTAssertTrue(santa::IsValidSigningID(std::string_view("platform:com.apple.system")));
  XCTAssertTrue(santa::IsValidSigningID(std::string_view("platform:a")));

  // Invalid TeamID
  XCTAssertFalse(santa::IsValidSigningID(std::string_view("ABCDE1234:com.example.app")));
  XCTAssertFalse(santa::IsValidSigningID(std::string_view("ABCDE-1234:com.example.app")));

  // Invalid - missing colon
  XCTAssertFalse(santa::IsValidSigningID(std::string_view("ABCDE12345com.example.app")));

  // Invalid - empty SID component
  XCTAssertFalse(santa::IsValidSigningID(std::string_view("ABCDE12345:")));
  XCTAssertFalse(santa::IsValidSigningID(std::string_view("platform:")));

  // Invalid - only colon / empty
  XCTAssertFalse(santa::IsValidSigningID(std::string_view(":")));
  XCTAssertFalse(santa::IsValidSigningID(std::string_view("")));
}

@end
