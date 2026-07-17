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

#import <XCTest/XCTest.h>

#include <sys/types.h>
#include <unistd.h>

#include <optional>
#include <string>

#include "Source/common/AccountLookup.h"

using santa::account::GroupNameForGID;
using santa::account::HomeDirForUID;
using santa::account::UIDForUsername;
using santa::account::UsernameForUID;

// A uid no real account is expected to occupy: below nobody ((uid_t)-2 ==
// 4294967294) and far above any allocated range. Used to exercise the
// "resolved cleanly, no such account" path.
static constexpr uid_t kAbsentUID = 4000000000;

// These tests query the live passwd/group database. They assert only against
// entries that exist on every macOS install (root/wheel) plus the current user,
// so they do not depend on any particular host configuration.
@interface AccountLookupTest : XCTestCase
@end

@implementation AccountLookupTest

- (void)testUsernameForUIDResolvesRoot {
  std::optional<std::string> name = UsernameForUID(0);
  XCTAssertTrue(name.has_value());
  if (!name.has_value()) {
    return;
  }
  XCTAssertTrue(*name == "root");
}

- (void)testUsernameForUIDAbsentReturnsNullopt {
  XCTAssertFalse(UsernameForUID(kAbsentUID).has_value());
}

- (void)testHomeDirForUIDResolvesRoot {
  std::optional<std::string> home = HomeDirForUID(0);
  XCTAssertTrue(home.has_value());
  if (!home.has_value()) {
    return;
  }
  XCTAssertFalse(home->empty());
  if (home->empty()) {
    return;
  }
  XCTAssertEqual(home->front(), '/');
}

- (void)testGroupNameForGIDResolvesWheel {
  std::optional<std::string> group = GroupNameForGID(0);
  XCTAssertTrue(group.has_value());
  if (!group.has_value()) {
    return;
  }
  XCTAssertTrue(*group == "wheel");
}

- (void)testUIDForUsernameResolvesRoot {
  std::optional<uid_t> uid = UIDForUsername("root");
  XCTAssertTrue(uid.has_value());
  if (!uid.has_value()) {
    return;
  }
  XCTAssertEqual(*uid, (uid_t)0);
}

- (void)testUIDForUsernameNonexistentReturnsNullopt {
  XCTAssertFalse(UIDForUsername("com.northpolesec.santa.no-such-user-xyzzy").has_value());
}

- (void)testUIDForUsernameEmptyReturnsNullopt {
  XCTAssertFalse(UIDForUsername("").has_value());
}

// A string_view is not required to be NUL-terminated; UIDForUsername must copy
// exactly the view's length rather than reading to the next NUL. Slice "rootXX"
// down to "root" to prove it does not read past the view.
- (void)testUIDForUsernameRespectsStringViewLength {
  std::string backing = "rootXX";
  std::string_view view(backing.data(), 4);  // "root"
  std::optional<uid_t> uid = UIDForUsername(view);
  XCTAssertTrue(uid.has_value());
  if (!uid.has_value()) {
    return;
  }
  XCTAssertEqual(*uid, (uid_t)0);
}

- (void)testRoundTripCurrentUser {
  uid_t me = getuid();
  std::optional<std::string> name = UsernameForUID(me);
  XCTAssertTrue(name.has_value());
  if (!name.has_value()) {
    return;
  }
  std::optional<uid_t> resolved = UIDForUsername(*name);
  XCTAssertTrue(resolved.has_value());
  if (!resolved.has_value()) {
    return;
  }
  XCTAssertEqual(*resolved, me);
}

@end
