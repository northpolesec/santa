/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/common/Keychain.h"

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <XCTest/XCTest.h>

#import "Source/common/TestUtils.h"

using santa::keychain_utils::IsValidAccountName;
using santa::keychain_utils::IsValidDescription;
using santa::keychain_utils::IsValidServiceName;
using santa::keychain_utils::SecurityOSStatusToAbslStatus;

@interface KeychainTest : XCTestCase
@end

@implementation KeychainTest

- (void)testValidationUtils {
  XCTAssertFalse(IsValidAccountName(nil));
  XCTAssertFalse(IsValidAccountName(RepeatedString(@"A", 512)));
  XCTAssertTrue(IsValidAccountName(RepeatedString(@"A", 64)));

  XCTAssertFalse(IsValidDescription(nil));
  XCTAssertFalse(IsValidDescription(RepeatedString(@"A", 512)));
  XCTAssertTrue(IsValidDescription(RepeatedString(@"A", 64)));

  XCTAssertFalse(IsValidServiceName(nil));
  XCTAssertFalse(IsValidServiceName(RepeatedString(@"A", 512)));
  XCTAssertTrue(IsValidServiceName(RepeatedString(@"A", 64)));
}

- (void)testSecurityOSStatusToAbslStatus {
  absl::Status s;

  s = SecurityOSStatusToAbslStatus(errSecSuccess);
  XCTAssertTrue(s.ok());

  s = SecurityOSStatusToAbslStatus(errSecDuplicateItem);
  XCTAssertFalse(s.ok());
}

- (void)testFactoryFailure {
  santa::KeychainManager::Create(nil, kSecPreferencesDomainSystem);
}

@end
