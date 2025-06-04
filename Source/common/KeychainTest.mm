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
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace keychain = ::santa::keychain;

@interface KeychainTest : XCTestCase
@property NSString *testKeychainPath;
@end

@implementation KeychainTest

- (void)setUp {
  self.testKeychainPath =
      [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
}

- (void)tearDown {
  [[NSFileManager defaultManager] removeItemAtPath:self.testKeychainPath error:nil];
}

- (void)testValidationUtils {
  XCTAssertFalse(keychain::IsValidAccountName(nil));
  XCTAssertFalse(keychain::IsValidAccountName(RepeatedString(@"A", 512)));
  XCTAssertTrue(keychain::IsValidAccountName(RepeatedString(@"A", 64)));

  XCTAssertFalse(keychain::IsValidDescription(nil));
  XCTAssertFalse(keychain::IsValidDescription(RepeatedString(@"A", 512)));
  XCTAssertTrue(keychain::IsValidDescription(RepeatedString(@"A", 64)));

  XCTAssertFalse(keychain::IsValidServiceName(nil));
  XCTAssertFalse(keychain::IsValidServiceName(RepeatedString(@"A", 512)));
  XCTAssertTrue(keychain::IsValidServiceName(RepeatedString(@"A", 64)));
}

- (void)testSecurityOSStatusToAbslStatus {
  absl::Status s;

  s = keychain::SecurityOSStatusToAbslStatus(errSecSuccess);
  XCTAssertTrue(s.ok());

  s = keychain::SecurityOSStatusToAbslStatus(errSecDuplicateItem);
  XCTAssertFalse(s.ok());
}

- (void)testFactoryFailure {
  keychain::Manager::Create(nil, kSecPreferencesDomainSystem);
}

- (void)testKeychainItem {
  SecKeychainRef keychain;
  NSString *password = @"TestPassword";

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus osStatus = SecKeychainCreate(self.testKeychainPath.UTF8String, (UInt32)password.length,
                                        password.UTF8String, NO, NULL, &keychain);
#pragma clang diagnostic pop

  if (osStatus != errSecSuccess) {
    XCTFail(@"Failed to create keychain. Status: %d", osStatus);
    return;
  }
  XCTAssertNotEqual(keychain, nullptr);

  keychain::Manager mgr(@"com.norhpolesec.test.service", keychain);
  std::unique_ptr<keychain::Item> item1 = mgr.CreateItem(@"TestAccount1", @"Test keychain item");
  std::unique_ptr<keychain::Item> item2 = mgr.CreateItem(@"TestAccount2", @"Test keychain item");

  NSData *testData1 = [@"hello1" dataUsingEncoding:NSUTF8StringEncoding];
  NSData *testData2 = [@"hello2" dataUsingEncoding:NSUTF8StringEncoding];

  // Getting a non-existent item is a failure
  absl::StatusOr<NSData *> maybeItem = item1->Get();
  XCTAssertEqual(maybeItem.status().code(), absl::StatusCode::kNotFound);

  // Deleting a non-existent item is successful
  absl::Status status = item1->Delete();
  XCTAssertTrue(status.ok());

  status = item1->Store(testData1);
  XCTAssertTrue(status.ok());

  // Storing a duplicate item should succeed (it is first deleted)
  status = item1->Store(testData1);
  XCTAssertTrue(status.ok());

  // Store the second item
  status = item2->Store(testData2);
  XCTAssertTrue(status.ok());

  // Retrieve the first item and verify contents
  maybeItem = item1->Get();
  XCTAssertTrue(maybeItem.ok());
  XCTAssertEqualObjects(*maybeItem, testData1);

  // Retrieve the second item and verify contents
  maybeItem = item2->Get();
  XCTAssertTrue(maybeItem.ok());
  XCTAssertEqualObjects(*maybeItem, testData2);
}

@end
