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

#include "src/santad/KillingMachine.h"

#import <Foundation/Foundation.h>
#import <Kernel/kern/cs_blobs.h>
#import <XCTest/XCTest.h>
#import <arpa/inet.h>

#include <cstring>
#include <functional>
#include <vector>

// Forward declare the types and functions we need to test
namespace santa {

using CSOpsFunc = std::function<int(pid_t, unsigned int, void *, size_t)>;

static constexpr unsigned int kCsopStatus = 0;
static constexpr unsigned int kCsopCDHash = 5;
static constexpr unsigned int kCsopIdentity = 11;
static constexpr unsigned int kCsopTeamID = 14;

struct csops_blob {
  uint32_t type;
  uint32_t len;
  char data[];
};

extern bool TestCDHashMatcher(pid_t pid, NSString *cdhash, CSOpsFunc csops_func);
extern bool TestTeamIDMatcher(pid_t pid, NSString *teamID, CSOpsFunc csops_func);
extern bool TestSigningIDMatcher(pid_t pid, NSString *signingID, CSOpsFunc csops_func);
extern bool TestStatusFlagsMatcher(pid_t pid, uint32_t mask, CSOpsFunc csops_func);

}  // namespace santa

@interface KillingMachineTest : XCTestCase
@end

@implementation KillingMachineTest

- (void)testCDHashMatcherSuccess {
  std::vector<uint8_t> actualCDhash = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23,
                                       0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};

  NSString *cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  XCTAssertTrue(santa::TestCDHashMatcher(
      12345, cdhash, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopCDHash && usersize == actualCDhash.size()) {
          std::memcpy(useraddr, actualCDhash.data(), actualCDhash.size());
          return 0;
        }
        return -1;
      }));
}

- (void)testCDHashMatcherMismatch {
  std::vector<uint8_t> actualCDhash(CS_CDHASH_LEN, 0xff);

  NSString *cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  XCTAssertFalse(santa::TestCDHashMatcher(
      12345, cdhash, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopCDHash) {
          std::memcpy(useraddr, actualCDhash.data(), actualCDhash.size());
          return 0;
        }
        return -1;
      }));
}

- (void)testCDHashMatcherCSopsFailure {
  NSString *cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  XCTAssertFalse(santa::TestCDHashMatcher(
      12345, cdhash, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        return -1;
      }));
}

- (void)testTeamIDMatcherSuccess {
  NSString *teamID = @"ABCDE12345";

  XCTAssertTrue(santa::TestTeamIDMatcher(
      12345, teamID, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopTeamID) {
          santa::csops_blob *blob = (santa::csops_blob *)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + teamID.length);
          std::memcpy(blob->data, teamID.UTF8String, teamID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testTeamIDMatcherMismatch {
  NSString *teamID = @"ZZZZZ99999";

  XCTAssertFalse(santa::TestTeamIDMatcher(
      12345, @"ABCDE12345", ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopTeamID) {
          santa::csops_blob *blob = (santa::csops_blob *)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + teamID.length);
          std::memcpy(blob->data, teamID.UTF8String, teamID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testTeamIDMatcherCSopsFailure {
  XCTAssertFalse(santa::TestTeamIDMatcher(
      12345, @"ABCDE12345", ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        return -1;
      }));
}

- (void)testSigningIDMatcherSuccess {
  NSString *signingID = @"com.example.app";

  XCTAssertTrue(santa::TestSigningIDMatcher(
      12345, @"com.example.app", ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopIdentity) {
          santa::csops_blob *blob = (santa::csops_blob *)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + signingID.length);
          std::memcpy(blob->data, signingID.UTF8String, signingID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testSigningIDMatcherMismatch {
  NSString *signingID = @"com.other.app";

  XCTAssertFalse(santa::TestSigningIDMatcher(
      12345, @"com.example.app", ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopIdentity) {
          santa::csops_blob *blob = (santa::csops_blob *)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + signingID.length);
          std::memcpy(blob->data, signingID.UTF8String, signingID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testStatusFlagsMatcherSuccess {
  XCTAssertTrue(santa::TestStatusFlagsMatcher(
      12345, CS_PLATFORM_BINARY, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopStatus && usersize == sizeof(uint32_t)) {
          uint32_t *flags = (uint32_t *)useraddr;
          *flags = CS_PLATFORM_BINARY | CS_VALID;
          return 0;
        }
        return -1;
      }));
}

- (void)testStatusFlagsMatcherMismatch {
  XCTAssertFalse(santa::TestStatusFlagsMatcher(
      12345, CS_PLATFORM_BINARY, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        if (ops == santa::kCsopStatus && usersize == sizeof(uint32_t)) {
          uint32_t *flags = (uint32_t *)useraddr;
          *flags = CS_VALID;
          return 0;
        }
        return -1;
      }));
}

- (void)testStatusFlagsMatcherCSopsFailure {
  XCTAssertFalse(santa::TestStatusFlagsMatcher(
      12345, CS_PLATFORM_BINARY, ^(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
        return -1;
      }));
}

@end
