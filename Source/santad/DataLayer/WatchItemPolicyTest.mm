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

#include "Source/santad/DataLayer/WatchItemPolicy.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <memory>

#include "absl/container/flat_hash_set.h"

using santa::PathAndTypePair;
using santa::PathAndTypeVec;
using santa::ProcessWatchItemPolicy;
using santa::SharedPtrProcessWatchItemPolicyEqual;
using santa::SharedPtrProcessWatchItemPolicyHash;
using santa::WatchItemPathType;
using santa::WatchItemProcess;
using santa::WatchItemRuleType;

@interface WatchItemPolicyTest : XCTestCase
@end

@implementation WatchItemPolicyTest

- (void)testProcessWatchItemPolicy {
  // Make sure the hash function for a WatchItemProcess covers all members
  WatchItemProcess proc{"proc_path_1", "com.example.proc", "PROCTEAMID", {}, "", std::nullopt};

  ProcessWatchItemPolicy pwip("name", "ver",
                              PathAndTypeVec{PathAndTypePair{"path1", WatchItemPathType::kLiteral}},
                              true, true, santa::WatchItemRuleType::kProcessesWithAllowedPaths,
                              false, false, "", nil, nil, {proc});

  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 1);

  proc.signing_id = "abc";
  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 2);

  proc.binary_path = "abc";
  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 3);

  proc.team_id = "abc";
  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 4);

  proc.platform_binary = true;
  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 5);

  proc.certificate_sha256 = "abc";
  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 6);

  proc.cdhash = {1};
  pwip.processes.insert(proc);
  pwip.processes.insert(proc);
  XCTAssertEqual(pwip.processes.size(), 7);
}

- (void)testSetSharedProcessWatchItemPolicy {
  // Test that hash/eq funcitons for set of shared pointers works as expected
  absl::flat_hash_set<std::shared_ptr<ProcessWatchItemPolicy>, SharedPtrProcessWatchItemPolicyHash,
                      SharedPtrProcessWatchItemPolicyEqual>
      procSet;

  auto sharedProcPolicy1 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", PathAndTypeVec{{"/foo", WatchItemPathType::kLiteral}}, true, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  auto sharedProcPolicy2 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", PathAndTypeVec{{"/foo", WatchItemPathType::kLiteral}}, true, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  auto sharedProcPolicy3 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", PathAndTypeVec{{"/bar", WatchItemPathType::kLiteral}}, true, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  // UNderlying pointers should be different
  XCTAssertNotEqual(sharedProcPolicy1, sharedProcPolicy2);
  XCTAssertNotEqual(sharedProcPolicy1, sharedProcPolicy3);
  XCTAssertNotEqual(sharedProcPolicy2, sharedProcPolicy3);

  // policies 1 and 2 have the same content, but policy 3 has a different path.
  // Check for expected equality.
  XCTAssertTrue(*sharedProcPolicy1 == *sharedProcPolicy2);
  XCTAssertFalse(*sharedProcPolicy1 == *sharedProcPolicy3);

  // Insert the same item multiple times, it should only be added once
  procSet.insert(sharedProcPolicy1);
  procSet.insert(sharedProcPolicy1);
  XCTAssertEqual(procSet.size(), 1);

  // Adding the second policy should also not increase the
  // size since it is equal to policy 1.
  procSet.insert(sharedProcPolicy2);
  XCTAssertEqual(procSet.size(), 1);

  // Adding policy 3 should be allowed since it isn't equal to 1 or 2.
  procSet.insert(sharedProcPolicy3);
  XCTAssertEqual(procSet.size(), 2);
}

@end
