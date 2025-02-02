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

using santa::DataWatchItemPolicy;
using santa::PairPathAndType;
using santa::ProcessWatchItemPolicy;
using santa::SetPairPathAndType;
using santa::SetSharedDataWatchItemPolicy;
using santa::SetSharedProcessWatchItemPolicy;
using santa::WatchItemPathType;
using santa::WatchItemProcess;
using santa::WatchItemRuleType;

@interface WatchItemPolicyTest : XCTestCase
@end

@implementation WatchItemPolicyTest

- (void)testProcessWatchItemPolicy {
  // Make sure the hash function for a WatchItemProcess covers all members
  WatchItemProcess proc{"proc_path_1", "com.example.proc", "PROCTEAMID", {}, "", std::nullopt};

  ProcessWatchItemPolicy pwip(
      "name", "ver", SetPairPathAndType{PairPathAndType{"path1", WatchItemPathType::kLiteral}},
      true, true, santa::WatchItemRuleType::kProcessesWithAllowedPaths, false, false, "", nil, nil,
      {proc});

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

- (void)testSetDataWatchItemPolicy {
  SetSharedDataWatchItemPolicy dataSet;

  auto sharedDataPolicy1 =
      std::make_shared<DataWatchItemPolicy>("name", "v1", "/foo", WatchItemPathType::kLiteral, true,
                                            true, WatchItemRuleType::kPathsWithAllowedProcesses);

  auto sharedDataPolicy2 =
      std::make_shared<DataWatchItemPolicy>("name", "v1", "/foo", WatchItemPathType::kLiteral, true,
                                            true, WatchItemRuleType::kPathsWithAllowedProcesses);

  auto sharedDataPolicy3 =
      std::make_shared<DataWatchItemPolicy>("name", "v1", "/bar", WatchItemPathType::kLiteral, true,
                                            true, WatchItemRuleType::kPathsWithAllowedProcesses);

  // Underlying pointers should be different
  XCTAssertNotEqual(sharedDataPolicy1, sharedDataPolicy2);
  XCTAssertNotEqual(sharedDataPolicy1, sharedDataPolicy3);
  XCTAssertNotEqual(sharedDataPolicy2, sharedDataPolicy3);

  // policies 1 and 2 have the same content, but policy 3 has a different path.
  // Check for expected equality.
  XCTAssertTrue(*sharedDataPolicy1 == *sharedDataPolicy2);
  XCTAssertFalse(*sharedDataPolicy1 == *sharedDataPolicy3);

  // Insert the same item multiple times, it should only be added once
  dataSet.insert(sharedDataPolicy1);
  dataSet.insert(sharedDataPolicy1);
  XCTAssertEqual(dataSet.size(), 1);

  // Adding the second policy should also not increase the
  // size since it is equal to policy 1.
  dataSet.insert(sharedDataPolicy2);
  XCTAssertEqual(dataSet.size(), 1);

  // Adding policy 3 should be allowed since it isn't equal to 1 or 2.
  dataSet.insert(sharedDataPolicy3);
  XCTAssertEqual(dataSet.size(), 2);
}

- (void)testSetSharedProcessWatchItemPolicy {
  // Test that hash/eq functions for set of shared pointers works as expected
  SetSharedProcessWatchItemPolicy procSet;

  auto sharedProcPolicy1 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", SetPairPathAndType{{"/foo", WatchItemPathType::kLiteral}}, true, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  auto sharedProcPolicy2 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", SetPairPathAndType{{"/foo", WatchItemPathType::kLiteral}}, true, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  auto sharedProcPolicy3 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", SetPairPathAndType{{"/bar", WatchItemPathType::kLiteral}}, true, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  // Underlying pointers should be different
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
