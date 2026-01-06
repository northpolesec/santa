/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
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

#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include <sys/syslimits.h>
#include <unistd.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <string_view>
#include <variant>
#include <vector>

#include "src/common/TestUtils.h"
#import "src/common/Unit.h"
#include "src/common/faa/WatchItemPolicy.h"
#include "src/common/faa/WatchItems.h"
#include "absl/container/flat_hash_set.h"

using santa::DataWatchItemPolicy;
using santa::DataWatchItems;
using santa::IterateTargetsBlock;
using santa::kWatchItemPolicyDefaultAllowReadAccess;
using santa::kWatchItemPolicyDefaultAuditOnly;
using santa::kWatchItemPolicyDefaultPathType;
using santa::kWatchItemPolicyDefaultRuleType;
using santa::LookupPolicyBlock;
using santa::PairPathAndType;
using santa::ProcessWatchItemPolicy;
using santa::SetPairPathAndType;
using santa::SetSharedDataWatchItemPolicy;
using santa::SetSharedProcessWatchItemPolicy;
using santa::SetWatchItemProcess;
using santa::Unit;
using santa::WatchItemPathType;
using santa::WatchItemProcess;
using santa::WatchItemsState;

namespace santa {

extern bool ParseConfig(NSDictionary *config, SetSharedDataWatchItemPolicy *data_policies,
                        SetSharedProcessWatchItemPolicy *proc_policies, uint64_t *rules_loaded,
                        NSError **err);
extern bool IsWatchItemNameValid(id key, NSError **err);
extern bool ParseConfigSingleWatchItem(NSString *name, std::string_view policy_version,
                                       NSDictionary *watch_item,
                                       SetSharedDataWatchItemPolicy *data_policies,
                                       SetSharedProcessWatchItemPolicy *proc_policies,
                                       NSError **err);
extern std::variant<Unit, SetPairPathAndType> VerifyConfigWatchItemPaths(NSArray<id> *paths,
                                                                         NSError **err);
std::variant<Unit, SetWatchItemProcess> VerifyConfigWatchItemProcesses(NSDictionary *watch_item,
                                                                       NSError **err);
extern std::optional<WatchItemRuleType> GetRuleType(NSString *rule_type);
extern std::vector<std::string> FindMatches(NSString *path);

class WatchItemsPeer : public WatchItems {
 public:
  WatchItemsPeer(NSString *config_path, dispatch_queue_t q,
                 void (^periodic_task_complete_f)(void) = nullptr)
      : WatchItems(MakeKey(), WatchItems::DataSource::kDetachedConfig, config_path, nil, q,
                   periodic_task_complete_f) {}

  WatchItemsPeer(NSDictionary *config, dispatch_queue_t q,
                 void (^periodic_task_complete_f)(void) = nullptr)
      : WatchItems(MakeKey(), WatchItems::DataSource::kEmbeddedConfig, nil, config, q,
                   periodic_task_complete_f) {}

  using WatchItems::ForceSetIntervalForTestingUnsafe;
  using WatchItems::ReloadConfig;
  using WatchItems::SetConfig;
  using WatchItems::SetConfigPath;

  using WatchItems::config_path_;
  using WatchItems::embedded_config_;
};

}  // namespace santa

using santa::FindMatches;
using santa::GetRuleType;
using santa::IsWatchItemNameValid;
using santa::ParseConfig;
using santa::ParseConfigSingleWatchItem;
using santa::VerifyConfigWatchItemPaths;
using santa::VerifyConfigWatchItemProcesses;
using santa::WatchItemPolicyBase;
using santa::WatchItemsPeer;

static constexpr std::string_view kBadPolicyName("__BAD_NAME__");
static constexpr std::string_view kBadPolicyPath("__BAD_PATH__");
static constexpr std::string_view kVersion("v0.1");

NSString *MakeTestDirPath(NSString *target, NSString *root = nil) {
  if (![target hasPrefix:@"/"]) {
    target = [NSString stringWithFormat:@"/%@", target];
  }

  return root ? [NSString stringWithFormat:@"%@%@", root, target]
              : [NSString stringWithFormat:@"%@", target];
};

static std::string MakePathTarget(std::string path, NSString *root = nil) {
  return root ? std::string(root.UTF8String) + "/" + path : path;
}

static std::shared_ptr<DataWatchItemPolicy> MakeBadPolicy() {
  return std::make_shared<DataWatchItemPolicy>(kBadPolicyName, kVersion, kBadPolicyPath);
}

static NSMutableDictionary *WrapWatchItemsConfig(NSDictionary *config) {
  return [@{@"Version" : @(kVersion.data()), @"WatchItems" : [config mutableCopy]} mutableCopy];
}

struct BlockGenResult {
  std::vector<std::optional<std::shared_ptr<WatchItemPolicyBase>>> &targetPolicies;
  IterateTargetsBlock(^blockGen)(std::vector<std::string>);
};

BlockGenResult CreatePolicyBlockGen() {
  auto targetPolicies =
      std::make_shared<std::vector<std::optional<std::shared_ptr<WatchItemPolicyBase>>>>();

  auto blockGen = ^IterateTargetsBlock(std::vector<std::string> paths) {
    targetPolicies->clear();
    return ^(santa::LookupPolicyBlock block) {
      for (const auto &path : paths) {
        targetPolicies->push_back(block(path));
      }
    };
  };

  return {*targetPolicies, blockGen};
}

@interface WatchItemsTest : XCTestCase
@property NSFileManager *fileMgr;
@property NSString *testDir;
@property dispatch_queue_t q;
@end

@implementation WatchItemsTest

- (void)setUp {
  self.fileMgr = [NSFileManager defaultManager];
  self.testDir =
      [NSString stringWithFormat:@"%@santa-watchitems-%d", NSTemporaryDirectory(), getpid()];

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);

  self.q = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
  XCTAssertNotNil(self.q);
}

- (void)tearDown {
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:nil]);
}

- (void)createTestDirStructure:(NSArray *)fs rootedAt:(NSString *)root {
  NSString *origCwd = [self.fileMgr currentDirectoryPath];
  XCTAssertNotNil(origCwd);
  XCTAssertTrue([self.fileMgr changeCurrentDirectoryPath:root]);

  for (id item in fs) {
    if ([item isKindOfClass:[NSString class]]) {
      XCTAssertTrue([self.fileMgr createFileAtPath:item contents:nil attributes:nil]);
    } else if ([item isKindOfClass:[NSDictionary class]]) {
      for (id dir in item) {
        XCTAssertTrue([item[dir] isKindOfClass:[NSArray class]]);
        XCTAssertTrue([self.fileMgr createDirectoryAtPath:dir
                              withIntermediateDirectories:NO
                                               attributes:nil
                                                    error:nil]);

        [self createTestDirStructure:item[dir] rootedAt:dir];
      }
    } else {
      XCTFail("Unexpected dir structure item: %@: %@", item, [item class]);
    }
  }

  XCTAssertTrue([self.fileMgr changeCurrentDirectoryPath:origCwd]);
}

- (void)createTestDirStructure:(NSArray *)fs {
  [self createTestDirStructure:fs rootedAt:self.testDir];
}

- (void)testGetRuleType {
  std::optional<santa::WatchItemRuleType> ruleType;

  ruleType = GetRuleType(@"PathsWithAllowedProcesses");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kPathsWithAllowedProcesses);

  ruleType = GetRuleType(@"PAthSWITHallowedProCesSES");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kPathsWithAllowedProcesses);

  ruleType = GetRuleType(@"PathsWithDeniedProcesses");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kPathsWithDeniedProcesses);

  ruleType = GetRuleType(@"paTHswIThdENieDProCEssES");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kPathsWithDeniedProcesses);

  ruleType = GetRuleType(@"ProcessesWithDeniedPaths");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kProcessesWithDeniedPaths);

  ruleType = GetRuleType(@"ProCEssESwIThdENieDpaTHs");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kProcessesWithDeniedPaths);

  ruleType = GetRuleType(@"ProcessesWithAllowedPaths");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kProcessesWithAllowedPaths);

  ruleType = GetRuleType(@"ProCEssESwIThaLLowEDpaTHs");
  XCTAssertTrue(ruleType.has_value());
  XCTAssertEqual(ruleType.value(), santa::WatchItemRuleType::kProcessesWithAllowedPaths);

  ruleType = GetRuleType(@"NotARealRuleType");
  XCTAssertFalse(ruleType.has_value());
}

- (void)testReloadScenarios {
  [self createTestDirStructure:@[
    @{
      @"a" : @[ @"f1", @"f2" ],
    },
    @{
      @"b" : @[ @"f1" ],
    },
  ]];

  NSDictionary *aAllFilesPolicy =
      @{kWatchItemConfigKeyPaths : @[ MakeTestDirPath(@"a/*", self.testDir) ]};
  NSDictionary *configAllFilesOriginalA =
      WrapWatchItemsConfig(@{@"all_files_orig" : aAllFilesPolicy});
  NSDictionary *configAllFilesRenameA =
      WrapWatchItemsConfig(@{@"all_files_rename" : aAllFilesPolicy});
  NSDictionary *configAllFilesOriginalB = WrapWatchItemsConfig(@{
    @"all_files_orig" : @{kWatchItemConfigKeyPaths : @[ MakeTestDirPath(@"b/*", self.testDir) ]}
  });

  auto [targetPolicies, blockGen] = CreatePolicyBlockGen();
  std::string af1Path = MakePathTarget("f1", [self.testDir stringByAppendingPathComponent:@"a"]);
  std::string af2Path = MakePathTarget("f2", [self.testDir stringByAppendingPathComponent:@"a"]);
  std::string bf2Path = MakePathTarget("f2", [self.testDir stringByAppendingPathComponent:@"b"]);

  // Changes in config dictionary will update policy info even if the
  // filesystem didn't change.
  {
    auto watchItems = std::make_shared<WatchItemsPeer>((NSString *)nil, nullptr);
    watchItems->ReloadConfig(configAllFilesOriginalA);

    watchItems->FindPoliciesForTargets(blockGen({af1Path}));
    XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_orig");

    watchItems->ReloadConfig(configAllFilesRenameA);
    watchItems->FindPoliciesForTargets(blockGen({af1Path}));
    XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_rename");

    watchItems->FindPoliciesForTargets(blockGen({af1Path}));
    XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_rename");
  }

  // Changes to fileystem structure are reflected when a config is reloaded
  {
    auto watchItems = std::make_shared<WatchItemsPeer>((NSString *)nil, nullptr);
    watchItems->ReloadConfig(configAllFilesOriginalA);

    watchItems->FindPoliciesForTargets(blockGen({af2Path}));
    XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                          "all_files_orig");

    watchItems->ReloadConfig(configAllFilesOriginalB);
    watchItems->FindPoliciesForTargets(blockGen({bf2Path}));
    XCTAssertFalse(targetPolicies[0].has_value());
  }
}

- (void)testPeriodicTask {
  // Ensure watch item policy memory is properly handled
  [self createTestDirStructure:@[ @"f1", @"f2", @"weird1" ]];

  NSDictionary *fFiles = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : MakeTestDirPath(@"f?", self.testDir),
      kWatchItemConfigKeyPathsIsPrefix : @(NO),
    } ]
  };
  NSDictionary *weirdFiles = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : MakeTestDirPath(@"weird?", self.testDir),
      kWatchItemConfigKeyPathsIsPrefix : @(NO),
    } ]
  };

  NSString *configFile = @"config.plist";
  NSDictionary *firstConfig = WrapWatchItemsConfig(@{@"f_files" : fFiles});
  NSDictionary *secondConfig =
      WrapWatchItemsConfig(@{@"f_files" : fFiles, @"weird_files" : weirdFiles});

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto watchItems = std::make_shared<WatchItemsPeer>(configFile, self.q, ^{
    dispatch_semaphore_signal(sema);
  });

  // Move into the base test directory and write the config to disk
  XCTAssertTrue([firstConfig writeToFile:configFile atomically:YES]);

  auto [targetPolicies, blockGen] = CreatePolicyBlockGen();
  std::string f1Path = MakePathTarget("f1", self.testDir);
  std::string weird1Path = MakePathTarget("weird1", self.testDir);

  // Ensure no policy has been loaded yet
  watchItems->FindPoliciesForTargets(blockGen({f1Path}));
  XCTAssertFalse(targetPolicies[0].has_value());
  watchItems->FindPoliciesForTargets(blockGen({weird1Path}));
  XCTAssertFalse(targetPolicies[0].has_value());

  // Begin the periodic task
  watchItems->ForceSetIntervalForTestingUnsafe(1);
  watchItems->StartTimer();

  // The first run of the task starts immediately
  // Wait for the first iteration and check for the expected policy
  XCTAssertSemaTrue(sema, 5, "Periodic task did not complete within expected window");
  watchItems->FindPoliciesForTargets(blockGen({f1Path}));
  XCTAssertTrue(targetPolicies[0].has_value());
  watchItems->FindPoliciesForTargets(blockGen({weird1Path}));
  XCTAssertFalse(targetPolicies[0].has_value());

  // Write the config update
  XCTAssertTrue([secondConfig writeToFile:configFile atomically:YES]);

  // Wait for the new config to be loaded and check for the new expected policies
  XCTAssertSemaTrue(sema, 5, "Periodic task did not complete within expected window");
  watchItems->FindPoliciesForTargets(blockGen({f1Path}));
  XCTAssertTrue(targetPolicies[0].has_value());
  watchItems->FindPoliciesForTargets(blockGen({weird1Path}));
  XCTAssertTrue(targetPolicies[0].has_value());
}

- (void)testPolicyLookup {
  // Test multiple, more comprehensive policies before/after config reload
  // Note: This test doesn't use glob chars, so no need to create FS artifacts since
  // paths that don't require expansion will always be watched.
  NSMutableDictionary *config = WrapWatchItemsConfig(@{
    @"foo_subdir" : @{
      kWatchItemConfigKeyPaths : @[ @{
        kWatchItemConfigKeyPathsPath : @"/foo",
        kWatchItemConfigKeyPathsIsPrefix : @(YES),
      } ]
    }
  });

  auto watchItems = std::make_shared<WatchItemsPeer>((NSString *)nil, nullptr);
  auto [targetPolicies, blockGen] = CreatePolicyBlockGen();

  // Resultant vector is same size as input vector
  // Initially nothing should be in the map
  std::vector<std::string> paths;
  watchItems->FindPoliciesForTargets(blockGen(paths));
  XCTAssertEqual(targetPolicies.size(), 0);
  paths.push_back(MakePathTarget("/foo"));
  watchItems->FindPoliciesForTargets(blockGen(paths));
  XCTAssertEqual(targetPolicies.size(), 1);
  XCTAssertFalse(targetPolicies[0].has_value());
  paths.push_back(MakePathTarget("/baz"));
  watchItems->FindPoliciesForTargets(blockGen(paths));
  XCTAssertEqual(targetPolicies.size(), 2);

  // Load the initial config
  watchItems->ReloadConfig(config);

  {
    // Test expected values with the inital policy
    const std::map<std::string, std::string_view> pathToPolicyName = {
        {"/foo", "foo_subdir"},
        {"/foo/bar.txt.tmp", "foo_subdir"},
        {"/foo/bar.txt", "foo_subdir"},
        {"/does/not/exist", kBadPolicyName},
    };

    for (const auto &kv : pathToPolicyName) {
      watchItems->FindPoliciesForTargets(blockGen({MakePathTarget(kv.first)}));
      XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->version.data(),
                            kVersion.data());
      XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }

    // Test multiple lookup
    watchItems->FindPoliciesForTargets(
        blockGen({MakePathTarget("/foo"), MakePathTarget("/does/not/exist")}));
    XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(), "foo_subdir");
    XCTAssertFalse(targetPolicies[1].has_value());
  }

  // Add a new policy and reload the config
  NSDictionary *barTxtFilePolicy = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : @"/foo/bar.txt",
      kWatchItemConfigKeyPathsIsPrefix : @(NO),
    } ]
  };
  [config[@"WatchItems"] setObject:barTxtFilePolicy forKey:@"bar_txt"];

  // Load the updated config
  watchItems->ReloadConfig(config);

  {
    // Test expected values with the updated policy
    const std::map<std::string, std::string_view> pathToPolicyName = {
        {"/foo", "foo_subdir"},
        {"/foo/bar.txt.tmp", "foo_subdir"},
        {"/foo/bar.txt", "bar_txt"},
        {"/does/not/exist", kBadPolicyName},
    };

    for (const auto &kv : pathToPolicyName) {
      watchItems->FindPoliciesForTargets(blockGen({MakePathTarget(kv.first)}));
      XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }
  }

  // Add a catch-all policy that should only affect the previously non-matching path
  NSDictionary *catchAllFilePolicy = @{
    kWatchItemConfigKeyPaths : @[ @{
      kWatchItemConfigKeyPathsPath : @"/",
      kWatchItemConfigKeyPathsIsPrefix : @(YES),
    } ]
  };
  [config[@"WatchItems"] setObject:catchAllFilePolicy forKey:@"slash_everything"];

  // Load the updated config
  watchItems->ReloadConfig(config);

  {
    // Test expected values with the catch-all policy
    const std::map<std::string, std::string_view> pathToPolicyName = {
        {"/foo", "foo_subdir"},
        {"/foo/bar.txt.tmp", "foo_subdir"},
        {"/foo/bar.txt", "bar_txt"},
        {"/does/not/exist", "slash_everything"},
    };

    for (const auto &kv : pathToPolicyName) {
      watchItems->FindPoliciesForTargets(blockGen({MakePathTarget(kv.first)}));
      XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }
  }

  // Now remove the foo_subdir rule, previous matches should fallback to the catch-all
  [config[@"WatchItems"] removeObjectForKey:@"foo_subdir"];
  watchItems->ReloadConfig(config);

  {
    // Test expected values with the foo_subdir policy removed
    const std::map<std::string, std::string_view> pathToPolicyName = {
        {"/foo", "slash_everything"},
        {"/foo/bar.txt.tmp", "slash_everything"},
        {"/foo/bar.txt", "bar_txt"},
        {"/does/not/exist", "slash_everything"},
    };

    for (const auto &kv : pathToPolicyName) {
      watchItems->FindPoliciesForTargets(blockGen({MakePathTarget(kv.first)}));
      XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(),
                            kv.second.data());
    }
  }
}

- (void)testVerifyConfigWatchItemPaths {
  std::variant<Unit, SetPairPathAndType> path_list;
  NSError *err;

  // Test no paths specified
  path_list = VerifyConfigWatchItemPaths(@[], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test invalid types in paths array
  path_list = VerifyConfigWatchItemPaths(@[ @(0) ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array with long string
  path_list = VerifyConfigWatchItemPaths(@[ RepeatedString(@"A", PATH_MAX + 1) ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array dictionary with missing required key
  path_list = VerifyConfigWatchItemPaths(@[ @{@"FakePath" : @"A"} ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array dictionary with long string
  path_list = VerifyConfigWatchItemPaths(
      @[ @{kWatchItemConfigKeyPathsPath : RepeatedString(@"A", PATH_MAX + 1)} ], &err);
  XCTAssertTrue(std::holds_alternative<Unit>(path_list));

  // Test path array dictionary with default path type
  path_list = VerifyConfigWatchItemPaths(@[ @{kWatchItemConfigKeyPathsPath : @"A"} ], &err);
  XCTAssertTrue(std::holds_alternative<SetPairPathAndType>(path_list));
  XCTAssertEqual(std::get<SetPairPathAndType>(path_list).size(), 1);
  XCTAssertCStringEqual((*std::get<SetPairPathAndType>(path_list).begin()).first.c_str(), "A");
  XCTAssertEqual((*std::get<SetPairPathAndType>(path_list).begin()).second,
                 kWatchItemPolicyDefaultPathType);

  // Test path array dictionary with custom path type
  path_list = VerifyConfigWatchItemPaths(
      @[ @{kWatchItemConfigKeyPathsPath : @"A", kWatchItemConfigKeyPathsIsPrefix : @(YES)} ], &err);
  XCTAssertTrue(std::holds_alternative<SetPairPathAndType>(path_list));
  XCTAssertEqual(std::get<SetPairPathAndType>(path_list).size(), 1);
  XCTAssertCStringEqual((*std::get<SetPairPathAndType>(path_list).begin()).first.c_str(), "A");
  XCTAssertEqual((*std::get<SetPairPathAndType>(path_list).begin()).second,
                 WatchItemPathType::kPrefix);
}

- (void)testVerifyConfigWatchItemProcesses {
  std::variant<Unit, SetWatchItemProcess> proc_list;
  NSError *err;

  // Non-existent process list parses successfully, but has no items
  proc_list = VerifyConfigWatchItemProcesses(@{}, &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 0);

  // Process list fails to parse if contains non-array type
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @""}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @(0)}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @{}}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @[]}, &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));

  // Test a process dictionary with no valid attributes set
  proc_list = VerifyConfigWatchItemProcesses(@{kWatchItemConfigKeyProcesses : @[ @{} ]}, &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test BinaryPath length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesBinaryPath : RepeatedString(@"A", PATH_MAX + 1)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid BinaryPath
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesBinaryPath : @"mypath"} ]},
      &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("mypath", "", "", {}, "", false));

  // Test SigningID length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesSigningID : RepeatedString(@"A", 513)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid SigningID, but no TeamID set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesSigningID : @"com.northpolesec.test"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid SigningID and TeamID
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesSigningID : @"com.northpolesec.test",
      kWatchItemConfigKeyProcessesTeamID : @"ABCDE12345",
    } ],
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "com.northpolesec.test", "ABCDE12345", {}, "", false));
  XCTAssertEqual((*std::get<SetWatchItemProcess>(proc_list).begin()).signing_id_wildcard_pos,
                 std::string::npos);

  // Test SigningID prefix but PlatformBinary or TeamID are not set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesPlatformBinary : @(NO),
      kWatchItemConfigKeyProcessesSigningID : @"com.northpolesec.*"
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test SigningID wildcard but neither PlatformBinary nor TeamID are not set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesPlatformBinary : @(NO),
      kWatchItemConfigKeyProcessesSigningID : @"com.*.test"
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test SigningID with multiple wildcards but neither PlatformBinary nor TeamID are not set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesPlatformBinary : @(NO),
      kWatchItemConfigKeyProcessesSigningID : @"com.*.*test"
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test SigningID prefix with PlatformBinary set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesPlatformBinary : @(YES),
      kWatchItemConfigKeyProcessesSigningID : @"com.northpolesec.*"
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "com.northpolesec.*", "", {}, "", true));
  XCTAssertNotEqual((*std::get<SetWatchItemProcess>(proc_list).begin()).signing_id_wildcard_pos,
                    std::string::npos);

  // Test SigningID prefix with TeamID set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesTeamID : @"myvalidtid",
      kWatchItemConfigKeyProcessesSigningID : @"com.*.test"
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "com.*.test", "myvalidtid", {}, "", false));
  XCTAssertNotEqual((*std::get<SetWatchItemProcess>(proc_list).begin()).signing_id_wildcard_pos,
                    std::string::npos);

  // Test SigningID with TeamID prefix
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesSigningID : @"ABCDE12345:com.northpolesec.*"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "com.northpolesec.*", "ABCDE12345", {}, "", false));
  XCTAssertNotEqual((*std::get<SetWatchItemProcess>(proc_list).begin()).signing_id_wildcard_pos,
                    std::string::npos);

  // Test SigningID with invalid TeamID prefix length (long)
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesSigningID : @"ABCDE123456:com.northpolesec.*"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test SigningID with invalid TeamID prefix length (short)
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesSigningID : @"ABCDE1234:com.northpolesec.*"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test SigningID with platform TeamID prefix
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesSigningID : @"platform:com.northpolesec.*"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "com.northpolesec.*", "", {}, "", true));
  XCTAssertNotEqual((*std::get<SetWatchItemProcess>(proc_list).begin()).signing_id_wildcard_pos,
                    std::string::npos);

  // Test SigningID with multiple wildcards and TeamID set
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesTeamID : @"myvalidtid",
      kWatchItemConfigKeyProcessesSigningID : @"com.*.*test"
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "com.*.*test", "myvalidtid", {}, "", false));
  XCTAssertNotEqual((*std::get<SetWatchItemProcess>(proc_list).begin()).signing_id_wildcard_pos,
                    std::string::npos);

  // Test TeamID length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesTeamID : @"LongerThanExpectedTeamID"} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test TeamID short, but not "platform"
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesTeamID : @"Blatform"} ]},
      &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid TeamID
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesTeamID : @"myvalidtid"} ]},
      &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "", "myvalidtid", {}, "", false));

  // Test valid TeamID - "platform"
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesTeamID : @"pLaTfOrM"} ]},
      &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "", "", {}, "", true));

  // Test CDHash length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesCDHash : RepeatedString(@"A", CS_CDHASH_LEN * 2 + 1)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test CDHash hex-only
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses :
        @[ @{kWatchItemConfigKeyProcessesCDHash : RepeatedString(@"Z", CS_CDHASH_LEN * 2)} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid CDHash
  NSString *cdhash = RepeatedString(@"A", CS_CDHASH_LEN * 2);
  std::vector<uint8_t> cdhashBytes(cdhash.length / 2);
  std::fill(cdhashBytes.begin(), cdhashBytes.end(), 0xAA);
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesCDHash : cdhash} ]}, &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "", "", cdhashBytes, "", false));

  // Test Cert Hash length limits
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesCertificateSha256 :
          RepeatedString(@"A", CC_SHA256_DIGEST_LENGTH * 2 + 1)
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test Cert Hash hex-only
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{
      kWatchItemConfigKeyProcessesCertificateSha256 :
          RepeatedString(@"Z", CC_SHA256_DIGEST_LENGTH * 2)
    } ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid Cert Hash
  NSString *certHash = RepeatedString(@"A", CC_SHA256_DIGEST_LENGTH * 2);
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesCertificateSha256 : certHash} ]
  },
                                             &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "", "", {}, [certHash UTF8String], false));

  // Test valid invalid PlatformBinary type
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesPlatformBinary : @"YES"} ]},
      &err);
  XCTAssertTrue(std::holds_alternative<Unit>(proc_list));

  // Test valid valid PlatformBinary
  proc_list = VerifyConfigWatchItemProcesses(
      @{kWatchItemConfigKeyProcesses : @[ @{kWatchItemConfigKeyProcessesPlatformBinary : @(YES)} ]},
      &err);
  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 1);
  XCTAssertEqual(*std::get<SetWatchItemProcess>(proc_list).begin(),
                 WatchItemProcess("", "", "", {}, "", true));

  // Test valid multiple attributes, multiple procs
  proc_list = VerifyConfigWatchItemProcesses(@{
    kWatchItemConfigKeyProcesses : @[
      @{
        kWatchItemConfigKeyProcessesBinaryPath : @"mypath1",
        kWatchItemConfigKeyProcessesSigningID : @"com.northpolesec.test1",
        kWatchItemConfigKeyProcessesTeamID : @"validtid_1",
        kWatchItemConfigKeyProcessesCDHash : cdhash,
        kWatchItemConfigKeyProcessesCertificateSha256 : certHash,
        kWatchItemConfigKeyProcessesPlatformBinary : @(NO),
      },
      @{
        kWatchItemConfigKeyProcessesBinaryPath : @"mypath2",
        kWatchItemConfigKeyProcessesSigningID : @"com.northpolesec.test2",
        kWatchItemConfigKeyProcessesTeamID : @"validtid_2",
        kWatchItemConfigKeyProcessesCDHash : cdhash,
        kWatchItemConfigKeyProcessesCertificateSha256 : certHash,
        kWatchItemConfigKeyProcessesPlatformBinary : @(NO),
      },
    ]
  },
                                             &err);

  SetWatchItemProcess expectedProcs{
      WatchItemProcess("mypath1", "com.northpolesec.test1", "validtid_1", cdhashBytes,
                       [certHash UTF8String], false),
      WatchItemProcess("mypath2", "com.northpolesec.test2", "validtid_2", cdhashBytes,
                       [certHash UTF8String], false)};

  XCTAssertTrue(std::holds_alternative<SetWatchItemProcess>(proc_list));
  XCTAssertEqual(std::get<SetWatchItemProcess>(proc_list).size(), 2);

  // Ensure each of the procs in the set is in the set of expected procs
  for (const auto &p : std::get<SetWatchItemProcess>(proc_list)) {
    XCTAssertEqual(expectedProcs.count(p), 1);
  }
}

- (void)testIsWatchItemNameValid {
  // Only legal C identifiers should be accepted
  XCTAssertFalse(IsWatchItemNameValid(nil, nil));
  XCTAssertFalse(IsWatchItemNameValid(@"", nil));
  XCTAssertFalse(IsWatchItemNameValid(@"1abc", nil));
  XCTAssertFalse(IsWatchItemNameValid(@"abc-1234", nil));
  XCTAssertFalse(IsWatchItemNameValid(@"a=b", nil));
  XCTAssertFalse(IsWatchItemNameValid(@"a!b", nil));
  XCTAssertFalse(IsWatchItemNameValid(@(1), nil));
  XCTAssertFalse(IsWatchItemNameValid(@[], nil));
  XCTAssertFalse(IsWatchItemNameValid(@{}, nil));
  XCTAssertFalse(IsWatchItemNameValid(RepeatedString(@"A", 64), nil));

  XCTAssertTrue(IsWatchItemNameValid(@"_", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"_1", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"_1_", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"abc", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"A", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"A_B", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"FooName", nil));
  XCTAssertTrue(IsWatchItemNameValid(@"bar_Name", nil));
  XCTAssertTrue(IsWatchItemNameValid(RepeatedString(@"A", 63), nil));
}

- (void)testParseConfig {
  NSError *err;
  SetSharedDataWatchItemPolicy data_policies;
  SetSharedProcessWatchItemPolicy proc_policies;
  uint64_t num_rules;

  // Ensure top level keys must be correct types if they exist
  XCTAssertTrue(ParseConfig(@{}, &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(num_rules, 0);
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @(0)}, &data_policies, &proc_policies,
                             &num_rules, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @{}}, &data_policies, &proc_policies,
                             &num_rules, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @[]}, &data_policies, &proc_policies,
                             &num_rules, &err));
  XCTAssertFalse(ParseConfig(@{kWatchItemConfigKeyVersion : @""}, &data_policies, &proc_policies,
                             &num_rules, &err));
  XCTAssertFalse(
      ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @""},
                  &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertFalse(
      ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @[]},
                  &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertFalse(
      ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @(0)},
                  &data_policies, &proc_policies, &num_rules, &err));

  // Minimally successful configs without watch items
  XCTAssertTrue(ParseConfig(@{kWatchItemConfigKeyVersion : @"1"}, &data_policies, &proc_policies,
                            &num_rules, &err));
  XCTAssertEqual(num_rules, 0);
  XCTAssertTrue(
      ParseConfig(@{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{}},
                  &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(num_rules, 0);

  // File access rules being invalid doesn't cause loading the entire policy to fail.
  // ParseConfig will return true here, but no policies will be created
  XCTAssertTrue(ParseConfig(
      @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@(0) : @(0)}},
      &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(data_policies.size(), 0);
  XCTAssertEqual(proc_policies.size(), 0);
  XCTAssertEqual(num_rules, 0);
  XCTAssertTrue(ParseConfig(
      @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@"" : @{}}},
      &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(data_policies.size(), 0);
  XCTAssertEqual(proc_policies.size(), 0);
  XCTAssertEqual(num_rules, 0);
  XCTAssertTrue(ParseConfig(
      @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@"a" : @[]}},
      &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(data_policies.size(), 0);
  XCTAssertEqual(proc_policies.size(), 0);
  XCTAssertEqual(num_rules, 0);
  XCTAssertTrue(ParseConfig(
      @{kWatchItemConfigKeyVersion : @"1", kWatchItemConfigKeyWatchItems : @{@"a" : @{}}},
      &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(data_policies.size(), 0);
  XCTAssertEqual(proc_policies.size(), 0);
  XCTAssertEqual(num_rules, 0);

  // Minimally successful config with watch item
  XCTAssertTrue(ParseConfig(@{
    kWatchItemConfigKeyVersion : @"1",
    kWatchItemConfigKeyWatchItems : @{@"a" : @{kWatchItemConfigKeyPaths : @[ @"asdf" ]}}
  },
                            &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(data_policies.size(), 1);
  XCTAssertEqual(proc_policies.size(), 0);
  XCTAssertEqual(num_rules, 1);

  data_policies.clear();

  // Test a large config with several valid and some invalid rules
  XCTAssertTrue(ParseConfig(@{
    kWatchItemConfigKeyVersion : @"1",
    kWatchItemConfigKeyWatchItems : @{
      @"a" : @{kWatchItemConfigKeyPaths : @[ @"foo1" ]},
      @"b" : @{kWatchItemConfigKeyPaths : @[ @"foo2" ]},
      @(123) : @{kWatchItemConfigKeyPaths : @[ @"foo_bad" ]},
      @"c" : @{kWatchItemConfigKeyPaths : @[ @"foo3" ]},
      @"d" : @{
        kWatchItemConfigKeyPaths : @[ @"foo4" ],
        kWatchItemConfigKeyOptions : @{
          kWatchItemConfigKeyOptionsRuleType : kRuleTypeProcessesWithDeniedPaths,
        },
        kWatchItemConfigKeyProcesses : @[ @{
          kWatchItemConfigKeyProcessesSigningID : @"hi.there",
          kWatchItemConfigKeyProcessesPlatformBinary : @(YES)
        } ]
      },
      @"e" : @{
        kWatchItemConfigKeyPaths : @[ @"foo4" ],
        kWatchItemConfigKeyOptions : @{
          kWatchItemConfigKeyOptionsRuleType : kRuleTypeProcessesWithDeniedPaths,
        },
        kWatchItemConfigKeyProcesses : @[ @{
          kWatchItemConfigKeyProcessesSigningID : @"hi:there",
        } ]
      },
      @"f" : @{
        kWatchItemConfigKeyPaths : @[ @"foo4" ],
        kWatchItemConfigKeyOptions : @{
          kWatchItemConfigKeyOptionsRuleType : kRuleTypeProcessesWithDeniedPaths,
        },
        kWatchItemConfigKeyProcesses : @[ @{
          kWatchItemConfigKeyProcessesTeamID : @"platform",
        } ]
      },
    },
  },
                            &data_policies, &proc_policies, &num_rules, &err));
  XCTAssertEqual(data_policies.size(), 3);
  XCTAssertEqual(proc_policies.size(), 2);
  XCTAssertEqual(num_rules, 5);
}

- (void)testParseConfigSingleWatchItemGeneral {
  SetSharedDataWatchItemPolicy data_policies;
  SetSharedProcessWatchItemPolicy proc_policies;
  NSError *err;

  // There must be valid Paths in a watch item
  XCTAssertFalse(
      ParseConfigSingleWatchItem(@"", kVersion, @{}, &data_policies, &proc_policies, &err));
  XCTAssertFalse(ParseConfigSingleWatchItem(@"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"" ]},
                                            &data_policies, &proc_policies, &err));
  XCTAssertTrue(ParseConfigSingleWatchItem(@"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"a" ]},
                                           &data_policies, &proc_policies, &err));

  // Empty options are fine
  XCTAssertTrue(ParseConfigSingleWatchItem(
      @"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @{}},
      &data_policies, &proc_policies, &err));

  // If an Options key exist, it must be a dictionary type
  XCTAssertFalse(ParseConfigSingleWatchItem(
      @"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @[]},
      &data_policies, &proc_policies, &err));
  XCTAssertFalse(ParseConfigSingleWatchItem(
      @"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @""},
      &data_policies, &proc_policies, &err));
  XCTAssertFalse(ParseConfigSingleWatchItem(
      @"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyOptions : @(0)},
      &data_policies, &proc_policies, &err));

  // Options keys must be valid types
  {
    // Check bool option keys
    for (NSString *key in @[
           kWatchItemConfigKeyOptionsAllowReadAccess,
           kWatchItemConfigKeyOptionsAuditOnly,
           kWatchItemConfigKeyOptionsInvertProcessExceptions,
           kWatchItemConfigKeyOptionsEnableSilentMode,
           kWatchItemConfigKeyOptionsEnableSilentTTYMode,
         ]) {
      // Parse bool option with invliad type
      XCTAssertFalse(ParseConfigSingleWatchItem(
          @"", kVersion,
          @{kWatchItemConfigKeyPaths : @[ @"a" ],
            kWatchItemConfigKeyOptions : @{key : @""}},
          &data_policies, &proc_policies, &err));

      // Parse bool option with valid type
      XCTAssertTrue(ParseConfigSingleWatchItem(
          @"", kVersion,
          @{kWatchItemConfigKeyPaths : @[ @"a" ],
            kWatchItemConfigKeyOptions : @{key : @(0)}},
          &data_policies, &proc_policies, &err));
    }

    // Check other option keys

    // kWatchItemConfigKeyOptionsRuleType - Invalid type
    XCTAssertFalse(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsRuleType : @[]}
        },
        &data_policies, &proc_policies, &err));

    // kWatchItemConfigKeyOptionsRuleType - Invalid RuleType value
    XCTAssertFalse(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsRuleType : @"InvalidValue"}
        },
        &data_policies, &proc_policies, &err));

    // kWatchItemConfigKeyOptionsRuleType - Override
    // kWatchItemConfigKeyOptionsInvertProcessExceptions
    data_policies.clear();
    XCTAssertTrue(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions : @{
            kWatchItemConfigKeyOptionsRuleType : kRuleTypePathsWithAllowedProcesses,
            kWatchItemConfigKeyOptionsInvertProcessExceptions : @(YES)
          }
        },
        &data_policies, &proc_policies, &err));
    XCTAssertEqual(data_policies.size(), 1);
    XCTAssertEqual(data_policies.begin()->get()->rule_type,
                   santa::WatchItemRuleType::kPathsWithAllowedProcesses);

    // kWatchItemConfigKeyOptionsRuleType - kWatchItemConfigKeyOptionsInvertProcessExceptions used
    // as fallback
    data_policies.clear();
    XCTAssertTrue(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsInvertProcessExceptions : @(YES)}
        },
        &data_policies, &proc_policies, &err));
    XCTAssertEqual(data_policies.size(), 1);
    XCTAssertEqual(data_policies.begin()->get()->rule_type,
                   santa::WatchItemRuleType::kPathsWithDeniedProcesses);

    // kWatchItemConfigKeyOptionsCustomMessage - Invalid type
    XCTAssertFalse(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsCustomMessage : @[]}
        },
        &data_policies, &proc_policies, &err));

    // kWatchItemConfigKeyOptionsCustomMessage zero length
    XCTAssertTrue(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions : @{kWatchItemConfigKeyOptionsCustomMessage : @""}
        },
        &data_policies, &proc_policies, &err));

    // kWatchItemConfigKeyOptionsCustomMessage valid "normal" length
    XCTAssertTrue(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions :
              @{kWatchItemConfigKeyOptionsCustomMessage : @"This is a custom message"}
        },
        &data_policies, &proc_policies, &err));

    // kWatchItemConfigKeyOptionsCustomMessage Invalid "long" length
    XCTAssertFalse(ParseConfigSingleWatchItem(
        @"", kVersion, @{
          kWatchItemConfigKeyPaths : @[ @"a" ],
          kWatchItemConfigKeyOptions :
              @{kWatchItemConfigKeyOptionsCustomMessage : RepeatedString(@"A", 4096)}
        },
        &data_policies, &proc_policies, &err));
  }

  // If processes are specified, they must be valid format
  // Note: Full tests in `testVerifyConfigWatchItemProcesses`
  XCTAssertFalse(ParseConfigSingleWatchItem(
      @"", kVersion, @{kWatchItemConfigKeyPaths : @[ @"a" ], kWatchItemConfigKeyProcesses : @""},
      &data_policies, &proc_policies, &err));

  // Test the policy vector is populated as expected

  // Test default options with no processes
  data_policies.clear();
  XCTAssertTrue(ParseConfigSingleWatchItem(@"rule", kVersion,
                                           @{kWatchItemConfigKeyPaths : @[ @"a" ]}, &data_policies,
                                           &proc_policies, &err));
  XCTAssertEqual(data_policies.size(), 1);
  XCTAssertEqual(
      **data_policies.begin(),
      DataWatchItemPolicy("rule", kVersion, "a", kWatchItemPolicyDefaultPathType,
                          kWatchItemPolicyDefaultAllowReadAccess, kWatchItemPolicyDefaultAuditOnly,
                          kWatchItemPolicyDefaultRuleType));
}

- (void)testParseConfigSingleWatchItemPolicies {
  SetSharedDataWatchItemPolicy data_policies;
  SetSharedProcessWatchItemPolicy proc_policies;
  NSError *err;

  // Data FAA - Test multiple paths, options, and processes
  data_policies.clear();
  proc_policies.clear();
  SetWatchItemProcess procs = {
      WatchItemProcess("pa", "", "", {}, "", false),
      WatchItemProcess("pb", "", "", {}, "", false),
  };

  NSMutableDictionary *singleWatchItemConfig = [@{
    kWatchItemConfigKeyPaths : @[
      @"a", @{kWatchItemConfigKeyPathsPath : @"b", kWatchItemConfigKeyPathsIsPrefix : @(YES)}
    ],
    kWatchItemConfigKeyOptions : [@{
      kWatchItemConfigKeyOptionsAllowReadAccess : @(YES),
      kWatchItemConfigKeyOptionsAuditOnly : @(NO),
      kWatchItemConfigKeyOptionsEnableSilentMode : @(YES),
      kWatchItemConfigKeyOptionsEnableSilentTTYMode : @(NO),
      kWatchItemConfigKeyOptionsCustomMessage : @"",
    } mutableCopy],
    kWatchItemConfigKeyProcesses : @[
      @{kWatchItemConfigKeyProcessesBinaryPath : @"pa"},
      @{kWatchItemConfigKeyProcessesBinaryPath : @"pb"}
    ]
  } mutableCopy];

  singleWatchItemConfig[kWatchItemConfigKeyOptions][kWatchItemConfigKeyOptionsRuleType] =
      kRuleTypePathsWithDeniedProcesses;
  XCTAssertTrue(ParseConfigSingleWatchItem(@"rule", kVersion, singleWatchItemConfig, &data_policies,
                                           &proc_policies, &err));

  SetSharedDataWatchItemPolicy expectedDataPolicies = {
      std::make_shared<DataWatchItemPolicy>(
          "rule", kVersion, "a", kWatchItemPolicyDefaultPathType, true, false,
          santa::WatchItemRuleType::kPathsWithDeniedProcesses, true, false, "", nil, nil, procs),
      std::make_shared<DataWatchItemPolicy>(
          "rule", kVersion, "b", WatchItemPathType::kPrefix, true, false,
          santa::WatchItemRuleType::kPathsWithDeniedProcesses, true, false, "", nil, nil, procs)};

  XCTAssertEqual(proc_policies.size(), 0);
  XCTAssertEqual(data_policies.size(), 2);
  // Ensure each of the procs in the set is in the set of expected procs
  for (const auto &p : data_policies) {
    XCTAssertEqual(expectedDataPolicies.count(p), 1);
  }

  // Proc FAA - Test multiple paths, options, and processes
  data_policies.clear();
  proc_policies.clear();

  singleWatchItemConfig[kWatchItemConfigKeyOptions][kWatchItemConfigKeyOptionsRuleType] =
      kRuleTypeProcessesWithDeniedPaths;
  XCTAssertTrue(ParseConfigSingleWatchItem(@"rule", kVersion, singleWatchItemConfig, &data_policies,
                                           &proc_policies, &err));

  XCTAssertEqual(proc_policies.size(), 1);
  XCTAssertEqual(data_policies.size(), 0);
  XCTAssertTrue(**proc_policies.begin() ==
                ProcessWatchItemPolicy(
                    "rule", kVersion,
                    {{"a", WatchItemPathType::kLiteral}, {"b", WatchItemPathType::kPrefix}}, true,
                    false, santa::WatchItemRuleType::kProcessesWithDeniedPaths, true, false, "",
                    nil, nil, procs));
}

- (void)testState {
  NSString *configPath = @"my_config_path";
  NSTimeInterval startTime = [[NSDate date] timeIntervalSince1970];

  NSMutableDictionary *config = WrapWatchItemsConfig(@{
    @"rule1" : @{kWatchItemConfigKeyPaths : @[ @"abc" ]},
    @"rule2" : @{kWatchItemConfigKeyPaths : @[ @"xyz" ]}
  });

  auto watchItems = std::make_shared<WatchItemsPeer>(configPath, nullptr);

  // If no policy yet exists, nullopt is returned
  std::optional<WatchItemsState> optionalState = watchItems->State();
  XCTAssertFalse(optionalState.has_value());

  watchItems->ReloadConfig(config);

  optionalState = watchItems->State();
  XCTAssertTrue(optionalState.has_value());
  WatchItemsState state = optionalState.value();

  XCTAssertEqual(state.rule_count, [config[kWatchItemConfigKeyWatchItems] count]);
  XCTAssertCStringEqual(state.policy_version.UTF8String, kVersion.data());
  XCTAssertEqual(state.config_path, configPath);
  XCTAssertGreaterThanOrEqual(state.last_config_load_epoch, startTime);
}

- (void)testPathPatternExpectations {
  NSMutableDictionary *config = WrapWatchItemsConfig(@{
    @"rule1" : @{kWatchItemConfigKeyPaths : @[ @"abc", @"xyz*" ]},
  });

  auto watchItems = std::make_shared<WatchItemsPeer>(@"my_fake_config_path", nullptr);
  watchItems->ReloadConfig(config);

  // Ensure that non-glob patterns are watched
  auto [targetPolicies, blockGen] = CreatePolicyBlockGen();
  watchItems->FindPoliciesForTargets(blockGen({MakePathTarget("/abc")}));
  XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(), "rule1");

  // Check that patterns with globs are not returned
  watchItems->FindPoliciesForTargets(blockGen({MakePathTarget("xyz")}));
  XCTAssertFalse(targetPolicies[0].has_value());
  watchItems->FindPoliciesForTargets(blockGen({MakePathTarget("xyzbar")}));
  XCTAssertFalse(targetPolicies[0].has_value());
}

- (void)testSetConfigAndSetConfigPath {
  // Test internal state when switching back and forth between path-based and
  // dictionary-based config options.
  auto watchItems = std::make_shared<WatchItemsPeer>(@{}, nullptr);

  XCTAssertNil(watchItems->config_path_);
  XCTAssertNotNil(watchItems->embedded_config_);

  watchItems->SetConfigPath(@"/path/to/a/nonexistent/file/so/nothing/is/opened");

  XCTAssertNotNil(watchItems->config_path_);
  XCTAssertNil(watchItems->embedded_config_);

  watchItems->SetConfig(@{});

  XCTAssertNil(watchItems->config_path_);
  XCTAssertNotNil(watchItems->embedded_config_);
}

- (void)testDataWatchItemsFindMatches {
  [self createTestDirStructure:@[ @{
          @"tmp" : @[
            @{
              @"nested" : @[ @{
                @"app" : @[
                  @{
                    @"v1" : @[ @{
                      @"plugins" : @[
                        @{@"foo" : @[ @"hi.txt" ]},
                        @{@"bar" : @[ @"bye.txt" ]},
                      ]
                    } ]
                  },
                  @{
                    @"v2" : @[ @{
                      @"plugins" : @[
                        @{@"foo" : @[ @"hi.txt" ]},
                        @{@"baz" : @[ @"hello.txt" ]},
                      ]
                    } ]
                  },
                  @{
                    @"v3" : @[],
                  }
                ]
              } ],
            },
            @{
              @"My.app" : @[
                @{
                  @"Contents" : @[
                    @"Info.plist",
                    @{@"MacOS" : @[ @"MyApp.exe" ]},
                  ]
                },
              ]
            }
          ]
        } ]];

  NSString * (^MakeTestDirPath)(NSString *) = ^NSString *(NSString *target) {
    if (![target hasPrefix:@"/"]) {
      target = [NSString stringWithFormat:@"/%@", target];
    }
    return [NSString stringWithFormat:@"%@%@", self.testDir, target];
  };

  std::vector<std::string> matches;

  matches = FindMatches(MakeTestDirPath(@"/tmp/My.app/C*/*.plist"));
  XCTAssertEqual(matches.size(), 1);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/My.app/Contents/Info.plist");

  matches = FindMatches(MakeTestDirPath(@"/*"));

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/app/*/plugins/hi.txt"));
  XCTAssertEqual(matches.size(), 3);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/nested/app/v1/plugins/hi.txt");
  XCTAssertCppStringEndsWith(matches[1], "/tmp/nested/app/v2/plugins/hi.txt");
  XCTAssertCppStringEndsWith(matches[2], "/tmp/nested/app/v3/plugins/hi.txt");

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/app/*/*/"));
  XCTAssertEqual(matches.size(), 2);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/nested/app/v1/plugins/");
  XCTAssertCppStringEndsWith(matches[1], "/tmp/nested/app/v2/plugins/");

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/app/*/*"));
  XCTAssertEqual(matches.size(), 2);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/nested/app/v1/plugins");
  XCTAssertCppStringEndsWith(matches[1], "/tmp/nested/app/v2/plugins");

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/app/*/*"));
  XCTAssertEqual(matches.size(), 2);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/nested/app/v1/plugins");
  XCTAssertCppStringEndsWith(matches[1], "/tmp/nested/app/v2/plugins");

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/apps/"));
  XCTAssertEqual(matches.size(), 2);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/My.app/apps/");
  XCTAssertCppStringEndsWith(matches[1], "/tmp/nested/apps/");

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/apps/foo"));
  XCTAssertEqual(matches.size(), 2);
  XCTAssertCppStringEndsWith(matches[0], "/tmp/My.app/apps/foo");
  XCTAssertCppStringEndsWith(matches[1], "/tmp/nested/apps/foo");

  matches = FindMatches(MakeTestDirPath(@"/tmp/*/apps/*"));
  XCTAssertEqual(matches.size(), 0);

  matches = FindMatches(MakeTestDirPath(@"/*"));
  XCTAssertEqual(matches.size(), 1);
  XCTAssertCppStringEndsWith(matches[0], "/tmp");

  // Test path without a leading slash to ensure the function forces it
  NSString *path = MakeTestDirPath(@"*");
  path = [path substringFromIndex:1];
  matches = FindMatches(path);
  XCTAssertEqual(matches.size(), 1);
  XCTAssertCppStringEndsWith(matches[0], "/tmp");
}

- (void)testDataWatchItemsBuild {
  [self createTestDirStructure:@[
    @{
      @"foo" : @[
        @{
          @"cake" : @[ @"hi.txt" ],
        },
        @{
          @"asdf" : @[ @"bye.txt" ],
        },
        @{
          @"appv1" : @[
            @{
              @"plugins" : @[
                @{
                  @"testplugin" : @[ @"t.txt" ],
                },
              ],
            },
          ]
        },
        @{
          @"appv2" : @[
            @{
              @"plugins" : @[
                @{
                  @"anotherplugin" : @[ @"t.txt" ],
                },
              ],
            },
          ]
        }
      ]
    },
  ]];

  std::string (^MakeTestDirPathTarget)(NSString *) = ^(NSString *target) {
    return MakePathTarget([[NSString stringWithFormat:@"%@%@", self.testDir, target] UTF8String]);
  };

  std::shared_ptr<DataWatchItemPolicy> (^MakeDataPolicy)(std::string, NSString *) =
      ^std::shared_ptr<DataWatchItemPolicy>(std::string name, NSString *path) {
    NSString *full = [NSString stringWithFormat:@"%@%@", self.testDir, path];
    return std::make_shared<DataWatchItemPolicy>(name, "v1", full.UTF8String,
                                                 WatchItemPathType::kPrefix);
  };

  SetSharedDataWatchItemPolicy policies{
      MakeDataPolicy("n1", @"/foo/*/plugins/"),
      MakeDataPolicy("n2", @"/foo/*/plugins/testplugin"),
      MakeDataPolicy("n3", @"/foo/*/plugins/does_not_yet_exist"),
  };

  DataWatchItems watchItems;

  watchItems.Build(policies);

  auto [targetPolicies, blockGen] = CreatePolicyBlockGen();

  // Existing v1 testplugin found
  watchItems.FindPolicies(blockGen({MakeTestDirPathTarget(@"/foo/appv1/plugins/testplugin")}));
  XCTAssertEqual(targetPolicies.size(), 1);
  XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(), "n2");

  // Existing v2 anotherplugin found, but no rule, matches parent plugins dir
  watchItems.FindPolicies(blockGen({MakeTestDirPathTarget(@"/foo/appv2/plugins/anotherplugin")}));
  XCTAssertEqual(targetPolicies.size(), 1);
  XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(), "n1");

  // Non existent path with a backing rule
  watchItems.FindPolicies(
      blockGen({MakeTestDirPathTarget(@"/foo/appv1/plugins/does_not_yet_exist")}));
  XCTAssertEqual(targetPolicies.size(), 1);
  XCTAssertCStringEqual(targetPolicies[0].value_or(MakeBadPolicy())->name.c_str(), "n3");
}

- (void)testDataWatchItemsSubtraction {
  SetSharedDataWatchItemPolicy policies1{
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "a", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "b", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "c", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "d", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "e", WatchItemPathType::kPrefix),
  };

  SetSharedDataWatchItemPolicy policies2{
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "x", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "b", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "c", WatchItemPathType::kLiteral),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "d", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "y", WatchItemPathType::kPrefix),
      std::make_shared<DataWatchItemPolicy>("n1", "v1", "z", WatchItemPathType::kPrefix),
  };

  DataWatchItems watchItems1;
  DataWatchItems watchItems2;

  watchItems1.Build(policies1);
  watchItems2.Build(policies2);

  XCTAssertEqual(watchItems1.Count(), 5);
  XCTAssertEqual(watchItems2.Count(), 6);

  SetPairPathAndType pathTypePairs1_2 = watchItems1 - watchItems2;
  XCTAssertEqual(pathTypePairs1_2.size(), 3);
  XCTAssertEqual(pathTypePairs1_2.count({"/a", WatchItemPathType::kPrefix}), 1);
  XCTAssertEqual(pathTypePairs1_2.count({"/c", WatchItemPathType::kPrefix}), 1);
  XCTAssertEqual(pathTypePairs1_2.count({"/e", WatchItemPathType::kPrefix}), 1);

  SetPairPathAndType pathTypePairs2_1 = watchItems2 - watchItems1;
  XCTAssertEqual(pathTypePairs2_1.size(), 4);
  XCTAssertEqual(pathTypePairs2_1.count({"/c", WatchItemPathType::kLiteral}), 1);
  XCTAssertEqual(pathTypePairs2_1.count({"/x", WatchItemPathType::kPrefix}), 1);
  XCTAssertEqual(pathTypePairs2_1.count({"/y", WatchItemPathType::kPrefix}), 1);
  XCTAssertEqual(pathTypePairs2_1.count({"/z", WatchItemPathType::kPrefix}), 1);
}

@end
