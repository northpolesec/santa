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

#include "Source/common/faa/WatchItemPolicy.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <vector>

#include "Source/common/TestUtils.h"
#include "absl/container/flat_hash_set.h"

using santa::DataWatchItemPolicy;
using santa::PairPathAndType;
using santa::ProcessWatchItemPolicy;
using santa::SetPairPathAndType;
using santa::SetSharedDataWatchItemPolicy;
using santa::SetSharedProcessWatchItemPolicy;
using santa::WatchItemParentDirectoryProtection;
using santa::WatchItemPathType;
using santa::WatchItemProcess;
using santa::WatchItemProcessOptions;
using santa::WatchItemRuleType;

@interface WatchItemPolicyTest : XCTestCase
@end

@implementation WatchItemPolicyTest

- (void)testWatchPathForMatch {
  constexpr WatchItemPathType kLiteral = WatchItemPathType::kLiteral;
  constexpr WatchItemPathType kPrefix = WatchItemPathType::kPrefix;

  struct Case {
    std::string match;
    WatchItemPathType type;
    std::string want;
  };

  const Case cases[] = {
      // A literal drops the trailing slash that restricted expansion to directories
      {"/a/b/", kLiteral, "/a/b"},
      {"/a/b", kLiteral, "/a/b"},

      // A prefix keeps it, since "/a/" and "/a" match different sets
      {"/a/b/", kPrefix, "/a/b/"},

      // Root, and paths the parser kept because they have no safe rewrite, are
      // unchanged. Stripping "//" would turn a dead rule into a live one on "/".
      {"/", kLiteral, "/"},
      {"//", kLiteral, "//"},
      {"///", kLiteral, "///"},
      {"/a/./b//", kLiteral, "/a/./b//"},
  };

  for (const Case& c : cases) {
    std::string got = santa::WatchPathForMatch(c.match, c.type);
    XCTAssertTrue(got == c.want, @"match: '%s' (%s), got: '%s', want: '%s'", c.match.c_str(),
                  c.type == kPrefix ? "prefix" : "literal", got.c_str(), c.want.c_str());
  }
}

- (void)testAncestorDirectories {
  using santa::AncestorDirectories;
  using Dirs = std::vector<std::string>;

  XCTAssertTrue(AncestorDirectories("/a/b/c/d") == Dirs({"/a", "/a/b", "/a/b/c"}));
  XCTAssertTrue(AncestorDirectories("/a/b/c/d/") == Dirs({"/a", "/a/b", "/a/b/c", "/a/b/c/d"}));
  XCTAssertTrue(AncestorDirectories("/a/b/c/do") == Dirs({"/a", "/a/b", "/a/b/c"}));
  XCTAssertTrue(AncestorDirectories("/a/") == Dirs({"/a"}));
  XCTAssertTrue(AncestorDirectories("/a").empty());
  XCTAssertTrue(AncestorDirectories("/").empty());

  // Paths the parser kept because they have no safe rewrite have no ancestors
  XCTAssertTrue(AncestorDirectories("/a/../b").empty());
  XCTAssertTrue(AncestorDirectories("/a/./b").empty());
  XCTAssertTrue(AncestorDirectories("/a/b/..").empty());
  XCTAssertTrue(AncestorDirectories("/a/./b//").empty());
  XCTAssertTrue(AncestorDirectories("//").empty());
  XCTAssertTrue(AncestorDirectories("///").empty());

  // Names that only begin with dots are ordinary components
  XCTAssertTrue(AncestorDirectories("/a/.hidden/b") == Dirs({"/a", "/a/.hidden"}));
  XCTAssertTrue(AncestorDirectories("/a/..b/c") == Dirs({"/a", "/a/..b"}));
}

- (void)testProcessWatchItemPolicyMatchesTarget {
  using Match = ProcessWatchItemPolicy::TargetMatch;
  SetPairPathAndType paths = {
      {"/a/b/c", WatchItemPathType::kLiteral},
      {"/x/y/", WatchItemPathType::kPrefix},
  };

  ProcessWatchItemPolicy denied("denied", "v1", paths, false,
                                WatchItemRuleType::kProcessesWithDeniedPaths);

  // Configured paths match directly regardless of the operation
  XCTAssertEqual(denied.MatchesTarget("/a/b/c", false), Match::kDirect);
  XCTAssertEqual(denied.MatchesTarget("/a/b/c", true), Match::kDirect);
  XCTAssertEqual(denied.MatchesTarget("/x/y/z", false), Match::kDirect);

  // Ancestors match only for directory tree operations
  XCTAssertEqual(denied.MatchesTarget("/a/b", false), Match::kNone);
  XCTAssertEqual(denied.MatchesTarget("/a/b", true), Match::kAncestor);
  XCTAssertEqual(denied.MatchesTarget("/a", true), Match::kAncestor);
  XCTAssertEqual(denied.MatchesTarget("/x/y", true), Match::kAncestor);
  XCTAssertEqual(denied.MatchesTarget("/x", true), Match::kAncestor);

  // Siblings, the root, and paths below a literal never match
  XCTAssertEqual(denied.MatchesTarget("/a/bc", true), Match::kNone);
  XCTAssertEqual(denied.MatchesTarget("/", true), Match::kNone);
  XCTAssertEqual(denied.MatchesTarget("/a/b/c/d", true), Match::kNone);

  // A path that is both configured and an ancestor of another configured path
  // matches directly
  ProcessWatchItemPolicy nested(
      "nested", "v1",
      {{"/a/b", WatchItemPathType::kLiteral}, {"/a/b/c", WatchItemPathType::kLiteral}}, false,
      WatchItemRuleType::kProcessesWithDeniedPaths);
  XCTAssertEqual(nested.MatchesTarget("/a/b", true), Match::kDirect);
  XCTAssertEqual(nested.MatchesTarget("/a", true), Match::kAncestor);

  // Allowed-paths rules never match ancestors, since that would allow the tree
  ProcessWatchItemPolicy allowed("allowed", "v1", paths, false,
                                 WatchItemRuleType::kProcessesWithAllowedPaths);
  XCTAssertEqual(allowed.MatchesTarget("/a/b/c", true), Match::kDirect);
  XCTAssertEqual(allowed.MatchesTarget("/a/b", true), Match::kNone);
  XCTAssertEqual(allowed.MatchesTarget("/x/y", true), Match::kNone);

  // With parent directory protection disabled the rule has no ancestors, and
  // direct matches are unchanged
  ProcessWatchItemPolicy disabled("disabled", "v1", paths, false,
                                  WatchItemRuleType::kProcessesWithDeniedPaths, {}, {}, 0,
                                  WatchItemParentDirectoryProtection::kDisabled);
  XCTAssertTrue(disabled.ancestor_dirs.empty());
  XCTAssertEqual(disabled.MatchesTarget("/a/b", true), Match::kNone);
  XCTAssertEqual(disabled.MatchesTarget("/x", true), Match::kNone);
  XCTAssertEqual(disabled.MatchesTarget("/a/b/c", true), Match::kDirect);
  XCTAssertEqual(disabled.MatchesTarget("/x/y/z", false), Match::kDirect);

  // Audit and enforce both match ancestors; the mode only changes the outcome
  for (WatchItemParentDirectoryProtection pdp :
       {WatchItemParentDirectoryProtection::kAudit, WatchItemParentDirectoryProtection::kEnforce}) {
    ProcessWatchItemPolicy p("p", "v1", paths, false, WatchItemRuleType::kProcessesWithDeniedPaths,
                             {}, {}, 0, pdp);
    XCTAssertEqual(p.MatchesTarget("/a/b", true), Match::kAncestor);
  }
}

- (void)testProcessWatchItemPolicy {
  // Make sure the equality operator for a WatchItemProcess covers all members.
  // Note: WatchItemProcess isn't assignable (it has a const member), so each
  // case starts from a fresh copy.
  auto makeProc = [] {
    return WatchItemProcess("proc_path_1", "com.example.proc", "PROCTEAMID", {}, "", false);
  };
  WatchItemProcess orig = makeProc();

  XCTAssertEqual(makeProc(), orig);

  {
    WatchItemProcess proc = makeProc();
    proc.UnsafeUpdateSigningId("abc");
    XCTAssertNotEqual(proc, orig);
  }
  {
    WatchItemProcess proc = makeProc();
    proc.binary_path = "abc";
    XCTAssertNotEqual(proc, orig);
  }
  {
    WatchItemProcess proc = makeProc();
    proc.team_id = "abc";
    XCTAssertNotEqual(proc, orig);
  }
  {
    WatchItemProcess proc = makeProc();
    proc.platform_binary = true;
    XCTAssertNotEqual(proc, orig);
  }
  {
    WatchItemProcess proc = makeProc();
    proc.certificate_sha256 = "abc";
    XCTAssertNotEqual(proc, orig);
  }
  {
    WatchItemProcess proc = makeProc();
    proc.cdhash = {1};
    XCTAssertNotEqual(proc, orig);
  }
  {
    WatchItemProcess proc = makeProc();
    proc.options = WatchItemProcessOptions{};
    XCTAssertNotEqual(proc, orig);
  }

  // Every field of the options struct that participates in equality
  WatchItemProcess withDefaultOptions = makeProc();
  withDefaultOptions.options = WatchItemProcessOptions{};

  {
    WatchItemProcess proc = makeProc();
    WatchItemProcessOptions opts;
    opts.action = santa::WatchItemProcessAction::kDeny;
    proc.options = opts;
    XCTAssertNotEqual(proc, withDefaultOptions);
  }
  {
    WatchItemProcess proc = makeProc();
    WatchItemProcessOptions opts;
    opts.allow_read_access = !opts.allow_read_access;
    proc.options = opts;
    XCTAssertNotEqual(proc, withDefaultOptions);
  }
  {
    WatchItemProcess proc = makeProc();
    WatchItemProcessOptions opts;
    opts.silent = !opts.silent;
    proc.options = opts;
    XCTAssertNotEqual(proc, withDefaultOptions);
  }
  {
    WatchItemProcess proc = makeProc();
    WatchItemProcessOptions opts;
    opts.silent_tty = !opts.silent_tty;
    proc.options = opts;
    XCTAssertNotEqual(proc, withDefaultOptions);
  }
}

- (void)testProcessWatchItemPolicyProcessOrder {
  // The processes list is ordered - matching is first-match-wins.
  WatchItemProcess first("first", "", "", {}, "", false);
  WatchItemProcess second("second", "", "", {}, "", false);

  ProcessWatchItemPolicy pwip(
      "name", "ver", SetPairPathAndType{PairPathAndType{"path1", WatchItemPathType::kLiteral}},
      true, santa::WatchItemRuleType::kProcessesWithAllowedPaths, {}, {first, second});

  XCTAssertEqual(pwip.processes.size(), 2);
  XCTAssertEqual(pwip.processes[0], first);
  XCTAssertEqual(pwip.processes[1], second);
}

- (void)testWatchItemProcessCreate {
  // Fail when nothing is set
  XCTAssertFalse(
      WatchItemProcess::Create(nil, nil, nil, nil, nil, false, std::nullopt, nil).has_value());

  // Both PlatformBinary and a TID cannot be set (as long as not "platform")
  XCTAssertFalse(
      WatchItemProcess::Create(nil, nil, @"ABCDE12345", nil, nil, true, std::nullopt, nil)
          .has_value());

  // SigningID being set requires a TID/PlatformBinary
  XCTAssertFalse(
      WatchItemProcess::Create(nil, @"com.example", nil, nil, nil, false, std::nullopt, nil)
          .has_value());

  // Test invalid TID prefixes for an SID
  XCTAssertFalse(WatchItemProcess::Create(nil, @"platforms:com.example", nil, nil, nil, false,
                                          std::nullopt, nil)
                     .has_value());
  XCTAssertFalse(WatchItemProcess::Create(nil, @"ABCDE1234:com.example", nil, nil, nil, false,
                                          std::nullopt, nil)
                     .has_value());
  XCTAssertFalse(WatchItemProcess::Create(nil, @"ABCDE123456:com.example", nil, nil, nil, false,
                                          std::nullopt, nil)
                     .has_value());

  {
    // If PB is set, TID:SID prefix is ignored
    auto wip = WatchItemProcess::Create(nil, @"ABCDE12345:com.example", nil, nil, nil, true,
                                        std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertCppStringEqual(wip->signing_id, "ABCDE12345:com.example");
    XCTAssertTrue(wip->platform_binary);
  }

  {
    // If TID is set to platform, TID:SID prefix is ignored, marked as platform
    auto wip = WatchItemProcess::Create(nil, @"ABCDE12345:com.example", @"PLatFOrm", nil, nil,
                                        false, std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertCppStringEqual(wip->signing_id, "ABCDE12345:com.example");
    XCTAssertTrue(wip->platform_binary);
    XCTAssertCppStringEqual(wip->team_id, "");
  }

  {
    // If TID is set, TID:SID prefix is ignored
    auto wip = WatchItemProcess::Create(nil, @"platform:com.example", @"ABCDE12345", nil, nil,
                                        false, std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertCppStringEqual(wip->signing_id, "platform:com.example");
    XCTAssertFalse(wip->platform_binary);
    XCTAssertCppStringEqual(wip->team_id, "ABCDE12345");
  }

  {
    // Extract TID
    auto wip =
        WatchItemProcess::Create(nil, @"ABCDE12345:x", nil, nil, nil, false, std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertCppStringEqual(wip->signing_id, "x");
    XCTAssertFalse(wip->platform_binary);
    XCTAssertCppStringEqual(wip->team_id, "ABCDE12345");
  }

  {
    // Extract platform TID
    auto wip =
        WatchItemProcess::Create(nil, @"platFORM:*", nil, nil, nil, false, std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertCppStringEqual(wip->signing_id, "*");
    XCTAssertTrue(wip->platform_binary);
    XCTAssertCppStringEqual(wip->team_id, "");
  }

  {
    // Extract platform TID
    auto wip =
        WatchItemProcess::Create(nil, @"platform:*", nil, nil, nil, false, std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertCppStringEqual(wip->signing_id, "*");
    XCTAssertTrue(wip->platform_binary);
    XCTAssertCppStringEqual(wip->team_id, "");
  }

  {
    // Both PlatformBinary and a TID can be set if TID is "platform"
    auto wip = WatchItemProcess::Create(nil, nil, @"plATFOrm", nil, nil, true, std::nullopt, nil);
    XCTAssertTrue(wip.has_value());
    XCTAssertTrue(wip->platform_binary);
    XCTAssertCppStringEqual(wip->team_id, "");
    XCTAssertCppStringEqual(wip->signing_id, "");
  }
}

- (void)testSetDataWatchItemPolicy {
  SetSharedDataWatchItemPolicy dataSet;

  auto sharedDataPolicy1 =
      std::make_shared<DataWatchItemPolicy>("name", "v1", "/foo", WatchItemPathType::kLiteral, true,
                                            WatchItemRuleType::kPathsWithAllowedProcesses);

  auto sharedDataPolicy2 =
      std::make_shared<DataWatchItemPolicy>("name", "v1", "/foo", WatchItemPathType::kLiteral, true,
                                            WatchItemRuleType::kPathsWithAllowedProcesses);

  auto sharedDataPolicy3 =
      std::make_shared<DataWatchItemPolicy>("name", "v1", "/bar", WatchItemPathType::kLiteral, true,
                                            WatchItemRuleType::kPathsWithAllowedProcesses);

  // Underlying pointers should be different
  XCTAssertNotEqual(sharedDataPolicy1, sharedDataPolicy2);
  XCTAssertNotEqual(sharedDataPolicy1, sharedDataPolicy3);
  XCTAssertNotEqual(sharedDataPolicy2, sharedDataPolicy3);

  // policies 1 and 2 have the same content, but policy 3 has a different path.
  // Check for expected equality.
  XCTAssertTrue(*sharedDataPolicy1 == *sharedDataPolicy2);
  XCTAssertFalse(*sharedDataPolicy1 == *sharedDataPolicy3);

  // Parent directory protection is part of equality, so changing only it
  // replaces the policy
  XCTAssertFalse(*sharedDataPolicy1 ==
                 DataWatchItemPolicy("name", "v1", "/foo", WatchItemPathType::kLiteral, true,
                                     WatchItemRuleType::kPathsWithAllowedProcesses, {}, {}, 0,
                                     WatchItemParentDirectoryProtection::kEnforce));

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
      "name", "v1", SetPairPathAndType{{"/foo", WatchItemPathType::kLiteral}}, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  auto sharedProcPolicy2 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", SetPairPathAndType{{"/foo", WatchItemPathType::kLiteral}}, true,
      WatchItemRuleType::kProcessesWithDeniedPaths);

  auto sharedProcPolicy3 = std::make_shared<ProcessWatchItemPolicy>(
      "name", "v1", SetPairPathAndType{{"/bar", WatchItemPathType::kLiteral}}, true,
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
