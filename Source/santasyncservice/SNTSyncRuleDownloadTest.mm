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

#import "Source/santasyncservice/SNTSyncRuleDownload.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTFileAccessRule.h"
#include "Source/common/TestUtils.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/common/faa/WatchItems.h"
#import "Source/santasyncservice/SNTSyncState.h"
#include "syncv2/v2.pb.h"

namespace pbv2 = ::santa::sync::v2;

extern NSArray *PathsFromProtoFAARulePaths(
    const google::protobuf::RepeatedPtrField<::pbv2::FileAccessRule::Path> &pbPaths);
extern NSDictionary *OptionsFromProtoFAARuleAdd(const ::pbv2::FileAccessRule::Add &pbAddRule);
extern NSArray *ProcessesFromProtoFAARuleProcesses(
    const google::protobuf::RepeatedPtrField<::pbv2::FileAccessRule::Process> &pbProcesses);
extern SNTFileAccessRule *FAARuleFromProtoFileAccessRule(const ::pbv2::FileAccessRule &wi);

@interface SNTSyncRuleDownloadTest : XCTestCase
@end

@implementation SNTSyncRuleDownloadTest

- (void)testPathsFromProtoFAARulePaths {
  ::pbv2::FileAccessRule::Add addRule;
  ::pbv2::FileAccessRule::Path *path = addRule.add_paths();
  path->set_path("/my/first/path");
  path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);

  path = addRule.add_paths();
  path->set_path("/my/second/path");
  // Note: Leaving path type unspecified so the default is used

  path = addRule.add_paths();
  path->set_path("/my/*/path");
  path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_PREFIX);

  NSArray *paths = PathsFromProtoFAARulePaths(addRule.paths());
  XCTAssertEqual(paths.count, 3);

  XCTAssertEqualObjects(paths[0][kWatchItemConfigKeyPathsPath], @"/my/first/path");
  XCTAssertFalse([paths[0][kWatchItemConfigKeyPathsIsPrefix] boolValue]);

  XCTAssertEqualObjects(paths[1][kWatchItemConfigKeyPathsPath], @"/my/second/path");
  XCTAssertFalse([paths[1][kWatchItemConfigKeyPathsIsPrefix] boolValue]);

  XCTAssertEqualObjects(paths[2][kWatchItemConfigKeyPathsPath], @"/my/*/path");
  XCTAssertTrue([paths[2][kWatchItemConfigKeyPathsIsPrefix] boolValue]);
}

- (void)testPathsFromProtoFAARulePathsBadValue {
  ::pbv2::FileAccessRule::Add addRule;
  ::pbv2::FileAccessRule::Path *path = addRule.add_paths();
  path->set_path("/my/first/path");
  path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);

  path = addRule.add_paths();
  path->set_path("/my/second/path");
  path->set_path_type(static_cast<::pbv2::FileAccessRule::Path::PathType>(123));

  path = addRule.add_paths();
  path->set_path("/my/*/path");
  path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_PREFIX);

  NSArray *paths = PathsFromProtoFAARulePaths(addRule.paths());
  XCTAssertNil(paths);
}

- (void)testOptionsFromProtoFAARuleAdd {
  {
    ::pbv2::FileAccessRule::Add addRule;
    addRule.set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PATHS_WITH_DENIED_PROCESSES);
    addRule.set_version("v1");
    addRule.set_allow_read_access(true);
    addRule.set_block_violations(true);
    addRule.set_enable_silent_mode(true);
    addRule.set_enable_silent_tty_mode(true);
    addRule.set_block_message("this is a block");
    addRule.set_event_detail_text("details details details");
    addRule.set_event_detail_url("url url url");

    NSDictionary *opts = OptionsFromProtoFAARuleAdd(addRule);

    XCTAssertEqual(opts.count, 9);
    XCTAssertEqualObjects([opts[kWatchItemConfigKeyOptionsRuleType] lowercaseString],
                          kRuleTypePathsWithDeniedProcesses);
    XCTAssertTrue([opts[kWatchItemConfigKeyOptionsAllowReadAccess] boolValue]);
    XCTAssertFalse([opts[kWatchItemConfigKeyOptionsAuditOnly] boolValue]);
    XCTAssertTrue([opts[kWatchItemConfigKeyOptionsEnableSilentMode] boolValue]);
    XCTAssertTrue([opts[kWatchItemConfigKeyOptionsEnableSilentTTYMode] boolValue]);
    XCTAssertEqualObjects(opts[kWatchItemConfigKeyOptionsCustomMessage], @"this is a block");
    XCTAssertEqualObjects(opts[kWatchItemConfigKeyOptionsEventDetailText],
                          @"details details details");
    XCTAssertEqualObjects(opts[kWatchItemConfigKeyOptionsEventDetailURL], @"url url url");
  }

  // Defaults
  {
    ::pbv2::FileAccessRule::Add addRule;
    NSDictionary *opts = OptionsFromProtoFAARuleAdd(addRule);

    XCTAssertEqual(opts.count, 6);

    XCTAssertEqualObjects([opts[kWatchItemConfigKeyOptionsRuleType] lowercaseString],
                          kRuleTypePathsWithAllowedProcesses);
    XCTAssertFalse([opts[kWatchItemConfigKeyOptionsAllowReadAccess] boolValue]);
    XCTAssertTrue([opts[kWatchItemConfigKeyOptionsAuditOnly] boolValue]);
    XCTAssertFalse([opts[kWatchItemConfigKeyOptionsEnableSilentMode] boolValue]);
    XCTAssertFalse([opts[kWatchItemConfigKeyOptionsEnableSilentTTYMode] boolValue]);
    XCTAssertNil(opts[kWatchItemConfigKeyOptionsCustomMessage]);
    XCTAssertNil(opts[kWatchItemConfigKeyOptionsEventDetailText]);
    XCTAssertNil(opts[kWatchItemConfigKeyOptionsEventDetailURL]);
  }
}

- (void)testOptionsFromProtoFAARuleAddBadValue {
  ::pbv2::FileAccessRule::Add addRule;
  addRule.set_rule_type(static_cast<::pbv2::FileAccessRule::RuleType>(123));
  addRule.set_allow_read_access(true);
  addRule.set_block_violations(true);
  addRule.set_enable_silent_mode(true);
  addRule.set_enable_silent_tty_mode(true);
  addRule.set_block_message("this is a block");
  addRule.set_event_detail_text("details details details");
  addRule.set_event_detail_url("url url url");

  NSDictionary *opts = OptionsFromProtoFAARuleAdd(addRule);
  XCTAssertNil(opts);
}

- (void)testProcessesFromProtoFAARuleProcesses {
  ::pbv2::FileAccessRule::Add addRule;

  ::pbv2::FileAccessRule::Process *proc = addRule.add_processes();
  proc->set_cd_hash("abc");
  proc = addRule.add_processes();
  proc->set_cd_hash("def");
  proc = addRule.add_processes();
  proc->set_binary_path("/my/path/");

  NSArray *procs = ProcessesFromProtoFAARuleProcesses(addRule.processes());
  XCTAssertEqual(procs.count, 3);
  XCTAssertEqualObjects(procs[0][kWatchItemConfigKeyProcessesCDHash], @"abc");
  XCTAssertEqualObjects(procs[1][kWatchItemConfigKeyProcessesCDHash], @"def");
  XCTAssertEqualObjects(procs[2][kWatchItemConfigKeyProcessesBinaryPath], @"/my/path/");

  // Should return an empty array when no processes are added
  addRule.clear_processes();
  procs = ProcessesFromProtoFAARuleProcesses(addRule.processes());
  XCTAssertEqual(procs.count, 0);

  // Should return nil when an invalid identifier is used
  proc = addRule.add_processes();
  procs = ProcessesFromProtoFAARuleProcesses(addRule.processes());
  XCTAssertNil(procs);
}

- (void)testFAARuleFromProtoFileAccessRuleAdd {
  ::pbv2::FileAccessRule wi;
  ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
  ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
  path->set_path("/foo");
  path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);
  path = addRule->add_paths();
  path->set_path("/bar");
  path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_PREFIX);

  addRule->set_name("my_test_rule");
  addRule->set_version("v1");
  addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);
  addRule->set_allow_read_access(true);
  addRule->set_block_violations(true);
  addRule->set_enable_silent_mode(true);
  addRule->set_enable_silent_tty_mode(true);
  addRule->set_block_message("this is a block");
  addRule->set_event_detail_text("details details details");
  addRule->set_event_detail_url("url url url");

  ::pbv2::FileAccessRule::Process *proc = addRule->add_processes();
  proc->set_team_id("EXAMPLETID");
  proc = addRule->add_processes();
  proc->set_cd_hash("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
  proc = addRule->add_processes();
  proc->set_binary_path("/my/path/");

  SNTFileAccessRule *rule = FAARuleFromProtoFileAccessRule(wi);
  XCTAssertEqual(rule.state, SNTFileAccessRuleStateAdd);

  // Spot check
  NSDictionary *details = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[NSDictionary class], [NSArray class],
                                                      [NSString class], [NSNumber class],
                                                      [NSData class], nil]
                       fromData:rule.details
                          error:nil];
  XCTAssertNotNil(details);
  XCTAssertEqual([details[kWatchItemConfigKeyPaths] count], 2);
  XCTAssertEqualObjects(details[kWatchItemConfigKeyPaths][1][kWatchItemConfigKeyPathsPath],
                        @"/bar");
  XCTAssertEqual([details[kWatchItemConfigKeyProcesses] count], 3);
  XCTAssertEqualObjects(
      details[kWatchItemConfigKeyProcesses][0][kWatchItemConfigKeyProcessesTeamID], @"EXAMPLETID");
}

- (void)testInvalidFAARuleFromProtoFileAccessRuleAdd {
  // This test does various spot checks to ensure that rules are only returned
  // from `FAARuleFromProtoFileAccessRule` if they are determined to be valid.

  // No paths defined
  {
    ::pbv2::FileAccessRule wi;
    ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
    addRule->set_name("my_test_rule");
    addRule->set_version("v1");
    addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);

    XCTAssertNil(FAARuleFromProtoFileAccessRule(wi));

    // Now add the path to ensure the rule parses
    ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
    path->set_path("/foo");
    path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);

    XCTAssertNotNil(FAARuleFromProtoFileAccessRule(wi));
  }

  // Bad path tyoe
  {
    ::pbv2::FileAccessRule wi;
    ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
    ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
    path->set_path("/foo");
    path->set_path_type(static_cast<::pbv2::FileAccessRule::Path::PathType>(123));
    addRule->set_name("my_test_rule");
    addRule->set_version("v1");
    addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);

    XCTAssertNil(FAARuleFromProtoFileAccessRule(wi));

    // Now use a valid path type to ensure the rule parses
    path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);
    XCTAssertNotNil(FAARuleFromProtoFileAccessRule(wi));
  }

  // No name
  {
    ::pbv2::FileAccessRule wi;
    ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
    ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
    path->set_path("/foo");
    path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);
    addRule->set_version("v1");
    addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);

    XCTAssertNil(FAARuleFromProtoFileAccessRule(wi));

    // Now add the name to ensure the rule parses
    addRule->set_name("my_test_rule");
    XCTAssertNotNil(FAARuleFromProtoFileAccessRule(wi));
  }

  // Invalid name
  {
    ::pbv2::FileAccessRule wi;
    ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
    ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
    path->set_path("/foo");
    path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);
    addRule->set_name("my-test-rule");
    addRule->set_version("v1");
    addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);

    XCTAssertNil(FAARuleFromProtoFileAccessRule(wi));

    // Now use a valid name to ensure the rule parses
    addRule->set_name("my_test_rule");
    XCTAssertNotNil(FAARuleFromProtoFileAccessRule(wi));
  }

  // No version
  {
    ::pbv2::FileAccessRule wi;
    ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
    ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
    path->set_path("/foo");
    path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);
    addRule->set_name("my_test_rule");
    addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);

    XCTAssertNil(FAARuleFromProtoFileAccessRule(wi));

    // Now add the version to ensure the rule parses
    addRule->set_version("v1");
    XCTAssertNotNil(FAARuleFromProtoFileAccessRule(wi));
  }

  // Bad rule type
  {
    ::pbv2::FileAccessRule wi;
    ::pbv2::FileAccessRule::Add *addRule = wi.mutable_add();
    ::pbv2::FileAccessRule::Path *path = addRule->add_paths();
    path->set_path("/foo");
    path->set_path_type(::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL);
    addRule->set_name("my_test_rule");
    addRule->set_version("v1");
    addRule->set_rule_type(static_cast<::pbv2::FileAccessRule::RuleType>(123));

    XCTAssertNil(FAARuleFromProtoFileAccessRule(wi));

    // Now use a valid rule type to ensure the rule parses
    addRule->set_rule_type(::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);
    XCTAssertNotNil(FAARuleFromProtoFileAccessRule(wi));
  }
}

- (void)testFAARuleFromProtoFileAccessRuleRemove {
  ::pbv2::FileAccessRule wi;
  ::pbv2::FileAccessRule::Remove *pbRemove = wi.mutable_remove();
  pbRemove->set_name("foo");

  SNTFileAccessRule *rule = FAARuleFromProtoFileAccessRule(wi);

  XCTAssertEqual(rule.state, SNTFileAccessRuleStateRemove);
  XCTAssertEqualObjects(rule.name, @"foo");
  XCTAssertNil(rule.details);
}

@end
