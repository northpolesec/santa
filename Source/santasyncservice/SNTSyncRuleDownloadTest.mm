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
#include "sync/v1.pb.h"

namespace pbv1 = ::santa::sync::v1;

@interface SNTSyncRuleDownload (Testing)
- (SNTFileAccessRule *)faaRuleFromProtoFAARuleRemove:
    (const ::pbv1::FileAccessRule::Remove &)removeRule;
- (NSArray *)pathsFromProtoFAARulePaths:
    (const google::protobuf::RepeatedPtrField<::pbv1::FileAccessRule::Path> &)pbPaths;
- (NSDictionary *)optionsFromProtoFAARuleAdd:(const ::pbv1::FileAccessRule::Add &)pbAddRule;
- (NSArray *)processesFromProtoFAARuleProcesses:
    (const google::protobuf::RepeatedPtrField<::pbv1::FileAccessRule::Process> &)pbProcesses;
- (SNTFileAccessRule *)fileAccessRuleFromProtoFileAccessRule:(const ::pbv1::FileAccessRule &)wi;
@end

@interface SNTSyncRuleDownloadTest : XCTestCase
@property SNTSyncState *syncState;
@property SNTSyncRuleDownload *sut;
@end

@implementation SNTSyncRuleDownloadTest

- (void)setUp {
  self.syncState = [[SNTSyncState alloc] init];
  self.sut = [[SNTSyncRuleDownload alloc] initWithState:self.syncState];
}

- (void)testPathsFromProtoFAARulePaths {
  ::pbv1::FileAccessRule::Add addRule;
  ::pbv1::FileAccessRule::Path *path = addRule.add_paths();
  path->set_path("/my/first/path");
  path->set_path_type(::pbv1::FileAccessRule::Path::PATH_TYPE_LITERAL);

  path = addRule.add_paths();
  path->set_path("/my/second/path");
  // Note: Leaving path type unspecified so the default is used

  path = addRule.add_paths();
  path->set_path("/my/*/path");
  path->set_path_type(::pbv1::FileAccessRule::Path::PATH_TYPE_PREFIX);

  NSArray *paths = [self.sut pathsFromProtoFAARulePaths:addRule.paths()];
  XCTAssertEqual(paths.count, 3);

  XCTAssertEqualObjects(paths[0][kWatchItemConfigKeyPathsPath], @"/my/first/path");
  XCTAssertFalse([paths[0][kWatchItemConfigKeyPathsIsPrefix] boolValue]);

  XCTAssertEqualObjects(paths[1][kWatchItemConfigKeyPathsPath], @"/my/second/path");
  XCTAssertFalse([paths[1][kWatchItemConfigKeyPathsIsPrefix] boolValue]);

  XCTAssertEqualObjects(paths[2][kWatchItemConfigKeyPathsPath], @"/my/*/path");
  XCTAssertTrue([paths[2][kWatchItemConfigKeyPathsIsPrefix] boolValue]);
}

- (void)testPathsFromProtoFAARulePathsBadValue {
  ::pbv1::FileAccessRule::Add addRule;
  ::pbv1::FileAccessRule::Path *path = addRule.add_paths();
  path->set_path("/my/first/path");
  path->set_path_type(::pbv1::FileAccessRule::Path::PATH_TYPE_LITERAL);

  path = addRule.add_paths();
  path->set_path("/my/second/path");
  path->set_path_type(static_cast<::pbv1::FileAccessRule::Path::PathType>(123));

  path = addRule.add_paths();
  path->set_path("/my/*/path");
  path->set_path_type(::pbv1::FileAccessRule::Path::PATH_TYPE_PREFIX);

  NSArray *paths = [self.sut pathsFromProtoFAARulePaths:addRule.paths()];
  XCTAssertNil(paths);
}

- (void)testOptionsFromProtoFAARuleAdd {
  {
    ::pbv1::FileAccessRule::Add addRule;
    addRule.set_rule_type(::pbv1::FileAccessRule::RULE_TYPE_PATHS_WITH_DENIED_PROCESSES);
    addRule.set_allow_read_access(true);
    addRule.set_block_violations(true);
    addRule.set_enable_silent_mode(true);
    addRule.set_enable_silent_tty_mode(true);
    addRule.set_block_message("this is a block");
    addRule.set_event_detail_text("details details details");
    addRule.set_event_detail_url("url url url");

    NSDictionary *opts = [self.sut optionsFromProtoFAARuleAdd:addRule];

    XCTAssertEqual(opts.count, 8);
    XCTAssertEqual(
        static_cast<santa::WatchItemRuleType>([opts[kWatchItemConfigKeyOptionsRuleType] intValue]),
        santa::WatchItemRuleType::kPathsWithDeniedProcesses);
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
    ::pbv1::FileAccessRule::Add addRule;
    NSDictionary *opts = [self.sut optionsFromProtoFAARuleAdd:addRule];

    XCTAssertEqual(opts.count, 5);

    XCTAssertEqual(
        static_cast<santa::WatchItemRuleType>([opts[kWatchItemConfigKeyOptionsRuleType] intValue]),
        santa::WatchItemRuleType::kPathsWithAllowedProcesses);
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
  ::pbv1::FileAccessRule::Add addRule;
  addRule.set_rule_type(static_cast<::pbv1::FileAccessRule::RuleType>(123));
  addRule.set_allow_read_access(true);
  addRule.set_block_violations(true);
  addRule.set_enable_silent_mode(true);
  addRule.set_enable_silent_tty_mode(true);
  addRule.set_block_message("this is a block");
  addRule.set_event_detail_text("details details details");
  addRule.set_event_detail_url("url url url");

  NSDictionary *opts = [self.sut optionsFromProtoFAARuleAdd:addRule];
  XCTAssertNil(opts);
}

- (void)testProcessesFromProtoFAARuleProcesses {
  ::pbv1::FileAccessRule::Add addRule;

  ::pbv1::FileAccessRule::Process *proc = addRule.add_processes();
  proc->set_cd_hash("abc");
  proc = addRule.add_processes();
  proc->set_cd_hash("def");
  proc = addRule.add_processes();
  proc->set_binary_path("/my/path/");

  NSArray *procs = [self.sut processesFromProtoFAARuleProcesses:addRule.processes()];
  XCTAssertEqual(procs.count, 3);
  XCTAssertEqualObjects(procs[0][kWatchItemConfigKeyProcessesCDHash], @"abc");
  XCTAssertEqualObjects(procs[1][kWatchItemConfigKeyProcessesCDHash], @"def");
  XCTAssertEqualObjects(procs[2][kWatchItemConfigKeyProcessesBinaryPath], @"/my/path/");

  // Should return an empty array when no processes are added
  addRule.clear_processes();
  procs = [self.sut processesFromProtoFAARuleProcesses:addRule.processes()];
  XCTAssertEqual(procs.count, 0);

  // Should return nil when an invalid identifier is used
  proc = addRule.add_processes();
  procs = [self.sut processesFromProtoFAARuleProcesses:addRule.processes()];
  XCTAssertNil(procs);
}

- (void)testFileAccessRuleFromProtoFileAccessRuleAdd {
  ::pbv1::FileAccessRule wi;
  ::pbv1::FileAccessRule::Add *addRule = wi.mutable_add();
  ::pbv1::FileAccessRule::Path *path = addRule->add_paths();
  path->set_path("/foo");
  path->set_path_type(::pbv1::FileAccessRule::Path::PATH_TYPE_LITERAL);
  path = addRule->add_paths();
  path->set_path("/bar");
  path->set_path_type(::pbv1::FileAccessRule::Path::PATH_TYPE_PREFIX);

  addRule->set_rule_type(::pbv1::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS);
  addRule->set_allow_read_access(true);
  addRule->set_block_violations(true);
  addRule->set_enable_silent_mode(true);
  addRule->set_enable_silent_tty_mode(true);
  addRule->set_block_message("this is a block");
  addRule->set_event_detail_text("details details details");
  addRule->set_event_detail_url("url url url");

  ::pbv1::FileAccessRule::Process *proc = addRule->add_processes();
  proc->set_team_id("my.tid");
  proc = addRule->add_processes();
  proc->set_cd_hash("abc");
  proc = addRule->add_processes();
  proc->set_binary_path("/my/path/");

  SNTFileAccessRule *rule = [self.sut fileAccessRuleFromProtoFileAccessRule:wi];
  XCTAssertEqual(rule.state, SNTFileAccessRuleStateAdd);

  // Spot check
  XCTAssertEqual([rule.details[kWatchItemConfigKeyPaths] count], 2);
  XCTAssertEqualObjects(rule.details[kWatchItemConfigKeyPaths][1][kWatchItemConfigKeyPathsPath],
                        @"/bar");
  XCTAssertEqual([rule.details[kWatchItemConfigKeyProcesses] count], 3);
  XCTAssertEqualObjects(
      rule.details[kWatchItemConfigKeyProcesses][0][kWatchItemConfigKeyProcessesTeamID], @"my.tid");
}

- (void)testFileAccessRuleFromProtoFileAccessRuleRemove {
  ::pbv1::FileAccessRule wi;
  ::pbv1::FileAccessRule::Remove *pbRemove = wi.mutable_remove();
  pbRemove->set_name("foo");

  SNTFileAccessRule *rule = [self.sut fileAccessRuleFromProtoFileAccessRule:wi];

  XCTAssertEqual(rule.state, SNTFileAccessRuleStateRemove);
  XCTAssertEqualObjects(rule.name, @"foo");
  XCTAssertNil(rule.details);
}

@end
