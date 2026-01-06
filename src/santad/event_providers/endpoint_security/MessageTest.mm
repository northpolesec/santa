/// Copyright 2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libproc.h>
#include <stdlib.h>

#include "src/common/AuditUtilities.h"
#include "src/common/TestUtils.h"
#include "src/santad/event_providers/endpoint_security/Message.h"
#include "src/santad/event_providers/endpoint_security/MockEndpointSecurityAPI.h"

using santa::Message;

bool IsPidInUse(pid_t pid) {
  char pname[MAXCOMLEN * 2 + 1] = {};
  errno = 0;
  if (proc_name(pid, pname, sizeof(pname)) <= 0 && errno == ESRCH) {
    return false;
  }

  // The PID may or may not actually be in use, but assume it is
  return true;
}

// Try to find an unused PID by looking for libproc returning ESRCH errno.
// Start searching backwards from PID_MAX to increase likelyhood that the
// returned PID will still be unused by the time it's being used.
// TODO(mlw): Alternatively, we could inject the `proc_name` function into
// the `Message` object to remove the guesswork here.
pid_t AttemptToFindUnusedPID() {
  for (pid_t pid = 99999 /* PID_MAX */; pid > 1; pid--) {
    if (!IsPidInUse(pid)) {
      return pid;
    }
  }

  return 0;
}

std::string GetProcessPath(pid_t pid) {
  char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {};
  int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
  if (ret > 0) {
    return std::string(pathbuf);
  } else {
    return nil;
  }
}

@interface MessageTest : XCTestCase
@end

@implementation MessageTest

- (void)setUp {
}

- (void)testConstructorsAndDestructors {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Constructing a `Message` retains the underlying `es_message_t` and it is
  // released when the `Message` object is destructed.
  {
    Message m(mockESApi, &esMsg);
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testCopyConstructor {
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(56, 78));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ReleaseMessage(testing::_))
      .Times(2)
      .After(EXPECT_CALL(*mockESApi, RetainMessage(testing::_)).Times(2));

  {
    Message msg1(mockESApi, &esMsg);
    Message msg2(msg1);

    // Both messages should now point to the same `es_message_t`
    XCTAssertEqual(msg1.operator->(), &esMsg);
    XCTAssertEqual(msg2.operator->(), &esMsg);
  }

  // Ensure the retain/release mocks were called the expected number of times
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testGetParentProcessName {
  // Construct a message where the parent pid is ourself
  es_file_t procFile = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(getpid(), 0));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Search for an *existing* parent process.
  {
    Message msg(mockESApi, &esMsg);

    std::string got = msg.ParentProcessName();
    std::string want = getprogname();

    XCTAssertCppStringEqual(got, want);
  }

  // Search for a *non-existent* parent process.
  {
    pid_t newPpid = AttemptToFindUnusedPID();
    proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(newPpid, 34));

    Message msg(mockESApi, &esMsg);

    std::string got = msg.ParentProcessName();
    std::string want = "";

    XCTAssertCppStringEqual(got, want);
  }
}

- (void)testGetParentProcessPath {
  // Construct a message where the parent pid is ourself
  es_file_t procFile = MakeESFile("foo");
  std::optional<audit_token_t> tok = santa::GetMyAuditToken();
  if (!tok.has_value()) {
    XCTFail("Failed to get audit token");
    return;
  }
  es_process_t proc = MakeESProcess(&procFile, MakeAuditToken(12, 34),
                                    MakeAuditToken(santa::Pid(*tok), santa::Pidversion(*tok)));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, &proc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Search for an *existing* parent process.
  {
    Message msg(mockESApi, &esMsg);

    std::string got = msg.ParentProcessPath();
    std::string want = GetProcessPath(getpid());

    XCTAssertCppStringEqual(got, want);
  }

  // Search for a *non-existent* parent process.
  {
    pid_t newPpid = AttemptToFindUnusedPID();
    proc = MakeESProcess(&procFile, MakeAuditToken(12, 34), MakeAuditToken(newPpid, 34));

    Message msg(mockESApi, &esMsg);

    std::string got = msg.ParentProcessPath();
    std::string want = "";

    XCTAssertCppStringEqual(got, want);
  }
}

- (void)testPathTargets {
  // This test ensures that the `GetPathTargets` functions returns the
  // expected combination of targets for each handled event variant
  es_file_t testFile1 = MakeESFile("test_file_1", MakeStat(100));
  es_file_t testFile2 = MakeESFile("test_file_2", MakeStat(200));
  es_file_t testDir = MakeESFile("test_dir", MakeStat(300));
  es_string_token_t testTok = MakeESStringToken("test_tok");
  std::string dirTok = std::string(testDir.path.data) + "/" + std::string(testTok.data);

  es_message_t esMsg;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    esMsg.event.open.file = &testFile1;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertTrue(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, &testFile1);
    XCTAssertTrue(msg.HasPathTarget(0));
    XCTAssertFalse(msg.HasPathTarget(1));
  }

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_LINK;
    esMsg.event.link.source = &testFile1;
    esMsg.event.link.target_dir = &testDir;
    esMsg.event.link.target_filename = testTok;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 2);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, &testFile1);
    XCTAssertCppStringEqual(targets[1].path, dirTok);
    XCTAssertFalse(targets[1].is_readable);
    XCTAssertEqual(targets[1].unsafe_file, nullptr);
    XCTAssertTrue(msg.HasPathTarget(0));
    XCTAssertTrue(msg.HasPathTarget(1));
    XCTAssertFalse(msg.HasPathTarget(2));
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &testFile1;

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = &testFile2;

      std::vector<Message::PathTarget> targets = msg.PathTargets();

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertFalse(targets[0].is_readable);
      XCTAssertEqual(targets[0].unsafe_file, &testFile1);
      XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
      XCTAssertFalse(targets[1].is_readable);
      XCTAssertEqual(targets[1].unsafe_file, &testFile2);
    }

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &testDir;
      esMsg.event.rename.destination.new_path.filename = testTok;

      std::vector<Message::PathTarget> targets = msg.PathTargets();

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertFalse(targets[0].is_readable);
      XCTAssertEqual(targets[0].unsafe_file, &testFile1);
      XCTAssertCppStringEqual(targets[1].path, dirTok);
      XCTAssertFalse(targets[1].is_readable);
      XCTAssertEqual(targets[1].unsafe_file, nullptr);
    }
  }

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    esMsg.event.unlink.target = &testFile1;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, &testFile1);
  }

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    esMsg.event.clone.source = &testFile1;
    esMsg.event.clone.target_dir = &testDir;
    esMsg.event.clone.target_name = testTok;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 2);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertTrue(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, &testFile1);
    XCTAssertCppStringEqual(targets[1].path, dirTok);
    XCTAssertFalse(targets[1].is_readable);
    XCTAssertEqual(targets[1].unsafe_file, nullptr);
  }

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXCHANGEDATA;
    esMsg.event.exchangedata.file1 = &testFile1;
    esMsg.event.exchangedata.file2 = &testFile2;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 2);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, &testFile1);
    XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
    XCTAssertFalse(targets[1].is_readable);
    XCTAssertEqual(targets[1].unsafe_file, &testFile2);
  }

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CREATE;
    esMsg.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
    esMsg.event.create.destination.new_path.dir = &testDir;
    esMsg.event.create.destination.new_path.filename = testTok;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCppStringEqual(targets[0].path, dirTok);
    XCTAssertFalse(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, nullptr);
  }

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_AUTH_TRUNCATE;
    esMsg.event.truncate.target = &testFile1;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 1);
    XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
    XCTAssertFalse(targets[0].is_readable);
    XCTAssertEqual(targets[0].unsafe_file, &testFile1);
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
    esMsg.event.copyfile.source = &testFile1;
    esMsg.event.copyfile.target_dir = &testDir;
    esMsg.event.copyfile.target_name = testTok;

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.target_file = nullptr;

      std::vector<Message::PathTarget> targets = msg.PathTargets();

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertTrue(targets[0].is_readable);
      XCTAssertEqual(targets[0].unsafe_file, &testFile1);
      XCTAssertCppStringEqual(targets[1].path, dirTok);
      XCTAssertFalse(targets[1].is_readable);
      XCTAssertEqual(targets[1].unsafe_file, nullptr);
    }

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.target_file = &testFile2;

      std::vector<Message::PathTarget> targets = msg.PathTargets();

      XCTAssertEqual(targets.size(), 2);
      XCTAssertCStringEqual(targets[0].path.c_str(), testFile1.path.data);
      XCTAssertTrue(targets[0].is_readable);
      XCTAssertEqual(targets[0].unsafe_file, &testFile1);
      XCTAssertCStringEqual(targets[1].path.c_str(), testFile2.path.data);
      XCTAssertFalse(targets[1].is_readable);
      XCTAssertEqual(targets[1].unsafe_file, &testFile2);
    }
  }

  // Test some event type without any targets
  {
    Message msg(mockESApi, &esMsg);
    esMsg.event_type = ES_EVENT_TYPE_NOTIFY_OD_DELETE_GROUP;

    std::vector<Message::PathTarget> targets = msg.PathTargets();

    XCTAssertEqual(targets.size(), 0);
    XCTAssertFalse(msg.HasPathTarget(0));
  }
}

@end
