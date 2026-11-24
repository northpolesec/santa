/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santad/EventProviders/SNTEndpointSecurityTreeAwareClient.h"

#include <EndpointSecurity/ESTypes.h>
#include <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/processtree/annotations/annotator.h"
#include "Source/common/processtree/process_tree.h"
#include "Source/common/processtree/process_tree_test_helpers.h"
#include "Source/santad/Metrics.h"

using santa::Message;
using santa::Processor;
using santa::santad::process_tree::Annotator;
using santa::santad::process_tree::ExitAndDrain;
using santa::santad::process_tree::Pid;
using santa::santad::process_tree::ProcessTreeTestPeer;

@interface SNTEndpointSecurityTreeAwareClient (Testing)
- (bool)eventWasAdded:(es_event_type_t)eventType;
@end

@interface SNTEndpointSecurityTreeAwareClientTest : XCTestCase
@end

@implementation SNTEndpointSecurityTreeAwareClientTest

- (void)testSubscribe {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, Subscribe).WillRepeatedly(testing::Return(true));

  SNTEndpointSecurityTreeAwareClient* treeClient =
      [[SNTEndpointSecurityTreeAwareClient alloc] initWithESAPI:mockESApi
                                                        metrics:nullptr
                                                      processor:Processor::kUnknown
                                                    processTree:nullptr];

  // Ensure no forced events initially set
  XCTAssertFalse([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_FORK]);
  XCTAssertFalse([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXEC]);
  XCTAssertFalse([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXIT]);

  // Subscribe with no events to trigger forced events added
  [treeClient subscribe:{}];

  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_FORK]);
  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXEC]);
  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXIT]);

  // Subscribing to one of the forced events results in that event not being tracked
  treeClient = [[SNTEndpointSecurityTreeAwareClient alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                               processor:Processor::kUnknown
                                                             processTree:nullptr];
  [treeClient subscribe:{ES_EVENT_TYPE_NOTIFY_EXEC}];

  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_FORK]);
  XCTAssertFalse([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXEC]);
  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXIT]);

  // A client subscribing to AUTH_EXEC still gets NOTIFY_EXEC force-added: ES
  // suppresses AUTH_EXEC delivery for binaries whose auth result is cached, so
  // AUTH_EXEC alone would miss those (cached) execs from the tree. NOTIFY_EXEC
  // is not cache-suppressed. The force-added NOTIFY_EXEC feeds the tree and is
  // filtered out before the client's own message handling.
  treeClient = [[SNTEndpointSecurityTreeAwareClient alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                               processor:Processor::kUnknown
                                                             processTree:nullptr];
  [treeClient subscribe:{ES_EVENT_TYPE_AUTH_EXEC}];

  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_FORK]);
  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXEC]);
  XCTAssertTrue([treeClient eventWasAdded:ES_EVENT_TYPE_NOTIFY_EXIT]);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testHandleContextMessageExpectedReturnNullTree {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockESApi, Subscribe).WillRepeatedly(testing::Return(true));

  // Check that tree aware clients that only subscribe to a subset of forced events
  // return appropriately from handleContextMessage based on which events for force-added.
  SNTEndpointSecurityTreeAwareClient* treeClient =
      [[SNTEndpointSecurityTreeAwareClient alloc] initWithESAPI:mockESApi
                                                        metrics:nullptr
                                                      processor:Processor::kUnknown
                                                    processTree:nullptr];

  [treeClient subscribe:{ES_EVENT_TYPE_NOTIFY_FORK}];

  {
    es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, NULL);
    Message msg(mockESApi, &esMsg);
    XCTAssertTrue([treeClient handleContextMessage:msg]);
  }
  {
    es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_FORK, NULL);
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([treeClient handleContextMessage:msg]);
  }
}

// Builds a tree that reaps an exited process one tick after the newest event,
// so a test can drain removals with a single later fork.
static std::shared_ptr<ProcessTreeTestPeer> MakeTestTree() {
  std::vector<std::unique_ptr<Annotator>> annotators{};
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators), 1);
  tree->InsertInit();
  return tree;
}

- (SNTEndpointSecurityTreeAwareClient*)
    authExecClientWithESAPI:(std::shared_ptr<MockEndpointSecurityAPI>)mockESApi
                       tree:(std::shared_ptr<ProcessTreeTestPeer>)tree {
  EXPECT_CALL(*mockESApi, Subscribe).WillRepeatedly(testing::Return(true));
  SNTEndpointSecurityTreeAwareClient* treeClient =
      [[SNTEndpointSecurityTreeAwareClient alloc] initWithESAPI:mockESApi
                                                        metrics:nullptr
                                                      processor:Processor::kUnknown
                                                    processTree:tree];
  // NOTIFY_FORK, NOTIFY_EXEC and NOTIFY_EXIT become added events.
  [treeClient subscribe:{ES_EVENT_TYPE_AUTH_EXEC}];
  return treeClient;
}

- (void)testAddedEventUpdatesTreeWithoutToken {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  auto tree = MakeTestTree();
  SNTEndpointSecurityTreeAwareClient* treeClient = [self authExecClientWithESAPI:mockESApi
                                                                            tree:tree];

  const Pid parent = {.pid = 2, .pidversion = 2};
  const Pid child = {.pid = 3, .pidversion = 3};
  tree->HandleFork(10, *tree->Get({.pid = 1, .pidversion = 1}), parent);

  es_file_t file = MakeESFile("foo");
  es_process_t parentProc = MakeESProcess(&file, MakeAuditToken(parent.pid, parent.pidversion));
  es_process_t childProc = MakeESProcess(&file, MakeAuditToken(child.pid, child.pidversion));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_FORK, &parentProc);
  esMsg.mach_time = 20;
  esMsg.event.fork.child = &childProc;

  Message msg(mockESApi, &esMsg);
  XCTAssertTrue([treeClient handleContextMessage:msg]);
  XCTAssertTrue(tree->Get(child).has_value(), @"the added event must still update the tree");

  // The message is still alive, but nothing holds the parent.
  ExitAndDrain(*tree, parent);
  XCTAssertFalse(tree->Get(parent).has_value(), @"an added event must not build a token");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testSubscribedEventHoldsToken {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockESApi, ExecArgCount).WillRepeatedly(testing::Return(0));
  auto tree = MakeTestTree();
  SNTEndpointSecurityTreeAwareClient* treeClient = [self authExecClientWithESAPI:mockESApi
                                                                            tree:tree];

  const Pid proc = {.pid = 2, .pidversion = 2};
  const Pid execd = {.pid = 2, .pidversion = 3};
  auto init = *tree->Get({.pid = 1, .pidversion = 1});
  tree->HandleFork(10, init, proc);

  es_file_t file = MakeESFile("foo");
  es_process_t procProc = MakeESProcess(&file, MakeAuditToken(proc.pid, proc.pidversion));
  es_process_t targetProc = MakeESProcess(&file, MakeAuditToken(execd.pid, execd.pidversion));
  targetProc.codesigning_flags = CS_ADHOC;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &procProc, ActionType::Auth);
  esMsg.mach_time = 20;
  esMsg.event.exec.target = &targetProc;

  {
    Message msg(mockESApi, &esMsg);
    XCTAssertFalse([treeClient handleContextMessage:msg]);
    XCTAssertTrue(tree->Get(execd).has_value());

    // HandleExec scheduled the pre-exec process for removal. The token holds it.
    tree->HandleFork(2000, init, {.pid = 99, .pidversion = 99});
    XCTAssertTrue(tree->Get(proc).has_value(), @"a subscribed event must hold a token");
  }

  // The message, and its token, are gone.
  XCTAssertFalse(tree->Get(proc).has_value());

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
