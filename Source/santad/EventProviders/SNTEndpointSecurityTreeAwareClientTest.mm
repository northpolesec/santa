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
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/santad/Metrics.h"

using santa::Message;
using santa::Processor;

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

@end
