/// Copyright 2022 Google Inc. All rights reserved.
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

#include <EndpointSecurity/ESTypes.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstddef>

#include <memory>
#include <optional>
#include <set>

#include "Source/common/Platform.h"
#include "Source/common/PrefixTree.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/common/TestUtils.h"
#include "Source/common/Unit.h"
#include "Source/common/es/Client.h"
#include "Source/common/es/EnrichedTypes.h"
#include "Source/common/es/Enricher.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/es/MockEnricher.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#include "Source/santad/Logs/EndpointSecurity/MockLogger.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTDecisionCache.h"

using santa::EnrichedMessage;
using santa::EventDisposition;
using santa::Message;
using santa::PrefixTree;
using santa::Processor;
using santa::TelemetryEvent;
using santa::Unit;

@interface SNTEndpointSecurityRecorderTest : XCTestCase
@property id mockConfigurator;
@end

@implementation SNTEndpointSecurityRecorderTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  NSString* testPattern = @"^/foo/match.*";
  NSRegularExpression* re = [NSRegularExpression regularExpressionWithPattern:testPattern
                                                                      options:0
                                                                        error:NULL];
  OCMStub([self.mockConfigurator fileChangesRegex]).andReturn(re);
}

- (std::set<es_event_type_t>)expectedSubscriptions {
  std::set<es_event_type_t> expectedEventSubs{ES_EVENT_TYPE_NOTIFY_CLONE,
                                              ES_EVENT_TYPE_NOTIFY_CLOSE,
                                              ES_EVENT_TYPE_NOTIFY_COPYFILE,
                                              ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
                                              ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
                                              ES_EVENT_TYPE_NOTIFY_EXEC,
                                              ES_EVENT_TYPE_NOTIFY_FORK,
                                              ES_EVENT_TYPE_NOTIFY_EXIT,
                                              ES_EVENT_TYPE_NOTIFY_LINK,
                                              ES_EVENT_TYPE_NOTIFY_RENAME,
                                              ES_EVENT_TYPE_NOTIFY_UNLINK,
                                              ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
                                              ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN,
                                              ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT,
                                              ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
                                              ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
                                              ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
                                              ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH,
                                              ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN,
                                              ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT,
                                              ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
                                              ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT,
                                              ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
                                              ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
                                              ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
                                              ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
                                              ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND_RESUME};

#if HAVE_MACOS_15
  if (@available(macOS 15.0, *)) {
    expectedEventSubs.insert(ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE);
  }
#endif  // HAVE_MACOS_15

#if HAVE_MACOS_15_4
  if (@available(macOS 15.4, *)) {
    expectedEventSubs.insert(ES_EVENT_TYPE_NOTIFY_TCC_MODIFY);
  }
#endif  // HAVE_MACOS_15_4

  return expectedEventSubs;
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs = [self expectedSubscriptions];

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  id recorderClient = [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                               processor:Processor::kRecorder];

  EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs)).WillOnce(testing::Return(true));

  [recorderClient enable];

  for (const auto& event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testTelemetryMappings {
  std::set<es_event_type_t> expectedEventSubs = [self expectedSubscriptions];
  // Make sure a TelemetryEvent exists for each subscription
  for (const auto& event : expectedEventSubs) {
    XCTAssertNotEqual(santa::ESEventToTelemetryEvent(event), TelemetryEvent::kNone,
                      "Unexpected TelemetryEvent for ES event: %d", event);
    ;
  }
}

typedef void (^TestHelperBlock)(es_message_t* message,
                                std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
                                SNTEndpointSecurityRecorder* recorderClient,
                                std::shared_ptr<PrefixTree<Unit>> prefixTree,
                                dispatch_semaphore_t* sema, dispatch_semaphore_t* semaMetrics);

es_file_t targetFileMatchesRegex = MakeESFile("/foo/matches");
es_file_t targetFileMatchesAlsoRegex = MakeESFile("/foo/matches_also");
es_file_t targetFileMissesRegex = MakeESFile("/foo/misses");

- (void)handleMessageShouldLog:(BOOL)shouldLog
                     withBlock:(TestHelperBlock)testBlock
                 telemetryMask:(TelemetryEvent)telemetryMask {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_CLOSE, &proc, ActionType::Auth);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Create a fake enriched message. It isn't used other than to inject a valid
  // returned object from a mocked Enrich method. The purpose is to ensure the
  // check in the recorder that a message is enriched always succeeds.
  es_message_t fakeEnrichedMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, NULL);
  std::unique_ptr<EnrichedMessage> enrichedMsg = std::make_unique<EnrichedMessage>(EnrichedMessage(
      santa::EnrichedExit(Message(mockESApi, &fakeEnrichedMsg), santa::EnrichedProcess())));

  auto mockEnricher = std::make_shared<santa::MockEnricher>();

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  // NOTE: Currently unable to create a partial mock of the
  // `SNTEndpointSecurityRecorder` object. There is a bug in OCMock that doesn't
  // properly handle the `processEnrichedMessage:handler:` block. Instead this
  // test will mock the `Log` method that is called in the handler block.
  __block dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto mockLogger = std::make_shared<MockLogger>();
  mockLogger->SetTelemetryMask(telemetryMask);

  if (shouldLog) {
    EXPECT_CALL(*mockEnricher, Enrich).WillOnce(testing::Return(std::move(enrichedMsg)));
    EXPECT_CALL(*mockLogger, Log).WillOnce(testing::InvokeWithoutArgs(^() {
      dispatch_semaphore_signal(sema);
    }));
  } else {
    EXPECT_CALL(*mockEnricher, Enrich).Times(0);
    EXPECT_CALL(*mockLogger, Log).Times(0);
  }

  auto prefixTree = std::make_shared<PrefixTree<Unit>>();

  id mockCC = OCMStrictClassMock([SNTCompilerController class]);

  SNTEndpointSecurityRecorder* recorderClient =
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                                  logger:mockLogger
                                                enricher:mockEnricher
                                      compilerController:mockCC
                               loginWindowSessionHandler:nil
                                              prefixTree:prefixTree
                                             processTree:nullptr];

  testBlock(&esMsg, mockESApi, mockCC, recorderClient, prefixTree, &sema, &semaMetrics);

  // Ensure the deleter is called on the fake enriched message so that the underlying message gets
  // released. Otherwise, various gmock warnings about uninteresting calls are printed because the
  // object isn't deleted until after expectations are verified below.
  enrichedMsg.reset();

  XCTAssertTrue(OCMVerifyAll(mockCC));

  XCTBubbleMockVerifyAndClearExpectations(mockEnricher.get());
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockLogger.get());

  [mockCC stopMocking];
}

- (void)handleMessageShouldLog:(BOOL)shouldLog withBlock:(TestHelperBlock)testBlock {
  [self handleMessageShouldLog:shouldLog
                     withBlock:testBlock
                 telemetryMask:TelemetryEvent::kEverything];
}

- (void)testHandleEventCloseMappedWritableMatchesRegex {
  // CLOSE not modified, but was_mapped_writable, and matches fileChangesRegex
  TestHelperBlock testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = false;
        esMsg->event.close.was_mapped_writable = true;
        esMsg->event.close.target = &targetFileMatchesRegex;
        Message msg(mockESApi, esMsg);

        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTAssertEqual(d, EventDisposition::kProcessed);
                                      dispatch_semaphore_signal(*semaMetrics);
                                    }]);
        XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
        XCTAssertSemaTrue(*sema, 5, "Log wasn't called within expected time window");
      };

  [self handleMessageShouldLog:YES withBlock:testBlock];
}

- (void)testHandleEventCloseMappedWritableMissesRegex {
  // CLOSE not modified, but was_mapped_writable, and does not match fileChangesRegex
  TestHelperBlock testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = false;
        esMsg->event.close.was_mapped_writable = true;
        esMsg->event.close.target = &targetFileMissesRegex;
        Message msg(mockESApi, esMsg);

        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTFail("Metrics record callback should not be called here");
                                    }]);
      };

  [self handleMessageShouldLog:NO withBlock:testBlock];
}

- (void)testHandleMessage {
  // CLOSE not modified, bail early
  TestHelperBlock testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = false;
        esMsg->event.close.target = NULL;

        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTFail("Metrics record callback should not be called here");
                                    }]);
      };

  [self handleMessageShouldLog:NO withBlock:testBlock];

  // CLOSE modified, and matches fileChangesRegex
  testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = true;
        esMsg->event.close.target = &targetFileMatchesRegex;
        Message msg(mockESApi, esMsg);

        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

        [recorderClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(*semaMetrics);
                   }];

        XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
        XCTAssertSemaTrue(*sema, 5, "Log wasn't called within expected time window");
      };

  [self handleMessageShouldLog:YES withBlock:testBlock];

  // CLOSE modified, but doesn't match fileChangesRegex
  testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = true;
        esMsg->event.close.target = &targetFileMissesRegex;
        Message msg(mockESApi, esMsg);
        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();
        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTFail("Metrics record callback should not be called here");
                                    }]);
      };

  [self handleMessageShouldLog:NO withBlock:testBlock];

  // CLONE Prefix match, bail early
  testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLONE;
        esMsg->event.clone.source = &targetFileMatchesRegex;
        esMsg->event.clone.target_dir = &targetFileMissesRegex;
        esMsg->event.clone.target_name = MakeESStringToken("foo");
        prefixTree->InsertPrefix(esMsg->event.clone.source->path.data, Unit{});
        Message msg(mockESApi, esMsg);
        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();
        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTAssertEqual(d, EventDisposition::kDropped);
                                      dispatch_semaphore_signal(*semaMetrics);
                                    }]);
        XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
      };

  [self handleMessageShouldLog:NO withBlock:testBlock];

  // COPYFILE Matches regex, not prefix, handle message
  testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_COPYFILE;
        esMsg->event.copyfile.source = &targetFileMatchesAlsoRegex;
        esMsg->event.copyfile.target_file = &targetFileMissesRegex;
        Message msg(mockESApi, esMsg);
        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();
        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTAssertEqual(d, EventDisposition::kProcessed);
                                      dispatch_semaphore_signal(*semaMetrics);
                                    }]);
        XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
        XCTAssertSemaTrue(*sema, 5, "Log wasn't called within expected time window");
      };

  [self handleMessageShouldLog:YES withBlock:testBlock];

  // UNLINK, but doesn't match fileChangesRegex
  testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_UNLINK;
        esMsg->event.unlink.target = &targetFileMissesRegex;
        Message msg(mockESApi, esMsg);
        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();
        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTFail("Metrics record callback should not be called here");
                                    }]);
      };

  [self handleMessageShouldLog:NO withBlock:testBlock];

  // EXCHANGEDATA, Prefix match, bail early
  testBlock =
      ^(es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
        SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
        __autoreleasing dispatch_semaphore_t* sema,
        __autoreleasing dispatch_semaphore_t* semaMetrics) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA;
        esMsg->event.exchangedata.file1 = &targetFileMatchesRegex;
        esMsg->event.exchangedata.file2 = &targetFileMissesRegex;
        prefixTree->InsertPrefix(esMsg->event.exchangedata.file1->path.data, Unit{});
        Message msg(mockESApi, esMsg);
        OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();
        XCTAssertNoThrow([recorderClient handleMessage:Message(mockESApi, esMsg)
                                    recordEventMetrics:^(EventDisposition d) {
                                      XCTAssertEqual(d, EventDisposition::kDropped);
                                      dispatch_semaphore_signal(*semaMetrics);
                                    }]);

        XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
      };

  [self handleMessageShouldLog:NO withBlock:testBlock];

  // LINK, Prefix match, bail early
  testBlock = ^(
      es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
      SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
      __autoreleasing dispatch_semaphore_t* sema, __autoreleasing dispatch_semaphore_t* semaMetrics)

  {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_LINK;
    esMsg->event.link.source = &targetFileMatchesRegex;
    esMsg->event.link.target_dir = &targetFileMissesRegex;
    esMsg->event.link.target_filename = MakeESStringToken("foo");
    prefixTree->InsertPrefix(esMsg->event.link.source->path.data, Unit{});
    Message msg(mockESApi, esMsg);

    OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

    [recorderClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kDropped);
                 dispatch_semaphore_signal(*semaMetrics);
               }];

    XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
  };

  [self handleMessageShouldLog:NO withBlock:testBlock];

  // EXIT, message handled
  testBlock = ^(
      es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
      SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
      __autoreleasing dispatch_semaphore_t* sema, __autoreleasing dispatch_semaphore_t* semaMetrics)

  {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_EXIT;
    Message msg(mockESApi, esMsg);

    OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

    [recorderClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kDropped);
                 dispatch_semaphore_signal(*semaMetrics);
               }];

    XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
  };

  // Use a bitmask without EXIT specified
  [self handleMessageShouldLog:NO
                     withBlock:testBlock
                 telemetryMask:santa::TelemetryConfigToBitmask(@[ @"execution" ])];

  // FORK, message handled
  testBlock = ^(
      es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
      SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
      __autoreleasing dispatch_semaphore_t* sema, __autoreleasing dispatch_semaphore_t* semaMetrics)

  {
    esMsg->event_type = ES_EVENT_TYPE_NOTIFY_FORK;
    Message msg(mockESApi, esMsg);

    OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

    [recorderClient handleMessage:std::move(msg)
               recordEventMetrics:^(EventDisposition d) {
                 XCTAssertEqual(d, EventDisposition::kProcessed);
                 dispatch_semaphore_signal(*semaMetrics);
               }];

    XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
  };

  [self handleMessageShouldLog:YES withBlock:testBlock];

  XCTAssertTrue(OCMVerifyAll(self.mockConfigurator));
}

es_file_t dirFoo = MakeESFile("/foo");
es_file_t targetFileMatchesRegexFiltered = MakeESFile("/foo/matches/filtered");
es_file_t targetFileMatchesRegexInvalidUTF8 = MakeESFile("/foo/matches\xff\xfe");
constexpr const char* kFilteredPrefix = "/foo/matches/";

// Handles a file change event built by `setup` and verifies the outcome. A
// disposition of kProcessed means the event is logged, kDropped means it was
// prefix filtered, and nullopt means it was filtered without recording metrics.
- (void)checkFileChangeEvent:(void (^)(es_message_t* esMsg,
                                       std::shared_ptr<PrefixTree<Unit>> prefixTree))setup
                 disposition:(std::optional<EventDisposition>)disposition {
  TestHelperBlock testBlock = ^(
      es_message_t* esMsg, std::shared_ptr<MockEndpointSecurityAPI> mockESApi, id mockCC,
      SNTEndpointSecurityRecorder* recorderClient, std::shared_ptr<PrefixTree<Unit>> prefixTree,
      __autoreleasing dispatch_semaphore_t* sema,
      __autoreleasing dispatch_semaphore_t* semaMetrics) {
    setup(esMsg, prefixTree);
    Message msg(mockESApi, esMsg);
    OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

    XCTAssertNoThrow([recorderClient handleMessage:std::move(msg)
                                recordEventMetrics:^(EventDisposition d) {
                                  if (disposition.has_value()) {
                                    XCTAssertEqual(d, *disposition);
                                  } else {
                                    XCTFail("Metrics record callback should not be called here");
                                  }
                                  dispatch_semaphore_signal(*semaMetrics);
                                }]);

    if (disposition.has_value()) {
      XCTAssertSemaTrue(*semaMetrics, 5, "Metrics not recorded within expected window");
    }
    if (disposition == EventDisposition::kProcessed) {
      XCTAssertSemaTrue(*sema, 5, "Log wasn't called within expected time window");
    }
  };

  [self handleMessageShouldLog:(disposition == EventDisposition::kProcessed) withBlock:testBlock];
}

- (void)testHandleMessageMultipleTargets {
  // RENAME to a new path: source misses regex, destination matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        esMsg->event.rename.source = &targetFileMissesRegex;
        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        esMsg->event.rename.destination.new_path.dir = &dirFoo;
        esMsg->event.rename.destination.new_path.filename = MakeESStringToken("matches_new");
      }
               disposition:EventDisposition::kProcessed];

  // RENAME over an existing file: source prefix filtered, destination matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        esMsg->event.rename.source = &targetFileMatchesRegexFiltered;
        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
        esMsg->event.rename.destination.existing_file = &targetFileMatchesAlsoRegex;
        prefixTree->InsertPrefix(kFilteredPrefix, Unit{});
      }
               disposition:EventDisposition::kProcessed];

  // RENAME: both targets prefix filtered
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        esMsg->event.rename.source = &targetFileMatchesRegexFiltered;
        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        esMsg->event.rename.destination.new_path.dir = &targetFileMatchesRegex;
        esMsg->event.rename.destination.new_path.filename = MakeESStringToken("filtered_new");
        prefixTree->InsertPrefix(kFilteredPrefix, Unit{});
      }
               disposition:EventDisposition::kDropped];

  // RENAME: source prefix filtered, destination misses regex
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        esMsg->event.rename.source = &targetFileMatchesRegexFiltered;
        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
        esMsg->event.rename.destination.existing_file = &targetFileMissesRegex;
        prefixTree->InsertPrefix(kFilteredPrefix, Unit{});
      }
               disposition:EventDisposition::kDropped];

  // RENAME: both targets miss regex
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        esMsg->event.rename.source = &targetFileMissesRegex;
        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
        esMsg->event.rename.destination.new_path.dir = &dirFoo;
        esMsg->event.rename.destination.new_path.filename = MakeESStringToken("misses_new");
      }
               disposition:std::nullopt];

  // CLOSE: path is not valid UTF-8, treated as a regex miss
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLOSE;
        esMsg->event.close.modified = true;
        esMsg->event.close.target = &targetFileMatchesRegexInvalidUTF8;
      }
               disposition:std::nullopt];

  // RENAME: source is not valid UTF-8, destination matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_RENAME;
        esMsg->event.rename.source = &targetFileMatchesRegexInvalidUTF8;
        esMsg->event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
        esMsg->event.rename.destination.existing_file = &targetFileMatchesAlsoRegex;
      }
               disposition:EventDisposition::kProcessed];

  // CLONE: source misses regex, target matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_CLONE;
        esMsg->event.clone.source = &targetFileMissesRegex;
        esMsg->event.clone.target_dir = &dirFoo;
        esMsg->event.clone.target_name = MakeESStringToken("matches_clone");
      }
               disposition:EventDisposition::kProcessed];

  // COPYFILE to a new file: source misses regex, target matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_COPYFILE;
        esMsg->event.copyfile.source = &targetFileMissesRegex;
        esMsg->event.copyfile.target_file = nullptr;
        esMsg->event.copyfile.target_dir = &dirFoo;
        esMsg->event.copyfile.target_name = MakeESStringToken("matches_copy");
      }
               disposition:EventDisposition::kProcessed];

  // EXCHANGEDATA: file1 misses regex, file2 matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA;
        esMsg->event.exchangedata.file1 = &targetFileMissesRegex;
        esMsg->event.exchangedata.file2 = &targetFileMatchesRegex;
      }
               disposition:EventDisposition::kProcessed];

  // LINK: source misses regex, new link matches
  [self
      checkFileChangeEvent:^(es_message_t* esMsg, std::shared_ptr<PrefixTree<Unit>> prefixTree) {
        esMsg->event_type = ES_EVENT_TYPE_NOTIFY_LINK;
        esMsg->event.link.source = &targetFileMissesRegex;
        esMsg->event.link.target_dir = &dirFoo;
        esMsg->event.link.target_filename = MakeESStringToken("matches_link");
      }
               disposition:EventDisposition::kProcessed];
}

// When NOTIFY_EXEC arrives for a held execution, logging is skipped because the
// execution controller logs it once the hold resolves.
- (void)checkHeldExecSkipsLogging:(SNTCachedDecision*)cd {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t execProc = MakeESProcess(&execFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, &proc, ActionType::Notify);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  auto mockEnricher = std::make_shared<santa::MockEnricher>();
  auto mockLogger = std::make_shared<MockLogger>();
  mockLogger->SetTelemetryMask(TelemetryEvent::kEverything);
  auto prefixTree = std::make_shared<PrefixTree<Unit>>();

  // Enricher and Logger should NOT be called for a held execution
  EXPECT_CALL(*mockEnricher, Enrich).Times(0);
  EXPECT_CALL(*mockLogger, Log).Times(0);

  id mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([mockDecisionCache sharedCache]).andReturn(mockDecisionCache);
  OCMStub([mockDecisionCache cachedDecisionForFile:esMsg.event.exec.target->executable->stat])
      .ignoringNonObjectArgs()
      .andReturn(cd);

  id mockCC = OCMStrictClassMock([SNTCompilerController class]);
  Message msg(mockESApi, &esMsg);
  OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

  SNTEndpointSecurityRecorder* recorderClient =
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                                  logger:mockLogger
                                                enricher:mockEnricher
                                      compilerController:mockCC
                               loginWindowSessionHandler:nil
                                              prefixTree:prefixTree
                                             processTree:nullptr];

  __block BOOL metricsRecorded = NO;
  [recorderClient handleMessage:Message(mockESApi, &esMsg)
             recordEventMetrics:^(EventDisposition d) {
               metricsRecorded = YES;
             }];

  // Metrics callback should not have been called (we returned early)
  XCTAssertFalse(metricsRecorded);

  XCTAssertTrue(OCMVerifyAll(mockCC));
  XCTBubbleMockVerifyAndClearExpectations(mockEnricher.get());
  XCTBubbleMockVerifyAndClearExpectations(mockLogger.get());
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  [mockCC stopMocking];
  [mockDecisionCache stopMocking];
}

- (void)testHandleExecWithHoldAndAskSkipsLogging {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.holdAndAsk = YES;
  [self checkHeldExecSkipsLogging:cd];
}

- (void)testHandleExecHeldForTransitiveRuleSkipsLogging {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.heldForTransitiveRule = YES;
  [self checkHeldExecSkipsLogging:cd];
}

- (void)testHandleExecWithoutHoldAndAskLogsNormally {
  // When NOTIFY_EXEC arrives without holdAndAsk set, logging should proceed normally.
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t execProc = MakeESProcess(&execFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, &proc, ActionType::Notify);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Create a fake enriched message
  es_message_t fakeEnrichedMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, NULL);
  std::unique_ptr<EnrichedMessage> enrichedMsg = std::make_unique<EnrichedMessage>(EnrichedMessage(
      santa::EnrichedExit(Message(mockESApi, &fakeEnrichedMsg), santa::EnrichedProcess())));

  auto mockEnricher = std::make_shared<santa::MockEnricher>();
  auto mockLogger = std::make_shared<MockLogger>();
  mockLogger->SetTelemetryMask(TelemetryEvent::kEverything);
  auto prefixTree = std::make_shared<PrefixTree<Unit>>();

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Enricher and Logger SHOULD be called when holdAndAsk is not set
  EXPECT_CALL(*mockEnricher, Enrich).WillOnce(testing::Return(std::move(enrichedMsg)));
  EXPECT_CALL(*mockLogger, Log).WillOnce(testing::InvokeWithoutArgs(^() {
    dispatch_semaphore_signal(sema);
  }));

  // Mock decision cache to return a decision with holdAndAsk=NO
  id mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([mockDecisionCache sharedCache]).andReturn(mockDecisionCache);
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.holdAndAsk = NO;
  OCMStub([mockDecisionCache cachedDecisionForFile:esMsg.event.exec.target->executable->stat])
      .ignoringNonObjectArgs()
      .andReturn(cd);

  id mockCC = OCMStrictClassMock([SNTCompilerController class]);
  Message msg(mockESApi, &esMsg);
  OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

  SNTEndpointSecurityRecorder* recorderClient =
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                                  logger:mockLogger
                                                enricher:mockEnricher
                                      compilerController:mockCC
                               loginWindowSessionHandler:nil
                                              prefixTree:prefixTree
                                             processTree:nullptr];

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);
  [recorderClient handleMessage:Message(mockESApi, &esMsg)
             recordEventMetrics:^(EventDisposition d) {
               XCTAssertEqual(d, EventDisposition::kProcessed);
               dispatch_semaphore_signal(semaMetrics);
             }];

  XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
  XCTAssertSemaTrue(sema, 5, "Log wasn't called within expected time window");

  XCTAssertTrue(OCMVerifyAll(mockCC));
  XCTBubbleMockVerifyAndClearExpectations(mockEnricher.get());
  XCTBubbleMockVerifyAndClearExpectations(mockLogger.get());
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  [mockCC stopMocking];
  [mockDecisionCache stopMocking];
}

- (void)testHandleExecWithNoCachedDecisionLogsNormally {
  // When NOTIFY_EXEC arrives with no cached decision, logging should proceed normally.
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_file_t execFile = MakeESFile("bar", {.st_dev = 12, .st_ino = 34});
  es_process_t execProc = MakeESProcess(&execFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXEC, &proc, ActionType::Notify);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  // Create a fake enriched message
  es_message_t fakeEnrichedMsg = MakeESMessage(ES_EVENT_TYPE_NOTIFY_EXIT, NULL);
  std::unique_ptr<EnrichedMessage> enrichedMsg = std::make_unique<EnrichedMessage>(EnrichedMessage(
      santa::EnrichedExit(Message(mockESApi, &fakeEnrichedMsg), santa::EnrichedProcess())));

  auto mockEnricher = std::make_shared<santa::MockEnricher>();
  auto mockLogger = std::make_shared<MockLogger>();
  mockLogger->SetTelemetryMask(TelemetryEvent::kEverything);
  auto prefixTree = std::make_shared<PrefixTree<Unit>>();

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Enricher and Logger SHOULD be called when no cached decision exists
  EXPECT_CALL(*mockEnricher, Enrich).WillOnce(testing::Return(std::move(enrichedMsg)));
  EXPECT_CALL(*mockLogger, Log).WillOnce(testing::InvokeWithoutArgs(^() {
    dispatch_semaphore_signal(sema);
  }));

  // Mock decision cache to return nil
  id mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([mockDecisionCache sharedCache]).andReturn(mockDecisionCache);
  OCMStub([mockDecisionCache cachedDecisionForFile:esMsg.event.exec.target->executable->stat])
      .ignoringNonObjectArgs()
      .andReturn(nil);

  id mockCC = OCMStrictClassMock([SNTCompilerController class]);
  Message msg(mockESApi, &esMsg);
  OCMExpect([mockCC handleEvent:msg withLogger:nullptr]).ignoringNonObjectArgs();

  SNTEndpointSecurityRecorder* recorderClient =
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:mockESApi
                                                 metrics:nullptr
                                                  logger:mockLogger
                                                enricher:mockEnricher
                                      compilerController:mockCC
                               loginWindowSessionHandler:nil
                                              prefixTree:prefixTree
                                             processTree:nullptr];

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);
  [recorderClient handleMessage:Message(mockESApi, &esMsg)
             recordEventMetrics:^(EventDisposition d) {
               XCTAssertEqual(d, EventDisposition::kProcessed);
               dispatch_semaphore_signal(semaMetrics);
             }];

  XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
  XCTAssertSemaTrue(sema, 5, "Log wasn't called within expected time window");

  XCTAssertTrue(OCMVerifyAll(mockCC));
  XCTBubbleMockVerifyAndClearExpectations(mockEnricher.get());
  XCTBubbleMockVerifyAndClearExpectations(mockLogger.get());
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  [mockCC stopMocking];
  [mockDecisionCache stopMocking];
}

@end
