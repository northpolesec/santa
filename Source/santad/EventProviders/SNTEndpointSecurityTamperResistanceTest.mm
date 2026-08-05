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

#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"

#include <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdlib.h>
#include <sys/mount.h>

#include <map>
#include <memory>
#include <set>

#import "Source/common/Platform.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/Client.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/faa/WatchItemPolicy.h"
#import "Source/santad/Metrics.h"

using santa::Client;
using santa::EventDisposition;
using santa::Message;
using santa::WatchItemPathType;

static constexpr std::string_view kEventsDBPath = "/private/var/db/santa/events.db";
static constexpr std::string_view kEventsDBWALPath = "/private/var/db/santa/events.db-wal";
static constexpr std::string_view kRulesDBPath = "/private/var/db/santa/rules.db";
static constexpr std::string_view kRulesDBJournalPath = "/private/var/db/santa/rules.db-journal";
static constexpr std::string_view kSantaDBDirectoryPath = "/private/var/db/santa";
static constexpr std::string_view kSantaLogPath = "/private/var/db/santa/santa.log";
static constexpr std::string_view kSantaMigrationPath = "/private/var/db/santa/migration";
static constexpr std::string_view kSantaAppPrefixPath =
    "/Applications/Santa.app/Contents/Info.plist";
static constexpr std::string_view kBenignPath = "/some/other/path";

@interface SNTEndpointSecurityTamperResistance (Testing)
+ (bool)isProtectedPath:(std::string_view)path;
+ (bool)isProtectedDirectory:(std::string_view)path;
@end

@interface SNTEndpointSecurityTamperResistanceTest : XCTestCase
@property id mockConfigurator;
@end

@implementation SNTEndpointSecurityTamperResistanceTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
}

- (void)testEnable {
  // Ensure the client subscribes to expected event types
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_SIGNAL,
      ES_EVENT_TYPE_AUTH_EXEC,
      ES_EVENT_TYPE_AUTH_CLONE,
      ES_EVENT_TYPE_AUTH_COPYFILE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
      ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_AUTH_RENAME,
      ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_TRUNCATE,
      ES_EVENT_TYPE_AUTH_LINK,
      ES_EVENT_TYPE_AUTH_MOUNT,
      ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, NewClient(testing::_))
      .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_)).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  // Setup mocks to handle inverting target path muting
  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  // Setup mocks to handle muting the protected paths
  EXPECT_CALL(*mockESApi, MuteTargetPath(testing::_, testing::_, WatchItemPathType::kLiteral))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockESApi, MuteTargetPath(testing::_, testing::_, WatchItemPathType::kPrefix))
      .WillRepeatedly(testing::Return(true));

  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi
                                                         metrics:nullptr
                                                          logger:nullptr
                                           antiSuspendSigningIDs:nil
                                           allowDelegatedSignals:NO];
  id mockTamperClient = OCMPartialMock(tamperClient);

  [mockTamperClient enable];

  for (const auto& event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockTamperClient stopMocking];
}

- (void)testEnableWithAntiSuspendSigningIDs {
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_SIGNAL,
      ES_EVENT_TYPE_AUTH_EXEC,
      ES_EVENT_TYPE_AUTH_CLONE,
      ES_EVENT_TYPE_AUTH_COPYFILE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
      ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_AUTH_RENAME,
      ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_TRUNCATE,
      ES_EVENT_TYPE_AUTH_LINK,
      ES_EVENT_TYPE_AUTH_MOUNT,
      ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, NewClient(testing::_))
      .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_)).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  EXPECT_CALL(*mockESApi, MuteTargetPath(testing::_, testing::_, WatchItemPathType::kLiteral))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockESApi, MuteTargetPath(testing::_, testing::_, WatchItemPathType::kPrefix))
      .WillRepeatedly(testing::Return(true));

  // Expect muting "/" prefix for PROC_SUSPEND_RESUME when signing IDs are provided
  EXPECT_CALL(*mockESApi,
              MuteTargetPathEvents(testing::_, testing::_, WatchItemPathType::kPrefix, testing::_))
      .WillOnce(testing::Return(true));

  SNTEndpointSecurityTamperResistance* tamperClient = [[SNTEndpointSecurityTamperResistance alloc]
              initWithESAPI:mockESApi
                    metrics:nullptr
                     logger:nullptr
      antiSuspendSigningIDs:@[ @"ABCDE12345:com.example.protected" ]
      allowDelegatedSignals:NO];
  id mockTamperClient = OCMPartialMock(tamperClient);

  [mockTamperClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockTamperClient stopMocking];
}

- (void)testSetAntiSuspendSigningIDsAfterEnable {
  std::set<es_event_type_t> expectedEventSubs{
      ES_EVENT_TYPE_AUTH_SIGNAL,
      ES_EVENT_TYPE_AUTH_EXEC,
      ES_EVENT_TYPE_AUTH_CLONE,
      ES_EVENT_TYPE_AUTH_COPYFILE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA,
      ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_AUTH_RENAME,
      ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_TRUNCATE,
      ES_EVENT_TYPE_AUTH_LINK,
      ES_EVENT_TYPE_AUTH_MOUNT,
      ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, NewClient(testing::_))
      .WillOnce(testing::Return(Client(nullptr, ES_NEW_CLIENT_RESULT_SUCCESS)));
  EXPECT_CALL(*mockESApi, MuteProcess(testing::_, testing::_)).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, ClearCache(testing::_))
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  EXPECT_CALL(*mockESApi, MuteTargetPath(testing::_, testing::_, WatchItemPathType::kLiteral))
      .WillRepeatedly(testing::Return(true));
  EXPECT_CALL(*mockESApi, MuteTargetPath(testing::_, testing::_, WatchItemPathType::kPrefix))
      .WillRepeatedly(testing::Return(true));

  // No MuteTargetPathEvents during enable (nil signing IDs)
  EXPECT_CALL(*mockESApi,
              MuteTargetPathEvents(testing::_, testing::_, WatchItemPathType::kPrefix, testing::_))
      .Times(0);

  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi
                                                         metrics:nullptr
                                                          logger:nullptr
                                           antiSuspendSigningIDs:nil
                                           allowDelegatedSignals:NO];
  id mockTamperClient = OCMPartialMock(tamperClient);

  [mockTamperClient enable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  // Now setting signing IDs post-enable should trigger the mute
  EXPECT_CALL(*mockESApi,
              MuteTargetPathEvents(testing::_, testing::_, WatchItemPathType::kPrefix, testing::_))
      .WillOnce(testing::Return(true));

  [tamperClient setAntiSuspendSigningIDs:@[ @"ABCDE12345:com.example.protected" ]];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  [mockTamperClient stopMocking];
}

- (void)testHandleMessage {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_READLINK, &proc, ActionType::Auth);

  es_file_t fileEventsDB = MakeESFile(kEventsDBPath.data());
  es_file_t fileEventsDBWAL = MakeESFile(kEventsDBWALPath.data());
  es_file_t fileRulesDB = MakeESFile(kRulesDBPath.data());
  es_file_t fileRulesDBJournal = MakeESFile(kRulesDBJournalPath.data());
  es_file_t santaDBDirectory = MakeESFile(kSantaDBDirectoryPath.data());
  es_file_t fileSantaLog = MakeESFile(kSantaLogPath.data());
  es_file_t santaMigrationDirectory = MakeESFile(kSantaMigrationPath.data());
  es_file_t fileSantaAppPrefix = MakeESFile(kSantaAppPrefixPath.data());
  es_file_t fileBenign = MakeESFile(kBenignPath.data());

  std::map<es_file_t*, es_auth_result_t> pathToResult{
      {&fileEventsDB, ES_AUTH_RESULT_DENY},      {&fileEventsDBWAL, ES_AUTH_RESULT_DENY},
      {&fileRulesDB, ES_AUTH_RESULT_DENY},       {&fileRulesDBJournal, ES_AUTH_RESULT_DENY},
      {&santaDBDirectory, ES_AUTH_RESULT_ALLOW}, {&fileSantaAppPrefix, ES_AUTH_RESULT_DENY},
      {&fileBenign, ES_AUTH_RESULT_ALLOW},
  };

  // Signals targeting the Santa process are denied, unless from launchd
  std::map<std::pair<pid_t, pid_t>, es_auth_result_t> pidsToResultSignal{
      {{getpid(), 31838}, ES_AUTH_RESULT_DENY},
      {{getpid(), 1}, ES_AUTH_RESULT_ALLOW},
      {{435, 98381}, ES_AUTH_RESULT_ALLOW},
  };

  // pid_suspend/pid_resume targeting the Santa process are denied
  std::map<std::pair<pid_t, pid_t>, es_auth_result_t> pidsToResultProcSuspendResume{
      {{getpid(), 31838}, ES_AUTH_RESULT_DENY},
      {{getpid(), 1}, ES_AUTH_RESULT_DENY},
      {{435, 98381}, ES_AUTH_RESULT_ALLOW},
  };

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi
                                                         metrics:nullptr
                                                          logger:nullptr
                                           antiSuspendSigningIDs:nil
                                           allowDelegatedSignals:NO];

  id mockTamperClient = OCMPartialMock(tamperClient);

  // Unable to use `OCMExpect` here because we cannot match on the `Message`
  // parameter. In order to verify the `AuthResult` and `Cacheable` parameters,
  // instead use `OCMStub` and extract the arguments in order to assert their
  // expected values.
  __block es_auth_result_t gotAuthResult;
  __block bool gotCachable;
  OCMStub([mockTamperClient respondToMessage:Message(mockESApi, &esMsg)
                              withAuthResult:(es_auth_result_t)0
                                   cacheable:false])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&gotAuthResult atIndex:3];
        [inv getArgument:&gotCachable atIndex:4];
      });

  // First check unhandled event types will crash
  {
    Message msg(mockESApi, &esMsg);
    XCTAssertThrows([tamperClient handleMessage:Message(mockESApi, &esMsg)
                             recordEventMetrics:^(EventDisposition d) {
                               XCTFail("Unhandled event types shouldn't call metrics recorder");
                             }]);
  }

  // Check UNLINK tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_UNLINK;
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.unlink.target = kv.first;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check LINK `source` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_LINK;
    es_file_t linkBenignDir = MakeESFile("/tmp");
    es_string_token_t linkBenignFilename = MakeESStringToken("benign");
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.link.source = kv.first;
      esMsg.event.link.target_dir = &linkBenignDir;
      esMsg.event.link.target_filename = linkBenignFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check LINK `dest` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_LINK;
    esMsg.event.link.source = &fileBenign;

    es_file_t linkDestDirProtected = MakeESFile("/Applications/Santa.app/Contents");
    es_file_t linkDestDirBenign = MakeESFile("/some/other");
    es_string_token_t linkDestFilename = MakeESStringToken("test");

    std::map<es_file_t*, es_auth_result_t> linkDestToResult{
        {&linkDestDirProtected, ES_AUTH_RESULT_DENY},
        {&linkDestDirBenign, ES_AUTH_RESULT_ALLOW},
    };

    for (const auto& kv : linkDestToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.link.target_dir = kv.first;
      esMsg.event.link.target_filename = linkDestFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check CLONE `source` tamper events. Cloning a protected source to a benign destination must be
  // denied to prevent protected data from being copied outside the protected path set.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    es_file_t cloneBenignDir = MakeESFile("/tmp");
    es_string_token_t cloneBenignFilename = MakeESStringToken("benign");
    for (const auto& kv : pathToResult) {
      // The directory object is denied for CLONE; covered in a dedicated block below.
      if (kv.first == &santaDBDirectory) continue;

      Message msg(mockESApi, &esMsg);
      esMsg.event.clone.source = kv.first;
      esMsg.event.clone.target_dir = &cloneBenignDir;
      esMsg.event.clone.target_name = cloneBenignFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check CLONE `dest` tamper events.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    esMsg.event.clone.source = &fileBenign;

    es_file_t cloneDestDirProtected = MakeESFile("/Applications/Santa.app/Contents");
    es_file_t cloneDestDirBenign = MakeESFile("/some/other");
    es_string_token_t cloneDestFilename = MakeESStringToken("test");

    std::map<es_file_t*, es_auth_result_t> cloneDestToResult{
        {&cloneDestDirProtected, ES_AUTH_RESULT_DENY},
        {&cloneDestDirBenign, ES_AUTH_RESULT_ALLOW},
    };

    for (const auto& kv : cloneDestToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.clone.target_dir = kv.first;
      esMsg.event.clone.target_name = cloneDestFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check COPYFILE `source` tamper events. Copying a protected source to a benign destination must
  // be denied to prevent protected data from being copied outside the protected path set.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
    es_file_t copyfileBenignDir = MakeESFile("/tmp");
    es_string_token_t copyfileBenignFilename = MakeESStringToken("benign");
    for (const auto& kv : pathToResult) {
      // The directory object is denied for COPYFILE; covered in a dedicated block below.
      if (kv.first == &santaDBDirectory) continue;

      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.source = kv.first;
      esMsg.event.copyfile.target_file = NULL;
      esMsg.event.copyfile.target_dir = &copyfileBenignDir;
      esMsg.event.copyfile.target_name = copyfileBenignFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check COPYFILE `dest` tamper events targeting a new path (target_dir + target_name).
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
    esMsg.event.copyfile.source = &fileBenign;
    esMsg.event.copyfile.target_file = NULL;

    es_file_t copyfileDestDirProtected = MakeESFile("/Applications/Santa.app/Contents");
    es_file_t copyfileDestDirBenign = MakeESFile("/some/other");
    es_string_token_t copyfileDestFilename = MakeESStringToken("test");

    std::map<es_file_t*, es_auth_result_t> copyfileDestToResult{
        {&copyfileDestDirProtected, ES_AUTH_RESULT_DENY},
        {&copyfileDestDirBenign, ES_AUTH_RESULT_ALLOW},
    };

    for (const auto& kv : copyfileDestToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.target_dir = kv.first;
      esMsg.event.copyfile.target_name = copyfileDestFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check COPYFILE `dest` tamper events overwriting an existing file (target_file). Unlike
  // clonefile, copyfile can overwrite an existing destination, so copying a benign source over a
  // protected file must be denied.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
    esMsg.event.copyfile.source = &fileBenign;
    esMsg.event.copyfile.target_dir = NULL;
    esMsg.event.copyfile.target_name = MakeESStringToken("");
    for (const auto& kv : pathToResult) {
      // The directory object is denied for COPYFILE; covered in a dedicated block below.
      if (kv.first == &santaDBDirectory) continue;

      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.target_file = kv.first;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check CLONE/COPYFILE of the /private/var/db/santa directory object are denied. A recursive
  // directory clone would expose the read-protected databases inside.
  {
    es_file_t dirCopyBenignDir = MakeESFile("/tmp");
    es_string_token_t dirCopyBenignFilename = MakeESStringToken("benign");

    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.clone.source = &santaDBDirectory;
      esMsg.event.clone.target_dir = &dirCopyBenignDir;
      esMsg.event.clone.target_name = dirCopyBenignFilename;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
      XCTAssertFalse(gotCachable);
    }

    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.source = &santaDBDirectory;
      esMsg.event.copyfile.target_file = NULL;
      esMsg.event.copyfile.target_dir = &dirCopyBenignDir;
      esMsg.event.copyfile.target_name = dirCopyBenignFilename;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
      XCTAssertFalse(gotCachable);
    }

    // COPYFILE overwriting the directory object via an existing target_file must also be denied.
    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.copyfile.source = &fileBenign;
      esMsg.event.copyfile.target_dir = NULL;
      esMsg.event.copyfile.target_name = MakeESStringToken("");
      esMsg.event.copyfile.target_file = &santaDBDirectory;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
      XCTAssertFalse(gotCachable);
    }
  }

  // Check EXCHANGEDATA tamper events. exchangedata swaps the contents of two files, so a protected
  // database appearing as either file1 or file2 must be denied.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_EXCHANGEDATA;
    for (const auto& kv : pathToResult) {
      // file1 = candidate, file2 = benign
      {
        Message msg(mockESApi, &esMsg);
        esMsg.event.exchangedata.file1 = kv.first;
        esMsg.event.exchangedata.file2 = &fileBenign;

        [mockTamperClient
                 handleMessage:std::move(msg)
            recordEventMetrics:^(EventDisposition d) {
              XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                                 : EventDisposition::kDropped);
              dispatch_semaphore_signal(semaMetrics);
            }];

        XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
        XCTAssertEqual(gotAuthResult, kv.second);
        XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
      }

      // file1 = benign, file2 = candidate
      {
        Message msg(mockESApi, &esMsg);
        esMsg.event.exchangedata.file1 = &fileBenign;
        esMsg.event.exchangedata.file2 = kv.first;

        [mockTamperClient
                 handleMessage:std::move(msg)
            recordEventMetrics:^(EventDisposition d) {
              XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                                 : EventDisposition::kDropped);
              dispatch_semaphore_signal(semaMetrics);
            }];

        XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
        XCTAssertEqual(gotAuthResult, kv.second);
        XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
      }
    }
  }

  // Check MOUNT tamper events. A mount whose mount point shadows the protected database directory
  // (or any ancestor of it) is denied; unrelated mount points are allowed.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_MOUNT;
    std::map<std::string_view, es_auth_result_t> mountPointToResult{
        {"/private/var/db/santa", ES_AUTH_RESULT_DENY},           // the database directory itself
        {"/private/var/db", ES_AUTH_RESULT_DENY},                 // parent
        {"/private/var", ES_AUTH_RESULT_DENY},                    // grandparent
        {"/", ES_AUTH_RESULT_DENY},                               // root shadows everything
        {"/private/var/db/santa-backup", ES_AUTH_RESULT_ALLOW},   // component-boundary near miss
        {"/private/var/db/santa/staging", ES_AUTH_RESULT_ALLOW},  // below the dir, cannot shadow
        {"/Volumes/attacker", ES_AUTH_RESULT_ALLOW},              // unrelated mount point
        {"", ES_AUTH_RESULT_ALLOW},                               // empty path must not match all
    };

    for (const auto& kv : mountPointToResult) {
      struct statfs fs = {0};
      strlcpy(fs.f_mntonname, kv.first.data(), sizeof(fs.f_mntonname));

      Message msg(mockESApi, &esMsg);
      esMsg.event.mount.statfs = &fs;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second, @"mount point: %s", kv.first.data());
      XCTAssertFalse(gotCachable);
    }
  }

  // Check TRUNCATE tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_TRUNCATE;
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.truncate.target = kv.first;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check CREATE `new_path` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CREATE;

    es_file_t createDestDirProtected = MakeESFile("/Applications/Santa.app/Contents");
    es_file_t createDestDirBenign = MakeESFile("/some/other");
    es_string_token_t createDestFilename = MakeESStringToken("test");

    std::map<es_file_t*, es_auth_result_t> createDestToResult{
        {&createDestDirProtected, ES_AUTH_RESULT_DENY},
        {&createDestDirBenign, ES_AUTH_RESULT_ALLOW},
    };

    for (const auto& kv : createDestToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.create.destination.new_path.dir = kv.first;
      esMsg.event.create.destination.new_path.filename = createDestFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // CREATE with EXISTING_FILE destination is not expected per the
  // Message::PathTargets contract. Verify such events fall through to ALLOW
  // rather than crashing, even if existing_file points to a protected path.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CREATE;
    esMsg.event.create.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
    esMsg.event.create.destination.existing_file = &fileRulesDB;

    Message msg(mockESApi, &esMsg);
    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kDropped);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_ALLOW);
    // CREATE with an unexpected EXISTING_FILE destination falls through to a cacheable ALLOW.
    XCTAssertTrue(gotCachable);
  }

  // Check CREATE under /private/var/db/santa remains allowed for package-created migration
  // artifacts and log files.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CREATE;
    es_file_t santaDBParentDir = MakeESFile(kSantaDBDirectoryPath.data());

    std::map<std::string_view, es_auth_result_t> createSantaDBChildToResult{
        {"migration", ES_AUTH_RESULT_ALLOW},
        {"santa.log", ES_AUTH_RESULT_ALLOW},
    };

    for (const auto& kv : createSantaDBChildToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.create.destination.new_path.dir = &santaDBParentDir;
      esMsg.event.create.destination.new_path.filename = MakeESStringToken(kv.first.data());

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kDropped);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertTrue(gotCachable);
    }
  }

  // Check RENAME `source` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    es_file_t renameSrcBenignDir = MakeESFile("/tmp");
    es_string_token_t renameSrcBenignFilename = MakeESStringToken("benign");
    for (const auto& kv : pathToResult) {
      if (kv.first == &santaDBDirectory) continue;

      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = kv.first;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &renameSrcBenignDir;
      esMsg.event.rename.destination.new_path.filename = renameSrcBenignFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check RENAME `dest` tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &fileBenign;
    for (const auto& kv : pathToResult) {
      if (kv.first == &santaDBDirectory) continue;

      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = kv.first;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check RENAME `dest` NEW_PATH tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    esMsg.event.rename.source = &fileBenign;

    es_file_t renameDestDirProtected = MakeESFile("/Applications/Santa.app/Contents");
    es_file_t renameDestDirBenign = MakeESFile("/some/other");
    es_string_token_t renameDestFilename = MakeESStringToken("test");

    std::map<es_file_t*, es_auth_result_t> renameNewPathDestToResult{
        {&renameDestDirProtected, ES_AUTH_RESULT_DENY},
        {&renameDestDirBenign, ES_AUTH_RESULT_ALLOW},
    };

    for (const auto& kv : renameNewPathDestToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = kv.first;
      esMsg.event.rename.destination.new_path.filename = renameDestFilename;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check RENAME of the /private/var/db/santa directory object is denied in all target forms.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    es_file_t renameDestBenignDir = MakeESFile("/tmp");
    es_file_t santaDBGrandparentDir = MakeESFile("/private/var/db");
    es_string_token_t renameDestBenignFilename = MakeESStringToken("benign");
    es_string_token_t santaDBDirectoryFilename = MakeESStringToken("santa");

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = &santaDBDirectory;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &renameDestBenignDir;
      esMsg.event.rename.destination.new_path.filename = renameDestBenignFilename;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
      XCTAssertFalse(gotCachable);
    }

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = &fileBenign;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE;
      esMsg.event.rename.destination.existing_file = &santaDBDirectory;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
      XCTAssertFalse(gotCachable);
    }

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = &fileBenign;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &santaDBGrandparentDir;
      esMsg.event.rename.destination.new_path.filename = santaDBDirectoryFilename;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kProcessed);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
      XCTAssertFalse(gotCachable);
    }
  }

  // Check RENAME of children under /private/var/db/santa remains allowed for newsyslog rotation
  // and migration directory lifecycle.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_RENAME;
    es_file_t santaDBParentDir = MakeESFile(kSantaDBDirectoryPath.data());
    es_file_t renameDestBenignDir = MakeESFile("/tmp");
    es_string_token_t rotatedLogFilename = MakeESStringToken("santa.log.0.gz");
    es_string_token_t renameDestBenignFilename = MakeESStringToken("benign");

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = &fileSantaLog;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &santaDBParentDir;
      esMsg.event.rename.destination.new_path.filename = rotatedLogFilename;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kDropped);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_ALLOW);
      XCTAssertTrue(gotCachable);
    }

    {
      Message msg(mockESApi, &esMsg);
      esMsg.event.rename.source = &santaMigrationDirectory;
      esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
      esMsg.event.rename.destination.new_path.dir = &renameDestBenignDir;
      esMsg.event.rename.destination.new_path.filename = renameDestBenignFilename;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kDropped);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_ALLOW);
      XCTAssertTrue(gotCachable);
    }
  }

  // Check SIGNAL tamper events
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_SIGNAL;

    for (const auto& kv : pidsToResultSignal) {
      Message msg(mockESApi, &esMsg);
      es_process_t target_proc = MakeESProcess(&file);
      target_proc.audit_token = MakeAuditToken(kv.first.first, 42);
      esMsg.event.signal.target = &target_proc;
      esMsg.process->audit_token = MakeAuditToken(kv.first.second, 42);

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertFalse(gotCachable);
    }
  }

  // Check SIGNAL tamper events with v9 instigator field
#if HAVE_MACOS_15_5
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_SIGNAL;
    esMsg.version = 9;

    struct InstigatorCase {
      const char* desc;
      bool allowDelegatedSignals;
      bool hasInstigator;
      bool instigatorIsPlatform;
      const char* instigatorTeamID;
      const char* instigatorSigningID;
      es_auth_result_t expected;
    };

    static const InstigatorCase cases[] = {
        // Direct signal from launchd (no instigator) -> ALLOW (shutdown path).
        {"direct from launchd", /*allow=*/false, /*hasInst=*/false,
         /*plat=*/false, "", "", ES_AUTH_RESULT_ALLOW},
        // Delegated by launchd itself -> ALLOW (baseline).
        {"baseline launchd", false, true, true, "", "com.apple.xpc.launchd", ES_AUTH_RESULT_ALLOW},
        // Delegated by smd -> ALLOW (baseline).
        {"baseline smd", false, true, true, "", "com.apple.xpc.smd", ES_AUTH_RESULT_ALLOW},
        // Unlisted platform binary with AllowDelegatedSignals=NO -> DENY.
        {"unlisted platform, AllowDelegatedSignals=NO", false, true, true, "", "com.apple.unknown",
         ES_AUTH_RESULT_DENY},
        // Same instigator with AllowDelegatedSignals=YES -> ALLOW.
        {"unlisted platform, AllowDelegatedSignals=YES", true, true, true, "", "com.apple.unknown",
         ES_AUTH_RESULT_ALLOW},
        // Third-party-signed instigator with AllowDelegatedSignals=YES -> DENY
        // (the config only relaxes when is_platform_binary == true).
        {"third party, AllowDelegatedSignals=YES", true, true, false, "ABCDE12345", "com.evil.app",
         ES_AUTH_RESULT_DENY},
    };

    for (const auto& c : cases) {
      [tamperClient setAllowDelegatedSignals:c.allowDelegatedSignals];
      Message msg(mockESApi, &esMsg);

      es_process_t target_proc = MakeESProcess(&file);
      target_proc.audit_token = MakeAuditToken(getpid(), 42);
      esMsg.event.signal.target = &target_proc;
      esMsg.process->audit_token = MakeAuditToken(1, 42);  // sender = launchd

      es_file_t instigatorFile = MakeESFile("/usr/libexec/instigator");
      es_process_t instigator_proc = MakeESProcess(&instigatorFile);
      instigator_proc.team_id = MakeESStringToken(c.instigatorTeamID);
      instigator_proc.signing_id = MakeESStringToken(c.instigatorSigningID);
      instigator_proc.is_platform_binary = c.instigatorIsPlatform;
      esMsg.event.signal.instigator = c.hasInstigator ? &instigator_proc : NULL;

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d,
                                    c.expected == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                                      : EventDisposition::kDropped,
                                    @"%s", c.desc);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, c.expected, @"%s", c.desc);
    }

    // Reset shared state for downstream test blocks.
    esMsg.event.signal.instigator = NULL;
    esMsg.version = MaxSupportedESMessageVersionForCurrentOS();
  }
#endif  // HAVE_MACOS_15_5

  // Check PROC_SUSPEND_RESUME tamper events - EnableAntiTamperProcessSuspendResume = NO
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME;
    [tamperClient setAntiSuspendSigningIDs:nil];

    for (const auto& kv : pidsToResultProcSuspendResume) {
      OCMExpect([self.mockConfigurator enableAntiTamperProcessSuspendResume]).andReturn(NO);
      Message msg(mockESApi, &esMsg);
      es_process_t target_proc = MakeESProcess(&file);
      target_proc.audit_token = MakeAuditToken(kv.first.first, 42);
      esMsg.event.proc_suspend_resume.target = &target_proc;
      esMsg.process->audit_token = MakeAuditToken(kv.first.second, 42);

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     XCTAssertEqual(d, EventDisposition::kDropped);
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_ALLOW);
      XCTAssertEqual(gotCachable, YES);
    }
  }

  // Check PROC_SUSPEND_RESUME tamper events - EnableAntiTamperProcessSuspendResume = YES
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME;

    for (const auto& kv : pidsToResultProcSuspendResume) {
      OCMExpect([self.mockConfigurator enableAntiTamperProcessSuspendResume]).andReturn(YES);
      Message msg(mockESApi, &esMsg);
      es_process_t target_proc = MakeESProcess(&file);
      target_proc.audit_token = MakeAuditToken(kv.first.first, 42);
      esMsg.event.proc_suspend_resume.target = &target_proc;
      esMsg.process->audit_token = MakeAuditToken(kv.first.second, 42);

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, kv.second);
      XCTAssertEqual(gotCachable, kv.second == ES_AUTH_RESULT_ALLOW);
    }
  }

  // Check PROC_SUSPEND_RESUME - AntiSuspendSigningIDs blocks matching signing ID
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME;
    [tamperClient setAntiSuspendSigningIDs:@[ @"ABCDE12345:com.example.protected" ]];

    OCMExpect([self.mockConfigurator enableAntiTamperProcessSuspendResume]).andReturn(NO);
    Message msg(mockESApi, &esMsg);
    es_process_t target_proc = MakeESProcess(&file);
    target_proc.audit_token = MakeAuditToken(435, 42);
    target_proc.team_id = MakeESStringToken("ABCDE12345");
    target_proc.signing_id = MakeESStringToken("com.example.protected");
    target_proc.is_platform_binary = false;
    esMsg.event.proc_suspend_resume.target = &target_proc;
    esMsg.process->audit_token = MakeAuditToken(98381, 42);

    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kProcessed);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
    XCTAssertEqual(gotCachable, NO);
  }

  // Check PROC_SUSPEND_RESUME - AntiSuspendSigningIDs allows non-matching signing ID
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME;
    [tamperClient setAntiSuspendSigningIDs:@[ @"ABCDE12345:com.example.protected" ]];

    OCMExpect([self.mockConfigurator enableAntiTamperProcessSuspendResume]).andReturn(NO);
    Message msg(mockESApi, &esMsg);
    es_process_t target_proc = MakeESProcess(&file);
    target_proc.audit_token = MakeAuditToken(435, 42);
    target_proc.team_id = MakeESStringToken("ABCDE12345");
    target_proc.signing_id = MakeESStringToken("com.example.other");
    target_proc.is_platform_binary = false;
    esMsg.event.proc_suspend_resume.target = &target_proc;
    esMsg.process->audit_token = MakeAuditToken(98381, 42);

    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kDropped);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_ALLOW);
    XCTAssertEqual(gotCachable, YES);
  }

  // Check PROC_SUSPEND_RESUME - AntiSuspendSigningIDs with platform binary
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_PROC_SUSPEND_RESUME;
    [tamperClient setAntiSuspendSigningIDs:@[ @"platform:com.apple.protected" ]];

    OCMExpect([self.mockConfigurator enableAntiTamperProcessSuspendResume]).andReturn(NO);
    Message msg(mockESApi, &esMsg);
    es_process_t target_proc = MakeESProcess(&file);
    target_proc.audit_token = MakeAuditToken(435, 42);
    target_proc.team_id = MakeESStringToken("");
    target_proc.signing_id = MakeESStringToken("com.apple.protected");
    target_proc.is_platform_binary = true;
    esMsg.event.proc_suspend_resume.target = &target_proc;
    esMsg.process->audit_token = MakeAuditToken(98381, 42);

    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kProcessed);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
    XCTAssertEqual(gotCachable, NO);
  }

  // Check OPEN tamper events (writable)
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    for (const auto& kv : pathToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.open.file = kv.first;
      esMsg.event.open.fflag = FWRITE;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      // OPEN events are currently never cached
      XCTAssertFalse(gotCachable);
    }
  }

  // Check OPEN tamper events (read-only). Database files and their sidecars must still be denied,
  // while protected paths whose policy allows reads remain accessible.
  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;
    std::map<es_file_t*, es_auth_result_t> openReadOnlyToResult{
        {&fileEventsDB, ES_AUTH_RESULT_DENY},         // literal-protected
        {&fileEventsDBWAL, ES_AUTH_RESULT_DENY},      // sidecar prefix, reads denied
        {&fileRulesDB, ES_AUTH_RESULT_DENY},          // literal-protected
        {&fileRulesDBJournal, ES_AUTH_RESULT_DENY},   // sidecar prefix, reads denied
        {&santaDBDirectory, ES_AUTH_RESULT_ALLOW},    // literal-protected, reads allowed
        {&fileSantaAppPrefix, ES_AUTH_RESULT_ALLOW},  // prefix-protected, read-only OK
        {&fileBenign, ES_AUTH_RESULT_ALLOW},
    };
    for (const auto& kv : openReadOnlyToResult) {
      Message msg(mockESApi, &esMsg);
      esMsg.event.open.file = kv.first;
      esMsg.event.open.fflag = 0;

      [mockTamperClient
               handleMessage:std::move(msg)
          recordEventMetrics:^(EventDisposition d) {
            XCTAssertEqual(d, kv.second == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                               : EventDisposition::kDropped);
            dispatch_semaphore_signal(semaMetrics);
          }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");

      XCTAssertEqual(gotAuthResult, kv.second);
      // OPEN events are currently never cached
      XCTAssertFalse(gotCachable);
    }
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTAssertTrue(OCMVerifyAll(mockTamperClient));

  [mockTamperClient stopMocking];
}

- (void)testHandleMessageTruncatedPath {
  es_file_t file = MakeESFile("foo");
  es_process_t proc = MakeESProcess(&file);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_UNLINK, &proc, ActionType::Auth);

  es_file_t fileBenign = MakeESFile(kBenignPath.data());
  es_file_t fileBenignTruncated = MakeESFile(kBenignPath.data());
  fileBenignTruncated.path_truncated = true;
  es_file_t dirBenign = MakeESFile("/some/other");
  es_file_t dirBenignTruncated = MakeESFile("/some/other");
  dirBenignTruncated.path_truncated = true;
  es_string_token_t cloneFilename = MakeESStringToken("path");

  struct CloneCase {
    es_file_t* source;
    es_file_t* targetDir;
  } cloneCases[] = {
      {&fileBenignTruncated, &dirBenign},
      {&fileBenign, &dirBenignTruncated},
  };

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi
                                                         metrics:nullptr
                                                          logger:nullptr
                                           antiSuspendSigningIDs:nil
                                           allowDelegatedSignals:NO];

  id mockTamperClient = OCMPartialMock(tamperClient);

  __block es_auth_result_t gotAuthResult;
  __block bool gotCachable;
  OCMStub([mockTamperClient respondToMessage:Message(mockESApi, &esMsg)
                              withAuthResult:(es_auth_result_t)0
                                   cacheable:false])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&gotAuthResult atIndex:3];
        [inv getArgument:&gotCachable atIndex:4];
      });

  {
    Message msg(mockESApi, &esMsg);
    esMsg.event.unlink.target = &fileBenignTruncated;

    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kProcessed);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
    XCTAssertFalse(gotCachable);
  }

  esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;
  for (const auto& cloneCase : cloneCases) {
    Message msg(mockESApi, &esMsg);
    esMsg.event.clone.source = cloneCase.source;
    esMsg.event.clone.target_dir = cloneCase.targetDir;
    esMsg.event.clone.target_name = cloneFilename;

    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kProcessed);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
    XCTAssertFalse(gotCachable);
  }

  // A truncated path on any COPYFILE target (source, new-path dest, or existing-file dest) is
  // unreliable and must be denied.
  struct CopyfileCase {
    es_file_t* source;
    es_file_t* targetFile;
    es_file_t* targetDir;
  } copyfileCases[] = {
      {&fileBenignTruncated, NULL, &dirBenign},
      {&fileBenign, NULL, &dirBenignTruncated},
      {&fileBenign, &fileBenignTruncated, NULL},
  };

  esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;
  for (const auto& copyfileCase : copyfileCases) {
    Message msg(mockESApi, &esMsg);
    esMsg.event.copyfile.source = copyfileCase.source;
    esMsg.event.copyfile.target_file = copyfileCase.targetFile;
    esMsg.event.copyfile.target_dir = copyfileCase.targetDir;
    esMsg.event.copyfile.target_name = cloneFilename;

    [mockTamperClient handleMessage:std::move(msg)
                 recordEventMetrics:^(EventDisposition d) {
                   XCTAssertEqual(d, EventDisposition::kProcessed);
                   dispatch_semaphore_signal(semaMetrics);
                 }];

    XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
    XCTAssertEqual(gotAuthResult, ES_AUTH_RESULT_DENY);
    XCTAssertFalse(gotCachable);
  }

  [mockTamperClient stopMocking];
}

// Sleigh must be able to unlink/truncate its own BoltDB state database, but nothing else, and no
// other process may touch that database.
- (void)testSleighStateDbAccess {
  es_file_t sleighExec = MakeESFile("/Applications/Santa.app/Contents/MacOS/sleigh");
  es_process_t sleighProc = MakeESProcess(&sleighExec);
  sleighProc.is_platform_binary = false;
  sleighProc.team_id = MakeESStringToken("ZMCG7MLDV9");
  sleighProc.signing_id = MakeESStringToken("com.northpolesec.santa.sleigh");
  sleighProc.codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD | CS_KILL;

  // Same identity, but the kernel is no longer strictly enforcing the cdhash.
  es_process_t unenforcedSleighProc = sleighProc;
  unenforcedSleighProc.codesigning_flags = CS_SIGNED;

  es_file_t otherExec = MakeESFile("/usr/local/bin/evil");
  es_process_t otherProc = MakeESProcess(&otherExec);
  otherProc.is_platform_binary = false;
  otherProc.team_id = MakeESStringToken("ABCDE12345");
  otherProc.signing_id = MakeESStringToken("com.example.evil");
  otherProc.codesigning_flags = CS_SIGNED | CS_VALID | CS_HARD | CS_KILL;

  es_file_t sleighStateDB = MakeESFile("/private/var/db/santa/sleigh_state.db");
  es_file_t rulesDB = MakeESFile(kRulesDBPath.data());

  struct {
    es_process_t* proc;
    es_file_t* target;
    es_auth_result_t want;
  } cases[] = {
      {&sleighProc, &sleighStateDB, ES_AUTH_RESULT_ALLOW},
      {&sleighProc, &rulesDB, ES_AUTH_RESULT_DENY},
      {&unenforcedSleighProc, &sleighStateDB, ES_AUTH_RESULT_DENY},
      {&otherProc, &sleighStateDB, ES_AUTH_RESULT_DENY},
  };

  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_UNLINK, &sleighProc, ActionType::Auth);

  dispatch_semaphore_t semaMetrics = dispatch_semaphore_create(0);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();

  SNTEndpointSecurityTamperResistance* tamperClient =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:mockESApi
                                                         metrics:nullptr
                                                          logger:nullptr
                                           antiSuspendSigningIDs:nil
                                           allowDelegatedSignals:NO];

  id mockTamperClient = OCMPartialMock(tamperClient);

  __block es_auth_result_t gotAuthResult;
  OCMStub([mockTamperClient respondToMessage:Message(mockESApi, &esMsg)
                              withAuthResult:(es_auth_result_t)0
                                   cacheable:false])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* inv) {
        [inv getArgument:&gotAuthResult atIndex:3];
      });

  for (es_event_type_t eventType : {ES_EVENT_TYPE_AUTH_UNLINK, ES_EVENT_TYPE_AUTH_TRUNCATE}) {
    esMsg.event_type = eventType;
    for (const auto& c : cases) {
      Message msg(mockESApi, &esMsg);
      esMsg.process = c.proc;
      if (eventType == ES_EVENT_TYPE_AUTH_UNLINK) {
        esMsg.event.unlink.target = c.target;
      } else {
        esMsg.event.truncate.target = c.target;
      }

      [mockTamperClient handleMessage:std::move(msg)
                   recordEventMetrics:^(EventDisposition d) {
                     dispatch_semaphore_signal(semaMetrics);
                   }];

      XCTAssertSemaTrue(semaMetrics, 5, "Metrics not recorded within expected window");
      XCTAssertEqual(gotAuthResult, c.want, "%s on %s",
                     eventType == ES_EVENT_TYPE_AUTH_UNLINK ? "unlink" : "truncate",
                     c.target->path.data);
    }
  }

  [mockTamperClient stopMocking];
}

- (void)testIsProtectedPath {
  XCTAssertTrue(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/rules.db"]);
  XCTAssertTrue(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/events.db"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance
      isProtectedPath:"/private/var/db/santa/rules.db-journal"]);
  XCTAssertTrue(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/rules.db-wal"]);
  XCTAssertTrue(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/events.db-shm"]);
  XCTAssertFalse([SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance isProtectedDirectory:"/private/var/db/santa"]);
  // The Santa directory's parents are protected as directory objects (rename/clone/copyfile only),
  // but are not general protected paths.
  XCTAssertTrue([SNTEndpointSecurityTamperResistance isProtectedDirectory:"/private/var/db"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance isProtectedDirectory:"/private/var"]);
  XCTAssertFalse([SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db"]);
  XCTAssertFalse([SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var"]);
  XCTAssertFalse(
      [SNTEndpointSecurityTamperResistance isProtectedDirectory:"/private/var/db/santa/migration"]);
  XCTAssertFalse(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa-backup"]);
  XCTAssertFalse(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/unrelated"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance isProtectedPath:"/Applications/Santa.app"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance
      isProtectedPath:"/Library/LaunchAgents/com.northpolesec.santa.plist"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance
      isProtectedPath:"/Library/LaunchDaemons/com.northpolesec.santa.syncservice.plist"]);
  XCTAssertFalse([SNTEndpointSecurityTamperResistance isProtectedPath:"/not/a/db/path"]);
}

- (void)testStagingDirectoryIsProtected {
  // /staging itself and any path beneath it must match the kPrefix entry.
  XCTAssertTrue(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/staging"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance
      isProtectedPath:"/private/var/db/santa/staging/Santa.app"]);
  XCTAssertTrue([SNTEndpointSecurityTamperResistance
      isProtectedPath:"/private/var/db/santa/staging/Santa.app/Contents/MacOS/Santa"]);
  // /migration is intentionally NOT protected in v2.
  XCTAssertFalse(
      [SNTEndpointSecurityTamperResistance isProtectedPath:"/private/var/db/santa/migration"]);
  XCTAssertFalse([SNTEndpointSecurityTamperResistance
      isProtectedPath:"/private/var/db/santa/migration/Santa.app"]);
}

@end
