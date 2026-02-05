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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTExportConfiguration.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/AnyBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Null.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"
#include "Source/santad/SleighLauncher.h"

using santa::BasicString;
using santa::Empty;
using santa::EnrichedClose;
using santa::EnrichedFile;
using santa::EnrichedMessage;
using santa::EnrichedProcess;
using santa::File;
using santa::Logger;
using santa::Message;
using santa::Null;
using santa::Protobuf;
using santa::Spool;
using santa::Syslog;
using santa::TelemetryEvent;
using testing::Pair;
using testing::Return;
using testing::UnorderedElementsAre;
using ExportLogType = ::santa::Logger::ExportLogType;

namespace santa {

class LoggerPeer : public Logger {
 public:
  // Make base class constructors and members visible
  using Logger::export_batch_threshold_size_bytes_;
  using Logger::export_max_files_per_batch_;
  using Logger::export_timeout_secs_;
  using Logger::ExportTelemetrySerialized;
  using Logger::Logger;
  using Logger::serializer_;
  using Logger::tracker_;
  using Logger::writer_;

  LoggerPeer(std::unique_ptr<Logger> l)
      : Logger(nil, nil, TelemetryEvent::kEverything, l->export_timeout_secs_->load(),
               static_cast<uint32_t>(l->export_batch_threshold_size_bytes_->load() / 1024 / 1024),
               l->export_max_files_per_batch_->load(), std::move(l->serializer_),
               std::move(l->writer_)) {}

  absl::flat_hash_map<std::string, bool> TrackerState() { return tracker_.file_state_; }
};

}  // namespace santa

using santa::LoggerPeer;

class MockSerializer : public Empty {
 public:
  MOCK_METHOD(std::vector<uint8_t>, SerializeMessage, (const EnrichedClose &msg));

  MOCK_METHOD(std::vector<uint8_t>, SerializeAllowlist, (const Message &, const std::string_view));

  MOCK_METHOD(std::vector<uint8_t>, SerializeBundleHashingEvent, (SNTStoredExecutionEvent *));
  MOCK_METHOD(std::vector<uint8_t>, SerializeDiskAppeared, (NSDictionary *, bool));
  MOCK_METHOD(std::vector<uint8_t>, SerializeDiskDisappeared, (NSDictionary *));

  MOCK_METHOD(std::vector<uint8_t>, SerializeFileAccess,
              (const std::string &policy_version, const std::string &policy_name,
               const santa::Message &msg, const santa::EnrichedProcess &enriched_process,
               size_t target_index, std::optional<santa::EnrichedFile> enriched_event_target,
               FileAccessPolicyDecision decision, std::string_view operation_id),
              (override));

  MOCK_METHOD(std::vector<uint8_t>, SerializeFileAccess,
              (const std::string &policy_version, const std::string &policy_name,
               const santa::Message &msg, const santa::EnrichedProcess &enriched_process,
               size_t target_index, std::optional<santa::EnrichedFile> enriched_event_target,
               FileAccessPolicyDecision decision),
              (override));
};

class MockWriter : public santa::Writer {
 public:
  MOCK_METHOD(void, Write, (std::vector<uint8_t> && bytes), (override));
  MOCK_METHOD(void, Flush, (), (override));
  MOCK_METHOD(std::optional<std::string>, NextFileToExport, (), (override));
  MOCK_METHOD(void, FilesExported, ((absl::flat_hash_map<std::string, bool> files_exported)),
              (override));
};

class MockSleighLauncher : public santa::SleighLauncher {
 public:
  MockSleighLauncher() : santa::SleighLauncher("/fake/sleigh") {}

  MOCK_METHOD(absl::Status, Launch,
              (const std::vector<std::string> &input_files, uint32_t timeout_seconds), (override));
};

@interface LoggerTest : XCTestCase
@property NSFileManager *fileMgr;
@property NSString *testDir;
@property SNTExportConfiguration * (^exportConfigBlock)(void);
@end

@implementation LoggerTest

- (void)setUp {
  self.fileMgr = [NSFileManager defaultManager];
  self.testDir =
      [NSString stringWithFormat:@"%@santa-logger-test-%d", NSTemporaryDirectory(), getpid()];

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);

  self.exportConfigBlock = ^{
    return [[SNTExportConfiguration alloc] initWithURL:[NSURL URLWithString:@"http://test.example"]
                                            formValues:@{@"key" : @"value"}];
  };
}

- (void)tearDown {
  NSError *err;
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:&err]);
  if (err) {
    XCTFail(@"Test dir cleanup failed: %@", err);
  }
}

- (NSString *)createTestFile:(NSString *)name
                 contentSize:(NSUInteger)contentSize
                        type:(ExportLogType)fileType {
  static uint32_t magic = 0x0;
  XCTAssertGreaterThanOrEqual(contentSize, sizeof(magic));
  switch (fileType) {
    case ExportLogType::kUnknown: magic = 0x0a; break;
    case ExportLogType::kZstdStream: magic = 0xfd2fb528; break;
    default: XCTFail("Creating unsupported file type: %d", (int)fileType); break;
  }

  NSMutableData *d = [[NSMutableData alloc] initWithBytes:&magic length:sizeof(magic)];
  NSString *content = RepeatedString(@"A", contentSize - sizeof(magic));
  [d appendBytes:content.UTF8String length:content.length];

  NSString *path = [NSString stringWithFormat:@"%@/%@", self.testDir, name];
  XCTAssertTrue([d writeToFile:path atomically:YES]);

  return path;
}

- (NSString *)createTestFile:(NSString *)name contentSize:(NSUInteger)contentSize {
  return [self createTestFile:name contentSize:contentSize type:ExportLogType::kUnknown];
}

- (void)testCreate {
  // Ensure that the factory method creates expected serializers/writers pairs
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();

  XCTAssertEqual(nullptr, Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                         (SNTEventLogType)123, nil, @"/tmp/temppy", @"/tmp/spool",
                                         1, 1, 1, 1, 1, 1, 1));

  LoggerPeer logger(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                   SNTEventLogTypeFilelog, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1,
                                   1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<BasicString>(logger.serializer_));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<File>(logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeSyslog, nil, @"/tmp/temppy", @"/tmp/spool", 1,
                                     1, 1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<BasicString>(logger.serializer_));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Syslog>(logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeNull, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1,
                                     1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Empty>(logger.serializer_));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Null>(logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeProtobuf, nil, @"/tmp/temppy", @"/tmp/spool", 1,
                                     1, 1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.serializer_));
  XCTAssertNotEqual(nullptr,
                    std::dynamic_pointer_cast<Spool<::fsspool::AnyBatcher>>(logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeProtobufStream, nil, @"/tmp/temppy",
                                     @"/tmp/spool", 1, 1, 1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.serializer_));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Spool<::fsspool::UncompressedStreamBatcher>>(
                                 logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeProtobufStreamGzip, nil, @"/tmp/temppy",
                                     @"/tmp/spool", 1, 1, 1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.serializer_));
  XCTAssertNotEqual(nullptr,
                    std::dynamic_pointer_cast<Spool<::fsspool::GzipStreamBatcher>>(logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeProtobufStreamZstd, nil, @"/tmp/temppy",
                                     @"/tmp/spool", 1, 1, 1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.serializer_));
  XCTAssertNotEqual(nullptr,
                    std::dynamic_pointer_cast<Spool<::fsspool::ZstdStreamBatcher>>(logger.writer_));

  logger = LoggerPeer(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                     SNTEventLogTypeJSON, nil, @"/tmp/temppy", @"/tmp/spool", 1, 1,
                                     1, 1, 1, 1, 1));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<Protobuf>(logger.serializer_));
  XCTAssertNotEqual(nullptr, std::dynamic_pointer_cast<File>(logger.writer_));
}

- (void)testLog {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();

  // Ensure all Logger::Log* methods call the serializer followed by the writer
  es_message_t msg;

  mockESApi->SetExpectationsRetainReleaseMessage();

  {
    auto enrichedMsg = std::make_unique<EnrichedMessage>(EnrichedClose(
        Message(mockESApi, &msg),
        EnrichedProcess(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                        EnrichedFile(std::nullopt, std::nullopt, std::nullopt), std::nullopt),
        EnrichedFile(std::nullopt, std::nullopt, std::nullopt)));

    EXPECT_CALL(*mockSerializer, SerializeMessage(testing::A<const EnrichedClose &>())).Times(1);
    EXPECT_CALL(*mockWriter, Write).Times(1);

    Logger(nil, nil, TelemetryEvent::kEverything, 1, 1, 1, mockSerializer, mockWriter)
        .Log(std::move(enrichedMsg));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogAllowList {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();
  es_message_t msg;
  std::string_view hash = "this_is_my_test_hash";

  mockESApi->SetExpectationsRetainReleaseMessage();
  EXPECT_CALL(*mockSerializer, SerializeAllowlist(testing::_, hash));
  EXPECT_CALL(*mockWriter, Write);

  Logger(nil, nil, TelemetryEvent::kEverything, 1, 1, 1, mockSerializer, mockWriter)
      .LogAllowlist(Message(mockESApi, &msg), hash);

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogBundleHashingEvents {
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();
  NSArray<id> *events = @[ @"event1", @"event2", @"event3" ];

  EXPECT_CALL(*mockSerializer, SerializeBundleHashingEvent).Times((int)[events count]);
  EXPECT_CALL(*mockWriter, Write).Times((int)[events count]);

  Logger(nil, nil, TelemetryEvent::kEverything, 1, 1, 1, mockSerializer, mockWriter)
      .LogBundleHashingEvents(events);

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogDiskAppeared {
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();

  EXPECT_CALL(*mockSerializer, SerializeDiskAppeared);
  EXPECT_CALL(*mockWriter, Write);

  Logger(nil, nil, TelemetryEvent::kEverything, 1, 1, 1, mockSerializer, mockWriter)
      .LogDiskAppeared(@{@"key" : @"value"}, true);

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogDiskDisappeared {
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();

  EXPECT_CALL(*mockSerializer, SerializeDiskDisappeared);
  EXPECT_CALL(*mockWriter, Write);

  Logger(nil, nil, TelemetryEvent::kEverything, 1, 1, 1, mockSerializer, mockWriter)
      .LogDiskDisappeared(@{@"key" : @"value"});

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testLogFileAccess {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  auto mockSerializer = std::make_shared<MockSerializer>();
  auto mockWriter = std::make_shared<MockWriter>();
  es_message_t msg;

  mockESApi->SetExpectationsRetainReleaseMessage();
  using testing::_;
  EXPECT_CALL(*mockSerializer, SerializeFileAccess(_, _, _, _, _, _, _));
  EXPECT_CALL(*mockWriter, Write);

  Logger(nil, nil, TelemetryEvent::kEverything, 1, 1, 1, mockSerializer, mockWriter)
      .LogFileAccess(
          "v1", "name", Message(mockESApi, &msg),
          EnrichedProcess(std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                          EnrichedFile(std::nullopt, std::nullopt, std::nullopt), std::nullopt),
          0, EnrichedFile(std::nullopt, std::nullopt, std::nullopt),
          FileAccessPolicyDecision::kDenied);

  XCTBubbleMockVerifyAndClearExpectations(mockSerializer.get());
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testExportTracker {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  LoggerPeer logger(Logger::Create(mockESApi, nil, nil, TelemetryEvent::kEverything,
                                   SNTEventLogTypeNull, nil, @"", @"", 1, 1, 1, 1, 1, 1, 1));

  // Nothing in the map initially
  auto map = logger.tracker_.Drain();
  XCTAssertEqual(logger.TrackerState().size(), 0);
  XCTAssertEqual(map.size(), 0);

  // Start tracking a couple of keys
  logger.tracker_.Track("foo");
  XCTAssertEqual(logger.TrackerState().size(), 1);
  XCTAssertEqual(logger.TrackerState().at("foo"), false);

  logger.tracker_.Track("bar");
  XCTAssertEqual(logger.TrackerState().size(), 2);
  XCTAssertEqual(logger.TrackerState().at("bar"), false);

  // Change state of an existing key
  logger.tracker_.AckCompleted("bar");
  XCTAssertEqual(logger.TrackerState().at("bar"), true);

  // Change state of a non-existing key, it should be created
  logger.tracker_.AckCompleted("cake");
  XCTAssertEqual(logger.TrackerState().at("cake"), true);

  // Drain the tracker
  map = logger.tracker_.Drain();
  XCTAssertEqual(logger.TrackerState().size(), 0);
  XCTAssertEqual(map.size(), 3);
  XCTAssertEqual(map.at("foo"), false);
  XCTAssertEqual(map.at("bar"), true);
  XCTAssertEqual(map.at("cake"), true);

  // Add some more keys after draining
  logger.tracker_.Track("baz");
  logger.tracker_.AckCompleted("qaz");
  XCTAssertEqual(logger.TrackerState().size(), 2);
  XCTAssertEqual(logger.TrackerState().at("baz"), false);
  XCTAssertEqual(logger.TrackerState().at("qaz"), true);

  // Track something already ack'd, ensure value doesn't change
  logger.tracker_.Track("qaz");
  XCTAssertEqual(logger.TrackerState().size(), 2);
  XCTAssertEqual(logger.TrackerState().at("baz"), false);
  XCTAssertEqual(logger.TrackerState().at("qaz"), true);

  // One last drain for fun
  map = logger.tracker_.Drain();
  XCTAssertEqual(logger.TrackerState().size(), 0);
  XCTAssertEqual(map.size(), 2);
  XCTAssertEqual(map.at("baz"), false);
  XCTAssertEqual(map.at("qaz"), true);
}

- (void)setExportExpectationSuccess:(BOOL)success mock:(MockSleighLauncher *)mock {
  absl::Status result = success ? absl::OkStatus() : absl::InternalError("mock failure");
  EXPECT_CALL(*mock, Launch).WillOnce(Return(result));
}

- (void)testExportSuccessWithSupportedTypeAndUnknownFile {
  auto mockWriter = std::make_shared<MockWriter>();
  auto mockSleigh = std::make_unique<MockSleighLauncher>();
  MockSleighLauncher *mockSleighPtr = mockSleigh.get();

  [self setExportExpectationSuccess:YES mock:mockSleighPtr];

  // Only f2 and f3 will be exported (total 25 bytes)
  NSString *f1 = [self createTestFile:@"f1" contentSize:5];
  NSString *f2 = [self createTestFile:@"f2" contentSize:10 type:ExportLogType::kZstdStream];
  NSString *f3 = [self createTestFile:@"f3" contentSize:15 type:ExportLogType::kZstdStream];

  LoggerPeer l(std::move(mockSleigh), self.exportConfigBlock, TelemetryEvent::kEverything, 5, 1, 10,
               nullptr, mockWriter);

  EXPECT_CALL(*mockWriter, NextFileToExport)
      .WillOnce(Return(f1.UTF8String))
      .WillOnce(Return(f2.UTF8String))
      .WillOnce(Return(f3.UTF8String))
      .WillOnce(Return(std::nullopt));

  // All 3 files should be marked true - The zstd files were successfully
  // exported and the unknown file will be cleaned up.
  EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre(Pair(f1.UTF8String, true),
                                                              Pair(f2.UTF8String, true),
                                                              Pair(f3.UTF8String, true))));

  l.ExportTelemetrySerialized();

  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
  XCTBubbleMockVerifyAndClearExpectations(mockSleighPtr);
}

- (void)testExportFail {
  auto mockWriter = std::make_shared<MockWriter>();
  auto mockSleigh = std::make_unique<MockSleighLauncher>();
  MockSleighLauncher *mockSleighPtr = mockSleigh.get();

  NSString *f1 = [self createTestFile:@"f1" contentSize:5 type:ExportLogType::kZstdStream];
  NSString *f2 = [self createTestFile:@"f2" contentSize:10 type:ExportLogType::kZstdStream];
  NSString *f3 = [self createTestFile:@"f3" contentSize:15 type:ExportLogType::kZstdStream];

  [self setExportExpectationSuccess:NO mock:mockSleighPtr];

  LoggerPeer l(std::move(mockSleigh), self.exportConfigBlock, TelemetryEvent::kEverything, 5, 1, 10,
               nullptr, mockWriter);

  EXPECT_CALL(*mockWriter, NextFileToExport)
      .WillOnce(Return(f1.UTF8String))
      .WillOnce(Return(f2.UTF8String))
      .WillOnce(Return(f3.UTF8String))
      .WillOnce(Return(std::nullopt));

  // All files fail to export and are marked false.
  EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre(Pair(f1.UTF8String, false),
                                                              Pair(f2.UTF8String, false),
                                                              Pair(f3.UTF8String, false))));

  l.ExportTelemetrySerialized();

  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
  XCTBubbleMockVerifyAndClearExpectations(mockSleighPtr);
}

- (void)testExportMaxOpenedFiles {
  auto mockWriter = std::make_shared<MockWriter>();
  auto mockSleigh = std::make_unique<MockSleighLauncher>();
  MockSleighLauncher *mockSleighPtr = mockSleigh.get();

  // Only f1, f2, and f3 will be exported in the first batch (total 30 bytes).
  // File f4 will not be visited because of the limit being reached, but will
  // be exported in the second batch.
  NSString *f1 = [self createTestFile:@"f1" contentSize:5 type:ExportLogType::kZstdStream];
  NSString *f2 = [self createTestFile:@"f2" contentSize:10 type:ExportLogType::kZstdStream];
  NSString *f3 = [self createTestFile:@"f3" contentSize:15 type:ExportLogType::kZstdStream];
  NSString *f4 = [self createTestFile:@"f4" contentSize:40 type:ExportLogType::kZstdStream];

  absl::Status successResult = absl::OkStatus();
  EXPECT_CALL(*mockSleighPtr, Launch)
      .WillOnce(Return(successResult))
      .WillOnce(Return(successResult));

  // Limit to 3 files per batch
  LoggerPeer l(std::move(mockSleigh), self.exportConfigBlock, TelemetryEvent::kEverything, 5, 1, 3,
               nullptr, mockWriter);

  EXPECT_CALL(*mockWriter, NextFileToExport)
      .WillOnce(Return(f1.UTF8String))
      .WillOnce(Return(f2.UTF8String))
      .WillOnce(Return(f3.UTF8String))
      .WillOnce(Return(f4.UTF8String))
      .WillOnce(Return(std::nullopt));

  // Ensure only 3/4 files are sent the first time because of the file limit
  // are sent the second time.
  EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre(Pair(f4.UTF8String, true))))
      .After(EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre(
                                          Pair(f1.UTF8String, true), Pair(f2.UTF8String, true),
                                          Pair(f3.UTF8String, true)))));

  l.ExportTelemetrySerialized();

  XCTBubbleMockVerifyAndClearExpectations(mockSleighPtr);
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testExportFilesExportedCalledWhenEmpty {
  // This test ensures that FilesExported is called even when there are no files to export.
  auto mockWriter = std::make_shared<MockWriter>();
  auto mockSleigh = std::make_unique<MockSleighLauncher>();
  MockSleighLauncher *mockSleighPtr = mockSleigh.get();

  // No Launch call expected since there are no files

  LoggerPeer l(std::move(mockSleigh), self.exportConfigBlock, TelemetryEvent::kEverything, 5, 1, 3,
               nullptr, mockWriter);

  EXPECT_CALL(*mockWriter, NextFileToExport).WillOnce(Return(std::nullopt));

  EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre()));

  l.ExportTelemetrySerialized();

  XCTBubbleMockVerifyAndClearExpectations(mockSleighPtr);
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testExportMaxBatchSize {
  auto mockWriter = std::make_shared<MockWriter>();
  auto mockSleigh = std::make_unique<MockSleighLauncher>();
  MockSleighLauncher *mockSleighPtr = mockSleigh.get();

  // Files f1 and f2 will be exported in the first batch.
  // File f3 will go alone in the second batch.
  // Files f4 and f5 will go in the third batch.
  static constexpr NSUInteger oneMB = 1024 * 1024;
  NSString *f1 = [self createTestFile:@"f1"
                          contentSize:(oneMB - 1)
                                 type:ExportLogType::kZstdStream];
  NSString *f2 = [self createTestFile:@"f2" contentSize:10 type:ExportLogType::kZstdStream];
  NSString *f3 = [self createTestFile:@"f3" contentSize:oneMB type:ExportLogType::kZstdStream];
  NSString *f4 = [self createTestFile:@"f4" contentSize:40 type:ExportLogType::kZstdStream];
  NSString *f5 = [self createTestFile:@"f5" contentSize:oneMB type:ExportLogType::kZstdStream];

  absl::Status successResult = absl::OkStatus();
  EXPECT_CALL(*mockSleighPtr, Launch)
      .WillOnce(Return(successResult))
      .WillOnce(Return(successResult))
      .WillOnce(Return(successResult));

  LoggerPeer l(std::move(mockSleigh), self.exportConfigBlock, TelemetryEvent::kEverything, 5, 1, 10,
               nullptr, mockWriter);

  EXPECT_CALL(*mockWriter, NextFileToExport)
      .WillOnce(Return(f1.UTF8String))
      .WillOnce(Return(f2.UTF8String))
      .WillOnce(Return(f3.UTF8String))
      .WillOnce(Return(f4.UTF8String))
      .WillOnce(Return(f5.UTF8String))
      .WillOnce(Return(std::nullopt));

  // Ensure the batches happen in the expected order
  EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre()))
      .After(EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre(
                                          Pair(f4.UTF8String, true), Pair(f5.UTF8String, true))))
                 .After(EXPECT_CALL(*mockWriter,
                                    FilesExported(UnorderedElementsAre(Pair(f3.UTF8String, true)))))
                 .After(EXPECT_CALL(
                     *mockWriter, FilesExported(UnorderedElementsAre(Pair(f1.UTF8String, true),
                                                                     Pair(f2.UTF8String, true))))));

  l.ExportTelemetrySerialized();

  XCTBubbleMockVerifyAndClearExpectations(mockSleighPtr);
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testExportNoMoreBatchesAfterFailedExport {
  auto mockWriter = std::make_shared<MockWriter>();
  auto mockSleigh = std::make_unique<MockSleighLauncher>();
  MockSleighLauncher *mockSleighPtr = mockSleigh.get();

  // Only f1 and f2 will be sent in the first batch due to file limitations.
  NSString *f1 = [self createTestFile:@"f1" contentSize:5 type:ExportLogType::kZstdStream];
  NSString *f2 = [self createTestFile:@"f2" contentSize:10 type:ExportLogType::kZstdStream];

  // Simulate failed export
  [self setExportExpectationSuccess:NO mock:mockSleighPtr];

  // Limit to 2 files per batch
  LoggerPeer l(std::move(mockSleigh), self.exportConfigBlock, TelemetryEvent::kEverything, 5, 1, 2,
               nullptr, mockWriter);

  // Note: std::nullopt is never returned as the export loops don't continue
  EXPECT_CALL(*mockWriter, NextFileToExport)
      .WillOnce(Return(f1.UTF8String))
      .WillOnce(Return(f2.UTF8String));

  // Both files should be marked false because the export failed.
  EXPECT_CALL(*mockWriter, FilesExported(UnorderedElementsAre(Pair(f1.UTF8String, false),
                                                              Pair(f2.UTF8String, false))));

  l.ExportTelemetrySerialized();

  XCTBubbleMockVerifyAndClearExpectations(mockSleighPtr);
  XCTBubbleMockVerifyAndClearExpectations(mockWriter.get());
}

- (void)testExportSettingsClamp {
  LoggerPeer l(nullptr, self.exportConfigBlock, TelemetryEvent::kNone, 5, 1, 2, nullptr, nullptr);

  // Export batch threshold size must be between 1 and 5120 MB
  constexpr uint64_t mb_multiplier = 1024 * 1024;
  l.SetBatchThresholdSizeMB(0);
  XCTAssertEqual(l.export_batch_threshold_size_bytes_->load(), 1 * mb_multiplier);
  l.SetBatchThresholdSizeMB(20000);
  XCTAssertEqual(l.export_batch_threshold_size_bytes_->load(), 5120 * mb_multiplier);
  l.SetBatchThresholdSizeMB(75);
  XCTAssertEqual(l.export_batch_threshold_size_bytes_->load(), 75 * mb_multiplier);

  // Max filesper batch must be between 1 and 100
  l.SetMaxFilesPerBatch(0);
  XCTAssertEqual(l.export_max_files_per_batch_->load(), 1);
  l.SetMaxFilesPerBatch(200);
  XCTAssertEqual(l.export_max_files_per_batch_->load(), 100);
  l.SetMaxFilesPerBatch(60);
  XCTAssertEqual(l.export_max_files_per_batch_->load(), 60);

  // Telemetry export timeout must be between 1 and 600 seconds
  l.SetTelmetryExportTimeoutSecs(0);
  XCTAssertEqual(l.export_timeout_secs_->load(), 1);
  l.SetTelmetryExportTimeoutSecs(1000);
  XCTAssertEqual(l.export_timeout_secs_->load(), 600);
  l.SetTelmetryExportTimeoutSecs(250);
  XCTAssertEqual(l.export_timeout_secs_->load(), 250);
}

@end
