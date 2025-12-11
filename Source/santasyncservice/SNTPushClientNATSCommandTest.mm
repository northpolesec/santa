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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTPushNotifications.h"

#include "commands/v1.pb.h"

__BEGIN_DECLS

// Include NATS C client header
#import "src/nats.h"

__END_DECLS

namespace pbv1 = ::santa::commands::v1;

// Expose private methods for testing
@interface SNTPushClientNATS (Testing)
@property(nonatomic) natsConnection *conn;
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic) dispatch_queue_t connectionQueue;
@property(nonatomic) dispatch_queue_t messageQueue;
@property(nonatomic, copy) NSString *pushDeviceID;
- (void)disconnectWithCompletion:(void (^)(void))completion;
- (::pbv1::SantaCommandResponse)handlePingRequest:(const ::pbv1::PingRequest &)pingRequest
                                  withCommandUUID:(NSString *)uuid;
- (::pbv1::SantaCommandResponse)handleKillRequest:(const ::pbv1::KillRequest &)killRequest
                                  withCommandUUID:(NSString *)uuid;
- (::pbv1::SantaCommandResponse)dispatchSantaCommandToHandler:
    (const ::pbv1::SantaCommandRequest &)command;
- (void)publishResponse:(const ::pbv1::SantaCommandResponse &)response
           toReplyTopic:(NSString *)replyTopic;
@end

@interface SNTPushClientNATSCommandTest : XCTestCase
@property id mockConfigurator;
@property id mockSyncDelegate;
@property SNTPushClientNATS *client;
@end

@implementation SNTPushClientNATSCommandTest

- (void)setUp {
  [super setUp];

  // Mock configurator
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // Mock sync delegate
  self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));

  // Create client
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
}

- (void)tearDown {
  [self.client disconnectWithCompletion:nil];
  self.client = nil;
  [self.mockConfigurator stopMocking];
  [super tearDown];
}

#pragma mark - Command Response Publishing Tests

- (void)testPublishCommandResponseSuccess {
  // Given: Success response
  // Note: We can't actually test NATS publish without a real connection
  // This test verifies the serialization logic works correctly

  // When: Creating a response
  ::pbv1::SantaCommandResponse response;
  response.mutable_ping();

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize command response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");
}

- (void)testPublishCommandResponseError {
  // Given: Error response
  // When: Creating an error response
  ::pbv1::SantaCommandResponse response;
  response.set_error(::pbv1::SantaCommandResponse::ERROR_UNSPECIFIED);

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize error response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");
}

#pragma mark - Command Handler Tests

- (void)testHandlePingCommand {
  // Given: A PingRequest
  ::pbv1::PingRequest pingRequest;

  // When: Handling the ping command
  ::pbv1::SantaCommandResponse response = [self.client handlePingRequest:pingRequest
                                                         withCommandUUID:@"uuid"];

  // Then: Should return a successful response
  XCTAssertFalse(response.has_error());
  XCTAssertEqual(response.result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Ping command should return ping response");
}

- (void)testCommandHandlerPingRequest {
  // Given: A valid PingRequest protobuf message
  ::pbv1::SantaCommandRequest command;
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize PingRequest");
  XCTAssertGreaterThan(commandData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized PingRequest");
  XCTAssertTrue(deserialized.has_ping(), @"Command should have ping field set");

  // Verify the ping handler works with the deserialized command
  ::pbv1::SantaCommandResponse response = [self.client handlePingRequest:deserialized.ping()
                                                         withCommandUUID:@"uuid"];
  XCTAssertFalse(response.has_error());
  XCTAssertEqual(response.result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Ping handler should return ping response");
}

- (void)testHandleEmptyKillCommand {
  // Given: A KillRequest
  ::pbv1::KillRequest killRequest;

  // When: Handling the kill command
  ::pbv1::SantaCommandResponse response = [self.client handleKillRequest:killRequest
                                                         withCommandUUID:@"uuid"];

  // Then: Should return a successful response
  XCTAssertFalse(response.has_error());
  XCTAssertEqual(response.result_case(), ::pbv1::SantaCommandResponse::kKill,
                 @"Kill command should return kill response");
}

- (void)testCommandHandlerEmptyKillRequest {
  // Given: A valid KillRequest protobuf message
  ::pbv1::SantaCommandRequest command;
  command.mutable_kill();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize KillRequest");
  XCTAssertGreaterThan(commandData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized KillRequest");
  XCTAssertTrue(deserialized.has_kill(), @"Command should have kill field set");

  // Verify the kill handler works with the deserialized command
  ::pbv1::SantaCommandResponse response = [self.client handleKillRequest:deserialized.kill()
                                                         withCommandUUID:@"uuid"];
  XCTAssertFalse(response.has_error());
  XCTAssertEqual(response.result_case(), ::pbv1::SantaCommandResponse::kKill,
                 @"Kill handler should return kill response");
}

- (void)testCommandHandlerBadUUID {
  // Given: A command with no known type set
  ::pbv1::SantaCommandRequest command;
  command.set_uuid("bad_uuid");
  // Don't set any command type

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully (empty command)
  XCTAssertTrue(serialized, @"Failed to serialize empty command");
  XCTAssertGreaterThanOrEqual(commandData.length(), 0, @"Serialized data can be empty");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized empty command");
  XCTAssertFalse(deserialized.has_ping(), @"Command should not have ping field set");
  XCTAssertFalse(deserialized.has_kill(), @"Command should not have kill field set");

  // Test dispatch with unknown command
  ::pbv1::SantaCommandResponse response = [self.client dispatchSantaCommandToHandler:deserialized];
  XCTAssertTrue(response.has_error());
  XCTAssertEqual(response.error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_UUID);
}

- (void)testCommandHandlerUnknownCommand {
  // Given: A command with no known type set
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  // Don't set any command type

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully (empty command)
  XCTAssertTrue(serialized, @"Failed to serialize empty command");
  XCTAssertGreaterThanOrEqual(commandData.length(), 0, @"Serialized data can be empty");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized empty command");
  XCTAssertFalse(deserialized.has_ping(), @"Command should not have ping field set");
  XCTAssertFalse(deserialized.has_kill(), @"Command should not have kill field set");

  // Test dispatch with unknown command
  ::pbv1::SantaCommandResponse response = [self.client dispatchSantaCommandToHandler:deserialized];
  XCTAssertTrue(response.has_error());
  XCTAssertEqual(response.error(), ::pbv1::SantaCommandResponse::ERROR_UNKNOWN_REQUEST_TYPE);
}

- (void)testCommandHandlerInvalidProtobuf {
  // Given: Invalid protobuf data
  std::string invalidData = "invalid protobuf data";

  // When: Trying to parse invalid data
  ::pbv1::SantaCommandRequest command;
  BOOL parsed = command.ParseFromString(invalidData);

  // Then: Should fail to parse
  XCTAssertFalse(parsed, @"Should fail to parse invalid protobuf data");
}

- (void)testCommandHandlerNoReplyTopic {
  // Given: Command message with no reply topic
  // Note: In real handler, message without reply topic would be ignored
  // This test verifies the command can be serialized/deserialized
  ::pbv1::SantaCommandRequest command;
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize command");
}

- (void)testCommandResponseSerialization {
  // Given: Command response for ping
  ::pbv1::SantaCommandResponse response;
  response.mutable_ping();

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize ping response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  ::pbv1::SantaCommandResponse deserialized;
  BOOL parsed = deserialized.ParseFromString(responseData);

  XCTAssertTrue(parsed, @"Failed to parse serialized ping response");
  XCTAssertFalse(deserialized.has_error());
  XCTAssertEqual(deserialized.result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Result should be ping");
}

- (void)testCommandResponseErrorSerialization {
  // Given: Error response
  ::pbv1::SantaCommandResponse response;
  response.set_error(::pbv1::SantaCommandResponse::ERROR_DESERIALIZATION);

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize error response");

  // Verify deserialization
  ::pbv1::SantaCommandResponse deserialized;
  BOOL parsed = deserialized.ParseFromString(responseData);

  XCTAssertTrue(parsed, @"Failed to parse serialized error response");
  XCTAssertEqual(deserialized.error(), ::pbv1::SantaCommandResponse::ERROR_DESERIALIZATION);
  XCTAssertEqual(deserialized.result_case(), ::pbv1::SantaCommandResponse::RESULT_NOT_SET,
                 @"Result should not be set for error");
}

- (void)testPingRequestSerialization {
  // Given: PingRequest command
  ::pbv1::SantaCommandRequest command;
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize PingRequest");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized PingRequest");
  XCTAssertTrue(deserialized.has_ping(), @"Command should have ping field set");
}

#pragma mark - Command Dispatch Tests

- (void)testDispatchSantaCommandToHandlerPing {
  // Given: A PingRequest command
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();

  // When: Dispatching the command
  ::pbv1::SantaCommandResponse response = [self.client dispatchSantaCommandToHandler:command];

  // Then: Should return a successful ping response
  XCTAssertFalse(response.has_error());
  XCTAssertEqual(response.result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Ping command should return ping response");
}

- (void)testDispatchSantaCommandToHandlerUnknown {
  // Given: A command with no known type set
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  // Don't set any command type

  // When: Dispatching the command
  ::pbv1::SantaCommandResponse response = [self.client dispatchSantaCommandToHandler:command];

  // Then: Should return an error response
  XCTAssertEqual(response.error(), ::pbv1::SantaCommandResponse::ERROR_UNKNOWN_REQUEST_TYPE);
}

- (void)testDispatchSantaCommandToHandlerWithPingRequest {
  // Given: A valid PingRequest protobuf message
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);
  XCTAssertTrue(serialized, @"Failed to serialize PingRequest");

  // Deserialize
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);
  XCTAssertTrue(parsed, @"Failed to parse serialized PingRequest");

  // When: Dispatching the deserialized command
  ::pbv1::SantaCommandResponse response = [self.client dispatchSantaCommandToHandler:deserialized];

  // Then: Should return a successful ping response
  XCTAssertFalse(response.has_error());
  XCTAssertEqual(response.result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Ping command should return ping response");
}

@end
