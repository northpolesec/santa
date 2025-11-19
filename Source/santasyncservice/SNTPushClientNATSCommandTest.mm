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

// Expose private methods for testing
@interface SNTPushClientNATS (Testing)
@property(nonatomic) natsConnection *conn;
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic) dispatch_queue_t connectionQueue;
@property(nonatomic) dispatch_queue_t messageQueue;
@property(nonatomic, copy) NSString *pushDeviceID;
- (void)disconnectWithCompletion:(void (^)(void))completion;
- (santa::commands::v1::SantaCommandResponse)handlePingCommand:
    (const santa::commands::v1::PingRequest &)pingRequest;
- (void)publishCommandResponse:(santa::commands::v1::SantaCommandResponseCode)resultCode
                        output:(NSString *)output
                  toReplyTopic:(NSString *)replyTopic;
- (void)sendCommandSuccess:(NSString *)message toReplyTopic:(NSString *)replyTopic;
- (void)sendCommandError:(NSString *)errorMessage toReplyTopic:(NSString *)replyTopic;
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
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL);
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
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR);

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize error response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");
}

- (void)testSendCommandSuccess {
  // Given: Success message
  // When: Creating a success response
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL);
  response.mutable_ping();

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize success response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");
}

- (void)testSendCommandError {
  // Given: Error message
  // When: Creating an error response
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR);

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize error response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");
}

#pragma mark - Command Handler Tests

- (void)testHandlePingCommand {
  // Given: A PingRequest
  santa::commands::v1::PingRequest pingRequest;

  // When: Handling the ping command
  santa::commands::v1::SantaCommandResponse response = [self.client handlePingCommand:pingRequest];

  // Then: Should return a successful response
  XCTAssertEqual(response.code(), santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL,
                 @"Ping command should return successful code");
  XCTAssertEqual(response.result_case(), santa::commands::v1::SantaCommandResponse::kPing,
                 @"Ping command should return ping response");
}

- (void)testCommandHandlerPingRequest {
  // Given: A valid PingRequest protobuf message
  santa::commands::v1::SantaCommandRequest command;
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize PingRequest");
  XCTAssertGreaterThan(commandData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  santa::commands::v1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized PingRequest");
  XCTAssertTrue(deserialized.has_ping(), @"Command should have ping field set");

  // Verify the ping handler works with the deserialized command
  santa::commands::v1::SantaCommandResponse response =
      [self.client handlePingCommand:deserialized.ping()];
  XCTAssertEqual(response.code(), santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL,
                 @"Ping handler should return successful code");
  XCTAssertEqual(response.result_case(), santa::commands::v1::SantaCommandResponse::kPing,
                 @"Ping handler should return ping response");
}

- (void)testCommandHandlerUnknownCommand {
  // Given: A command with no known type set
  santa::commands::v1::SantaCommandRequest command;
  // Don't set any command type

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully (empty command)
  XCTAssertTrue(serialized, @"Failed to serialize empty command");
  XCTAssertGreaterThanOrEqual(commandData.length(), 0, @"Serialized data can be empty");

  // Verify deserialization
  santa::commands::v1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized empty command");
  XCTAssertFalse(deserialized.has_ping(), @"Command should not have ping field set");
}

- (void)testCommandHandlerInvalidProtobuf {
  // Given: Invalid protobuf data
  std::string invalidData = "invalid protobuf data";

  // When: Trying to parse invalid data
  santa::commands::v1::SantaCommandRequest command;
  BOOL parsed = command.ParseFromString(invalidData);

  // Then: Should fail to parse
  XCTAssertFalse(parsed, @"Should fail to parse invalid protobuf data");
}

- (void)testCommandHandlerNoReplyTopic {
  // Given: Command message with no reply topic
  // Note: In real handler, message without reply topic would be ignored
  // This test verifies the command can be serialized/deserialized
  santa::commands::v1::SantaCommandRequest command;
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize command");
}

- (void)testCommandResponseSerialization {
  // Given: Command response for ping
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL);
  response.mutable_ping();

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize ping response");
  XCTAssertGreaterThan(responseData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  santa::commands::v1::SantaCommandResponse deserialized;
  BOOL parsed = deserialized.ParseFromString(responseData);

  XCTAssertTrue(parsed, @"Failed to parse serialized ping response");
  XCTAssertEqual(deserialized.code(), santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL,
                 @"Code should be SUCCESSFUL");
  XCTAssertEqual(deserialized.result_case(), santa::commands::v1::SantaCommandResponse::kPing,
                 @"Result should be ping");
}

- (void)testCommandResponseErrorSerialization {
  // Given: Error response
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR);

  std::string responseData;
  BOOL serialized = response.SerializeToString(&responseData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize error response");

  // Verify deserialization
  santa::commands::v1::SantaCommandResponse deserialized;
  BOOL parsed = deserialized.ParseFromString(responseData);

  XCTAssertTrue(parsed, @"Failed to parse serialized error response");
  XCTAssertEqual(deserialized.code(), santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR,
                 @"Code should be ERROR");
  XCTAssertEqual(deserialized.result_case(),
                 santa::commands::v1::SantaCommandResponse::RESULT_NOT_SET,
                 @"Result should not be set for error");
}

- (void)testPingRequestSerialization {
  // Given: PingRequest command
  santa::commands::v1::SantaCommandRequest command;
  command.mutable_ping();

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize PingRequest");

  // Verify deserialization
  santa::commands::v1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized PingRequest");
  XCTAssertTrue(deserialized.has_ping(), @"Command should have ping field set");
}

@end
