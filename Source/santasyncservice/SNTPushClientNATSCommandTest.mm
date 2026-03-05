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

#import <CommonCrypto/CommonHMAC.h>
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

// Constants from SNTPushClientNATS+Commands.mm
static constexpr int64_t kMaxCommandAgeSeconds = 300;
static constexpr NSUInteger kMaxCommandNonceCacheCount = kMaxCommandAgeSeconds;

// Expose private methods for testing
@interface SNTPushClientNATS (Testing)
@property(nonatomic) natsConnection *conn;
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic) dispatch_queue_t connectionQueue;
@property(nonatomic) dispatch_queue_t messageQueue;
@property(nonatomic, copy) NSString *pushDeviceID;
@property(nonatomic, copy) NSData *hmacKey;
@property(nonatomic) NSMutableSet<NSString *> *currentNonces;
@property(nonatomic) NSMutableSet<NSString *> *previousNonces;
@property(nonatomic) int64_t lastRotationTime;
- (void)disconnectWithCompletion:(void (^)(void))completion;
- (::pbv1::PingResponse *)handlePingRequest:(const ::pbv1::PingRequest &)pingRequest
                            withCommandUUID:(NSString *)uuid
                                    onArena:(google::protobuf::Arena *)arena;
- (::pbv1::KillResponse *)handleKillRequest:(const ::pbv1::KillRequest &)killRequest
                            withCommandUUID:(NSString *)uuid
                                    onArena:(google::protobuf::Arena *)arena;
- (::pbv1::EventUploadResponse *)handleEventUploadRequest:
                                     (const ::pbv1::EventUploadRequest &)eventUploadRequest
                                          withCommandUUID:(NSString *)uuid
                                                  onArena:(google::protobuf::Arena *)arena;
- (::pbv1::SantaCommandResponse *)dispatchSantaCommandToHandler:
                                      (const ::pbv1::SantaCommandRequest &)command
                                                        onArena:(google::protobuf::Arena *)arena;
- (void)publishResponse:(const ::pbv1::SantaCommandResponse &)response
           toReplyTopic:(NSString *)replyTopic;
@end

@interface SNTPushClientNATSCommandTest : XCTestCase
@property id mockConfigurator;
@property id mockSyncDelegate;
@property SNTPushClientNATS *client;
@property google::protobuf::Arena *arena;
@property NSData *testHMACKey;

// Helper method to sign a command request with HMAC
- (void)signCommandRequest:(::pbv1::SantaCommandRequest *)command;
@end

@implementation SNTPushClientNATSCommandTest

- (void)setUp {
  [super setUp];

  self.arena = new google::protobuf::Arena();

  // Mock configurator
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // Mock sync delegate
  self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));

  // Create client
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Set up test HMAC key (32 bytes for SHA256)
  const char *keyString = "test_hmac_key_for_unit_tests_32";
  self.testHMACKey = [NSData dataWithBytes:keyString length:32];
  self.client.hmacKey = self.testHMACKey;

  // Ensure the nonce caches are in an expected initial state
  self.client.currentNonces = [NSMutableSet set];
  self.client.previousNonces = [NSMutableSet set];
  self.client.lastRotationTime = time(nullptr);
}

- (void)tearDown {
  [self.client disconnectWithCompletion:nil];
  self.client = nil;
  [self.mockConfigurator stopMocking];
  delete self.arena;
  self.arena = nullptr;
  [super tearDown];
}

#pragma mark - Helper Methods

- (void)signCommandRequest:(::pbv1::SantaCommandRequest *)command {
  // Prep the command to be signed - set the current time and clear any existing hmac.
  command->set_issued_at(time(nullptr));
  command->clear_hmac();

  std::string serialized;
  if (!command->SerializeToString(&serialized)) {
    XCTFail(@"Failed to serialize command for HMAC signing");
    return;
  }

  unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, self.testHMACKey.bytes, self.testHMACKey.length, serialized.data(),
         serialized.size(), hmac);

  command->set_hmac(hmac, CC_SHA256_DIGEST_LENGTH);
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
  ::pbv1::PingResponse *response = [self.client handlePingRequest:pingRequest
                                                  withCommandUUID:@"uuid"
                                                          onArena:self.arena];

  // Then: Should return a successful response
  XCTAssertNotEqual(response, nullptr, @"Response should not be nil");
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
  ::pbv1::PingResponse *response = [self.client handlePingRequest:deserialized.ping()
                                                  withCommandUUID:@"uuid"
                                                          onArena:self.arena];
  XCTAssertNotEqual(response, nullptr, @"Ping handler should return ping response");
}

- (void)testHandleEmptyKillCommand {
  // Given: A KillRequest
  ::pbv1::KillRequest killRequest;

  // When: Handling the kill command
  ::pbv1::KillResponse *response = [self.client handleKillRequest:killRequest
                                                  withCommandUUID:@"uuid"
                                                          onArena:self.arena];

  // Then: Should return a successful response
  XCTAssertNotEqual(response, nullptr, @"Kill command should return kill response");
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
  ::pbv1::KillResponse *response = [self.client handleKillRequest:deserialized.kill()
                                                  withCommandUUID:@"uuid"
                                                          onArena:self.arena];
  XCTAssertNotEqual(response, nullptr, @"Kill handler should return kill response");
}

- (void)testCommandHandlerBadUUID {
  // Given: A command with a bad UUID
  ::pbv1::SantaCommandRequest command;
  command.set_uuid("bad_uuid");
  // Don't set any command type

  // Sign the command with HMAC
  [self signCommandRequest:&command];

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize command");
  XCTAssertGreaterThan(commandData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized empty command");
  XCTAssertFalse(deserialized.has_ping(), @"Command should not have ping field set");
  XCTAssertFalse(deserialized.has_kill(), @"Command should not have kill field set");

  // Test dispatch with bad UUID
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:deserialized
                                                                              onArena:self.arena];
  XCTAssertTrue(response->has_error());
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_UUID);
}

- (void)testCommandHandlerUnknownCommand {
  // Given: A command with a valid UUID but no known type set
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  // Don't set any command type

  [self signCommandRequest:&command];

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);

  // Then: Should serialize successfully
  XCTAssertTrue(serialized, @"Failed to serialize command");
  XCTAssertGreaterThan(commandData.length(), 0, @"Serialized data should not be empty");

  // Verify deserialization
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);

  XCTAssertTrue(parsed, @"Failed to parse serialized command");
  XCTAssertFalse(deserialized.has_ping(), @"Command should not have ping field set");
  XCTAssertFalse(deserialized.has_kill(), @"Command should not have kill field set");

  // Test dispatch with unknown command
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:deserialized
                                                                              onArena:self.arena];
  XCTAssertTrue(response->has_error());
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_UNKNOWN_REQUEST_TYPE);
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

  [self signCommandRequest:&command];

  // When: Dispatching the command
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should return a successful ping response
  XCTAssertFalse(response->has_error());
  XCTAssertEqual(response->result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Ping command should return ping response");
}

- (void)testDispatchSantaCommandToHandlerUnknown {
  // Given: A command with no known type set
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  // Don't set any command type

  [self signCommandRequest:&command];

  // When: Dispatching the command
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should return an error response
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_UNKNOWN_REQUEST_TYPE);
}

- (void)testDispatchSantaCommandToHandlerWithPingRequest {
  // Given: A valid PingRequest protobuf message
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();

  [self signCommandRequest:&command];

  std::string commandData;
  BOOL serialized = command.SerializeToString(&commandData);
  XCTAssertTrue(serialized, @"Failed to serialize PingRequest");

  // Deserialize
  ::pbv1::SantaCommandRequest deserialized;
  BOOL parsed = deserialized.ParseFromString(commandData);
  XCTAssertTrue(parsed, @"Failed to parse serialized PingRequest");

  // When: Dispatching the deserialized command
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:deserialized
                                                                              onArena:self.arena];

  // Then: Should return a successful ping response
  XCTAssertFalse(response->has_error());
  XCTAssertEqual(response->result_case(), ::pbv1::SantaCommandResponse::kPing,
                 @"Ping command should return ping response");
}

#pragma mark - HMAC Verification Tests

- (void)testHMACVerificationInvalidSignature {
  // Given: A command with an invalid HMAC signature
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();
  [self signCommandRequest:&command];

  // Corrupt the HMAC by flipping a byte
  std::string hmac = command.hmac();
  hmac[0] ^= 0xFF;
  command.set_hmac(hmac);

  // When: Dispatching the command with corrupted HMAC
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response->has_error(), @"Command with invalid HMAC should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Invalid HMAC should return INVALID_DATA error");
}

- (void)testHMACVerificationMissingSignature {
  // Given: A command without HMAC signature
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();
  command.set_issued_at(time(nullptr));

  // When: Dispatching the command without HMAC
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response->has_error(), @"Command without HMAC should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Missing HMAC should return INVALID_DATA error");
}

- (void)testHMACVerificationWrongLength {
  // Given: A command with incorrect HMAC length
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();
  command.set_issued_at(time(nullptr));

  // Set HMAC with wrong length (16 bytes instead of 32)
  unsigned char shortHmac[16] = {0};
  command.set_hmac(shortHmac, 16);

  // When: Dispatching the command with wrong HMAC length
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response->has_error(), @"Command with wrong HMAC length should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Wrong HMAC length should return INVALID_DATA error");
}

#pragma mark - Timestamp Verification Tests

- (void)testTimestampVerificationTooOld {
  // Given: A command with timestamp older than kMaxCommandAgeSeconds seconds
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();

  // Set timestamp to just over the limit
  command.set_issued_at(time(nullptr) - (kMaxCommandAgeSeconds + 1));

  // Sign with the old timestamp
  command.clear_hmac();
  std::string serialized;
  XCTAssertTrue(command.SerializeToString(&serialized));

  unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, self.testHMACKey.bytes, self.testHMACKey.length, serialized.data(),
         serialized.size(), hmac);
  command.set_hmac(hmac, CC_SHA256_DIGEST_LENGTH);

  // When: Dispatching the command with old timestamp
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response->has_error(), @"Command with old timestamp should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Old timestamp should return INVALID_DATA error");
}

- (void)testTimestampVerificationFromFuture {
  // Given: A command with timestamp from far future (>kMaxCommandAgeSeconds seconds)
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();

  // Set timestamp to (kMaxCommandAgeSeconds + 1) seconds in the future
  command.set_issued_at(time(nullptr) + (kMaxCommandAgeSeconds + 1));

  // Sign with the future timestamp
  command.clear_hmac();
  std::string serialized;
  XCTAssertTrue(command.SerializeToString(&serialized));

  unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, self.testHMACKey.bytes, self.testHMACKey.length, serialized.data(),
         serialized.size(), hmac);
  command.set_hmac(hmac, CC_SHA256_DIGEST_LENGTH);

  // When: Dispatching the command with future timestamp
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response->has_error(), @"Command with future timestamp should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Future timestamp should return INVALID_DATA error");
}

- (void)testTimestampVerificationMissing {
  // Given: A command without timestamp (issued_at = 0)
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_ping();
  // Don't set issued_at (defaults to 0)

  // Sign without timestamp
  command.clear_hmac();
  std::string serialized;
  XCTAssertTrue(command.SerializeToString(&serialized));

  unsigned char hmac[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, self.testHMACKey.bytes, self.testHMACKey.length, serialized.data(),
         serialized.size(), hmac);
  command.set_hmac(hmac, CC_SHA256_DIGEST_LENGTH);

  // When: Dispatching the command without timestamp
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response->has_error(), @"Command without timestamp should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Missing timestamp should return INVALID_DATA error");
}

- (void)testTimestampVerificationWithinBounds {
  // Given: Commands with timestamps at the edge of acceptable range

  // Test timestamp just within the limit
  ::pbv1::SantaCommandRequest command1;
  command1.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command1.mutable_ping();
  command1.set_issued_at(time(nullptr) - (kMaxCommandAgeSeconds - 1));

  command1.clear_hmac();
  std::string serialized1;
  XCTAssertTrue(command1.SerializeToString(&serialized1));
  unsigned char hmac1[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, self.testHMACKey.bytes, self.testHMACKey.length, serialized1.data(),
         serialized1.size(), hmac1);
  command1.set_hmac(hmac1, CC_SHA256_DIGEST_LENGTH);

  ::pbv1::SantaCommandResponse *response1 = [self.client dispatchSantaCommandToHandler:command1
                                                                               onArena:self.arena];
  XCTAssertFalse(response1->has_error(), @"Command just within the limit should be accepted");

  // Test timestamp in future just within the limit
  ::pbv1::SantaCommandRequest command2;
  command2.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command2.mutable_ping();
  command2.set_issued_at(time(nullptr) + (kMaxCommandAgeSeconds - 1));

  command2.clear_hmac();
  std::string serialized2;
  XCTAssertTrue(command2.SerializeToString(&serialized2));
  unsigned char hmac2[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, self.testHMACKey.bytes, self.testHMACKey.length, serialized2.data(),
         serialized2.size(), hmac2);
  command2.set_hmac(hmac2, CC_SHA256_DIGEST_LENGTH);

  ::pbv1::SantaCommandResponse *response2 = [self.client dispatchSantaCommandToHandler:command2
                                                                               onArena:self.arena];
  XCTAssertFalse(response2->has_error(),
                 @"Command just within the future limit should be accepted");
}

#pragma mark - Nonce Cache Tests

- (void)testNonceReplayProtection {
  // Given: A PingRequest command with a specific UUID
  NSString *testUUID = [[NSUUID UUID] UUIDString];
  ::pbv1::SantaCommandRequest command;
  command.set_uuid(testUUID.UTF8String);
  command.mutable_ping();
  [self signCommandRequest:&command];

  // When: Dispatching the command the first time
  ::pbv1::SantaCommandResponse *response1 = [self.client dispatchSantaCommandToHandler:command
                                                                               onArena:self.arena];

  // Then: Should succeed
  XCTAssertFalse(response1->has_error(), @"First command should succeed");
  XCTAssertEqual(response1->result_case(), ::pbv1::SantaCommandResponse::kPing);

  // When: Dispatching the same command again (replay attack)
  ::pbv1::SantaCommandResponse *response2 = [self.client dispatchSantaCommandToHandler:command
                                                                               onArena:self.arena];

  // Then: Should be rejected with INVALID_DATA error
  XCTAssertTrue(response2->has_error(), @"Replay should be rejected");
  XCTAssertEqual(response2->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Replay should return INVALID_DATA error");
}

- (void)testNonceCacheRotation {
  // Given: A command that succeeds
  NSString *testUUID = [[NSUUID UUID] UUIDString];
  ::pbv1::SantaCommandRequest command;
  command.set_uuid(testUUID.UTF8String);
  command.mutable_ping();
  [self signCommandRequest:&command];

  ::pbv1::SantaCommandResponse *response1 = [self.client dispatchSantaCommandToHandler:command
                                                                               onArena:self.arena];
  XCTAssertFalse(response1->has_error(), @"First command should succeed");

  // When: Forcing a cache rotation (by manipulating lastRotationTime)
  // Simulate time passing ((kMaxCommandAgeSeconds + 1) seconds)
  self.client.lastRotationTime = time(nullptr) - (kMaxCommandAgeSeconds + 1);

  // Send a new command to trigger rotation
  NSString *newUUID = [[NSUUID UUID] UUIDString];
  ::pbv1::SantaCommandRequest newCommand;
  newCommand.set_uuid(newUUID.UTF8String);
  newCommand.mutable_ping();
  [self signCommandRequest:&newCommand];

  ::pbv1::SantaCommandResponse *response2 = [self.client dispatchSantaCommandToHandler:newCommand
                                                                               onArena:self.arena];
  XCTAssertFalse(response2->has_error(), @"New command should succeed and trigger rotation");

  // Then: The original UUID should still be rejected (now in previousNonces)
  ::pbv1::SantaCommandRequest replayCommand;
  replayCommand.set_uuid(testUUID.UTF8String);
  replayCommand.mutable_ping();
  [self signCommandRequest:&replayCommand];

  ::pbv1::SantaCommandResponse *response3 = [self.client dispatchSantaCommandToHandler:replayCommand
                                                                               onArena:self.arena];
  XCTAssertTrue(response3->has_error(), @"UUID in previousNonces should still be rejected");
  XCTAssertEqual(response3->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA);
}

- (void)testNonceCacheDoubleRotation {
  // Given: A command that succeeds
  NSString *oldUUID = [[NSUUID UUID] UUIDString];
  ::pbv1::SantaCommandRequest command;
  command.set_uuid(oldUUID.UTF8String);
  command.mutable_ping();
  [self signCommandRequest:&command];

  ::pbv1::SantaCommandResponse *response1 = [self.client dispatchSantaCommandToHandler:command
                                                                               onArena:self.arena];
  XCTAssertFalse(response1->has_error(), @"First command should succeed");

  // When: Forcing TWO cache rotations
  // First rotation
  self.client.lastRotationTime = time(nullptr) - (kMaxCommandAgeSeconds + 1);
  ::pbv1::SantaCommandRequest command2;
  command2.set_uuid([[[NSUUID UUID] UUIDString] UTF8String]);
  command2.mutable_ping();
  [self signCommandRequest:&command2];
  [self.client dispatchSantaCommandToHandler:command2 onArena:self.arena];

  // Second rotation
  self.client.lastRotationTime = time(nullptr) - (kMaxCommandAgeSeconds + 1);
  ::pbv1::SantaCommandRequest command3;
  command3.set_uuid([[[NSUUID UUID] UUIDString] UTF8String]);
  command3.mutable_ping();
  [self signCommandRequest:&command3];
  [self.client dispatchSantaCommandToHandler:command3 onArena:self.arena];

  // Then: The original UUID should now be accepted again (aged out of cache)
  ::pbv1::SantaCommandRequest replayCommand;
  replayCommand.set_uuid(oldUUID.UTF8String);
  replayCommand.mutable_ping();
  [self signCommandRequest:&replayCommand];

  ::pbv1::SantaCommandResponse *response4 = [self.client dispatchSantaCommandToHandler:replayCommand
                                                                               onArena:self.arena];
  XCTAssertFalse(response4->has_error(),
                 @"UUID should be accepted after aging out of two-generation cache");
  XCTAssertEqual(response4->result_case(), ::pbv1::SantaCommandResponse::kPing);
}

- (void)testNonceCacheThrottling {
  // Given: A client with an empty nonce cache
  // When: Sending more commands than the max cache size
  NSUInteger maxCommands = kMaxCommandNonceCacheCount;
  NSMutableArray<NSString *> *uuids = [NSMutableArray array];

  // Send maxCommands commands - all should succeed
  for (NSUInteger i = 0; i < maxCommands; i++) {
    NSString *uuid = [[NSUUID UUID] UUIDString];
    [uuids addObject:uuid];

    ::pbv1::SantaCommandRequest command;
    command.set_uuid(uuid.UTF8String);
    command.mutable_ping();
    [self signCommandRequest:&command];

    ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                                onArena:self.arena];
    XCTAssertFalse(response->has_error(), @"Command %lu should succeed (within limit)", i + 1);
  }

  // Then: The next command should be throttled
  ::pbv1::SantaCommandRequest throttledCommand;
  throttledCommand.set_uuid([[[NSUUID UUID] UUIDString] UTF8String]);
  throttledCommand.mutable_ping();
  [self signCommandRequest:&throttledCommand];

  ::pbv1::SantaCommandResponse *throttledResponse =
      [self.client dispatchSantaCommandToHandler:throttledCommand onArena:self.arena];

  XCTAssertTrue(throttledResponse->has_error(), @"Command over limit should be throttled");
  XCTAssertEqual(throttledResponse->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA,
                 @"Throttled command should return INVALID_DATA error");
}

- (void)testNonceCachePreviousGenerationReplay {
  // Given: Add a UUID directly to the previousNonces cache
  NSString *previousUUID = [[NSUUID UUID] UUIDString];
  [self.client.previousNonces addObject:previousUUID];

  // When: Attempting to use that UUID
  ::pbv1::SantaCommandRequest command;
  command.set_uuid(previousUUID.UTF8String);
  command.mutable_ping();
  [self signCommandRequest:&command];

  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should be rejected
  XCTAssertTrue(response->has_error(), @"UUID in previousNonces should be rejected");
  XCTAssertEqual(response->error(), ::pbv1::SantaCommandResponse::ERROR_INVALID_DATA);
}

#pragma mark - EventUpload Handler Tests

- (void)testHandleEventUploadRequestEmptyPath {
  // Given: An EventUploadRequest with an empty path
  ::pbv1::EventUploadRequest eventUploadRequest;

  // When: Handling the event upload request
  ::pbv1::EventUploadResponse *response = [self.client handleEventUploadRequest:eventUploadRequest
                                                                withCommandUUID:@"uuid"
                                                                        onArena:self.arena];

  // Then: Should return response with ERROR_INVALID_PATH
  XCTAssertNotEqual(response, nullptr, @"Should return non-nil response");
  XCTAssertTrue(response->has_error(), @"Should have error set");
  XCTAssertEqual(response->error(), ::pbv1::EventUploadResponse::ERROR_INVALID_PATH,
                 @"Empty path should return ERROR_INVALID_PATH");
}

- (void)testHandleEventUploadRequestNilSyncDelegate {
  // Given: An EventUploadRequest with a valid path but no sync delegate
  SNTPushClientNATS *clientWithoutDelegate = [[SNTPushClientNATS alloc] initWithSyncDelegate:nil];

  ::pbv1::EventUploadRequest eventUploadRequest;
  eventUploadRequest.set_path("/Applications/Safari.app");

  // When: Handling the event upload request without a sync delegate
  ::pbv1::EventUploadResponse *response =
      [clientWithoutDelegate handleEventUploadRequest:eventUploadRequest
                                      withCommandUUID:@"uuid"
                                              onArena:self.arena];

  // Then: Should return response with ERROR_INTERNAL
  XCTAssertNotEqual(response, nullptr, @"Should return non-nil response");
  XCTAssertTrue(response->has_error(), @"Should have error set");
  XCTAssertEqual(response->error(), ::pbv1::EventUploadResponse::ERROR_INTERNAL,
                 @"Nil sync delegate should return ERROR_INTERNAL");
}

- (void)testHandleEventUploadRequestSuccess {
  // Given: An EventUploadRequest with a valid path
  ::pbv1::EventUploadRequest eventUploadRequest;
  eventUploadRequest.set_path("/Applications/Safari.app");

  // Mock delegate - handler fires and forgets, so we just need the stub
  OCMStub([self.mockSyncDelegate eventUploadForPath:@"/Applications/Safari.app"
                                              reply:[OCMArg any]]);

  // When: Handling the event upload request
  ::pbv1::EventUploadResponse *response = [self.client handleEventUploadRequest:eventUploadRequest
                                                                withCommandUUID:@"uuid"
                                                                        onArena:self.arena];

  // Then: Should return a successful response with no error
  XCTAssertNotEqual(response, nullptr, @"Should return non-nil response");
  XCTAssertFalse(response->has_error(), @"Successful request should not have error");
}

- (void)testHandleEventUploadRequestFiresDelegate {
  // Given: An EventUploadRequest with a valid path
  ::pbv1::EventUploadRequest eventUploadRequest;
  eventUploadRequest.set_path("/Applications/Safari.app");

  // Mock delegate to verify it gets called (fire-and-forget)
  OCMExpect([self.mockSyncDelegate eventUploadForPath:@"/Applications/Safari.app"
                                                reply:[OCMArg any]]);

  // When: Handling the event upload request
  ::pbv1::EventUploadResponse *response = [self.client handleEventUploadRequest:eventUploadRequest
                                                                withCommandUUID:@"uuid"
                                                                        onArena:self.arena];

  // Then: Should return immediately with no error and delegate method should be called
  XCTAssertNotEqual(response, nullptr, @"Should return non-nil response");
  XCTAssertFalse(response->has_error(), @"Should not have error");
  OCMVerifyAll(self.mockSyncDelegate);
}

- (void)testDispatchSantaCommandToHandlerEventUpload {
  // Given: An EventUploadRequest command
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_event_upload()->set_path("/Applications/Safari.app");

  [self signCommandRequest:&command];

  // Mock delegate - handler fires and forgets
  OCMStub([self.mockSyncDelegate eventUploadForPath:@"/Applications/Safari.app"
                                              reply:[OCMArg any]]);

  // When: Dispatching the command
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should return a successful event upload response
  XCTAssertFalse(response->has_error());
  XCTAssertEqual(response->result_case(), ::pbv1::SantaCommandResponse::kEventUpload,
                 @"EventUpload command should return event upload response");
}

- (void)testDispatchSantaCommandToHandlerEventUploadError {
  // Given: An EventUploadRequest command with empty path
  ::pbv1::SantaCommandRequest command;
  command.set_uuid([[NSUUID UUID] UUIDString].UTF8String);
  command.mutable_event_upload();  // No path set

  [self signCommandRequest:&command];

  // When: Dispatching the command
  ::pbv1::SantaCommandResponse *response = [self.client dispatchSantaCommandToHandler:command
                                                                              onArena:self.arena];

  // Then: Should return EventUploadResponse with ERROR_INVALID_PATH (not top-level error)
  XCTAssertFalse(response->has_error(), @"Should not have top-level error");
  XCTAssertEqual(response->result_case(), ::pbv1::SantaCommandResponse::kEventUpload,
                 @"Should have event_upload response set");
  XCTAssertTrue(response->event_upload().has_error(), @"EventUploadResponse should have error");
  XCTAssertEqual(response->event_upload().error(), ::pbv1::EventUploadResponse::ERROR_INVALID_PATH,
                 @"Should return ERROR_INVALID_PATH on empty path");
}

@end
