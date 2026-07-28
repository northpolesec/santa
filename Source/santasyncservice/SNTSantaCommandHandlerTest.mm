/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+BinaryUpload.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+EventUpload.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+Kill.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+PackageInventory.h"
#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#include "commands/v1.pb.h"
#include "google/protobuf/arena.h"

namespace pbv1 = ::santa::commands::v1;

// Fake sync delegate that replies to event uploads synchronously, once per
// path, mirroring the contract of SNTSyncManager's implementation.
@interface SNTFakeCommandSyncDelegate : NSObject <SNTPushNotificationsSyncDelegate>
// Per-path reply errors. NSNull (or a missing entry) replies success.
@property(nonatomic) NSArray* eventUploadReplyErrors;
@property(nonatomic) NSArray<NSString*>* lastEventUploadPaths;
@property(nonatomic) NSUInteger eventUploadCallCount;
// Connection handed to commands that talk to santad. Nil (the default) stands
// in for a santasyncservice that isn't connected to the daemon.
@property(nonatomic) MOLXPCConnection* daemonConnection;
@end

@implementation SNTFakeCommandSyncDelegate
- (void)sync {
}
- (void)syncSecondsFromNow:(uint64_t)seconds {
}
- (void)ruleSync {
}
- (void)ruleSyncSecondsFromNow:(uint64_t)seconds {
}
- (void)preflightSync {
}
- (void)pushNotificationSyncSecondsFromNow:(uint64_t)seconds {
}
- (void)eventUploadForPaths:(NSArray<NSString*>*)paths reply:(void (^)(NSError* error))reply {
  self.eventUploadCallCount++;
  self.lastEventUploadPaths = paths;
  for (NSUInteger i = 0; i < paths.count; i++) {
    NSError* err = nil;
    if (i < self.eventUploadReplyErrors.count && ![self.eventUploadReplyErrors[i]
                                                     isKindOfClass:[NSNull class]]) {
      err = self.eventUploadReplyErrors[i];
    }
    reply(err);
  }
}
@end

@interface SNTSantaCommandHandlerTest : XCTestCase
@property id mockConfigurator;
@property id mockDaemonConnection;
@property SNTFakeCommandSyncDelegate* fakeSyncDelegate;
@property SNTSantaCommandHandler* handler;
@property google::protobuf::Arena* arena;
@property NSData* lastBinaryUploadRequestData;
@property NSUInteger binaryUploadCallCount;
@end

@implementation SNTSantaCommandHandlerTest

- (void)setUp {
  [super setUp];

  self.arena = new google::protobuf::Arena();

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.fakeSyncDelegate = [[SNTFakeCommandSyncDelegate alloc] init];
  self.handler = [[SNTSantaCommandHandler alloc] initWithSyncDelegate:self.fakeSyncDelegate];
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
  [self.mockDaemonConnection stopMocking];
  delete self.arena;
  self.arena = nullptr;
  [super tearDown];
}

#pragma mark - Test Helpers

// Connects the fake sync delegate to a mock santad that replies to
// uploadBinary: with `replyData`, recording what it was handed.
- (void)stubDaemonBinaryUploadReplyData:(NSData*)replyData {
  id mockProxy = OCMProtocolMock(@protocol(SNTDaemonControlXPC));
  OCMStub([mockProxy uploadBinary:OCMOCK_ANY reply:OCMOCK_ANY]).andDo(^(NSInvocation* invocation) {
    __unsafe_unretained NSData* requestData = nil;
    [invocation getArgument:&requestData atIndex:2];
    __unsafe_unretained void (^reply)(NSData*) = nil;
    [invocation getArgument:&reply atIndex:3];
    self.lastBinaryUploadRequestData = requestData;
    self.binaryUploadCallCount++;
    reply(replyData);
  });

  self.mockDaemonConnection = OCMClassMock([MOLXPCConnection class]);
  OCMStub([self.mockDaemonConnection remoteObjectProxy]).andReturn(mockProxy);
  self.fakeSyncDelegate.daemonConnection = self.mockDaemonConnection;
}

- (NSData*)serializedBinaryUploadResponseWithDisposition:
               (pbv1::BinaryUploadResponse::Disposition)disposition
                                          sha256Computed:(const std::string&)sha256 {
  pbv1::BinaryUploadResponse response;
  response.set_disposition(disposition);
  response.set_sha256_computed(sha256);
  std::string serialized;
  response.SerializeToString(&serialized);
  return [NSData dataWithBytes:serialized.data() length:serialized.size()];
}

#pragma mark - isCommandAllowed

- (void)testIsCommandAllowedUnsetConfigAllowsAll {
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(nil);
  XCTAssertTrue([SNTSantaCommandHandler isCommandAllowed:@"kill"]);
  XCTAssertTrue([SNTSantaCommandHandler isCommandAllowed:@"event_upload"]);
}

- (void)testIsCommandAllowedEmptyConfigBlocksAll {
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(@[]);
  XCTAssertFalse([SNTSantaCommandHandler isCommandAllowed:@"kill"]);
  XCTAssertFalse([SNTSantaCommandHandler isCommandAllowed:@"event_upload"]);
}

- (void)testIsCommandAllowedRespectsList {
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(@[ @"kill" ]);
  XCTAssertTrue([SNTSantaCommandHandler isCommandAllowed:@"kill"]);
  XCTAssertFalse([SNTSantaCommandHandler isCommandAllowed:@"event_upload"]);
}

#pragma mark - executeQueuedCommand

- (void)testExecuteQueuedCommandUnsetTypeFails {
  ::pbv1::QueuedCommand command;
  command.set_command_id(42);

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 42);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_FAILED);
  XCTAssertGreaterThan(result->error_message().size(), 0u);
  XCTAssertEqual(result->result_case(), ::pbv1::CommandResult::RESULT_NOT_SET);
}

- (void)testExecuteQueuedCommandRejectedWhenNotAllowed {
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(@[ @"ping" ]);

  ::pbv1::QueuedCommand command;
  command.set_command_id(7);
  command.mutable_kill()->set_team_id("EQHXZ8M8AV");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 7);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_REJECTED);
  XCTAssertGreaterThan(result->error_message().size(), 0u);
  XCTAssertEqual(result->result_case(), ::pbv1::CommandResult::RESULT_NOT_SET);
}

- (void)testExecuteQueuedCommandPackageInventoryRejectedWhenNotAllowed {
  // package_inventory is a recognized queued command, gated by the allowlist.
  // When disallowed it is rejected before any XPC to santad.
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(@[ @"ping" ]);

  ::pbv1::QueuedCommand command;
  command.set_command_id(23);
  command.mutable_package_inventory()->mutable_scan()->set_profile(
      ::santa::common::v1::PackageInventoryScan::PROFILE_BASELINE);

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 23);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_REJECTED);
  XCTAssertGreaterThan(result->error_message().size(), 0u);
  XCTAssertEqual(result->result_case(), ::pbv1::CommandResult::RESULT_NOT_SET);
}

- (void)testHandlePackageInventoryWithoutDaemonConnectionFails {
  ::pbv1::PackageInventoryRequest request;
  std::string errorMessage;

  auto* response = [self.handler handlePackageInventoryRequest:request
                                                       onArena:self.arena
                                                  errorMessage:&errorMessage];

  XCTAssertEqual(response->error(), ::pbv1::PackageInventoryResponse::ERROR_INTERNAL);
  XCTAssertEqual(errorMessage, "no daemon connection");
}

- (void)testExecuteQueuedCommandKillWithoutProcessCompletes {
  // A kill request with no process target executes and reports a typed error
  // in the payload; the command itself still completes.
  ::pbv1::QueuedCommand command;
  command.set_command_id(9);
  command.mutable_kill();

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 9);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertTrue(result->has_kill());
  XCTAssertEqual(result->kill().error(), ::pbv1::KillResponse::ERROR_UNKNOWN_PROCESS_TYPE);
}

- (void)testExecuteQueuedCommandEventUploadSuccess {
  ::pbv1::QueuedCommand command;
  command.set_command_id(11);
  command.mutable_event_upload()->add_paths("/Applications/Safari.app");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 11);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertTrue(result->has_event_upload());
  XCTAssertFalse(result->event_upload().has_error());
  XCTAssertEqual(result->error_message().size(), 0u);
  XCTAssertEqual(self.fakeSyncDelegate.eventUploadCallCount, 1u);
  XCTAssertEqualObjects(self.fakeSyncDelegate.lastEventUploadPaths,
                        @[ @"/Applications/Safari.app" ]);
}

- (void)testExecuteQueuedCommandEventUploadFailure {
  NSError* uploadError =
      [NSError errorWithDomain:@"com.northpolesec.santa.syncservice"
                          code:4
                      userInfo:@{NSLocalizedDescriptionKey : @"Failed to upload events"}];
  self.fakeSyncDelegate.eventUploadReplyErrors = @[ uploadError ];

  ::pbv1::QueuedCommand command;
  command.set_command_id(13);
  command.mutable_event_upload()->add_paths("/Applications/Safari.app");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertTrue(result->has_event_upload());
  XCTAssertEqual(result->event_upload().error(), ::pbv1::EventUploadResponse::ERROR_INTERNAL);
  XCTAssertEqual(result->error_message(), "Failed to upload events");
}

- (void)testExecuteQueuedCommandEventUploadFirstErrorWins {
  NSError* firstError = [NSError errorWithDomain:@"com.northpolesec.santa.syncservice"
                                            code:2
                                        userInfo:@{NSLocalizedDescriptionKey : @"first error"}];
  NSError* secondError = [NSError errorWithDomain:@"com.northpolesec.santa.syncservice"
                                             code:3
                                         userInfo:@{NSLocalizedDescriptionKey : @"second error"}];
  self.fakeSyncDelegate.eventUploadReplyErrors = @[ [NSNull null], firstError, secondError ];

  ::pbv1::QueuedCommand command;
  command.set_command_id(17);
  command.mutable_event_upload()->add_paths("/Applications/Safari.app");
  command.mutable_event_upload()->add_paths("/Applications/Mail.app");
  command.mutable_event_upload()->add_paths("/Applications/Notes.app");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertEqual(result->event_upload().error(), ::pbv1::EventUploadResponse::ERROR_INTERNAL);
  XCTAssertEqual(result->error_message(), "first error");
  XCTAssertEqual(self.fakeSyncDelegate.eventUploadCallCount, 1u);
}

- (void)testExecuteQueuedCommandEventUploadNoValidPaths {
  ::pbv1::QueuedCommand command;
  command.set_command_id(19);
  command.mutable_event_upload()->add_paths("");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertTrue(result->has_event_upload());
  XCTAssertEqual(result->event_upload().error(), ::pbv1::EventUploadResponse::ERROR_INVALID_PATH);
  XCTAssertEqual(self.fakeSyncDelegate.eventUploadCallCount, 0u,
                 @"Delegate should not be invoked when validation fails");
}

- (void)testExecuteQueuedCommandBinaryUploadForwardsRequestAndReportsResponse {
  [self
      stubDaemonBinaryUploadReplyData:[self
                                          serializedBinaryUploadResponseWithDisposition:
                                              pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED
                                                                         sha256Computed:"abc123"]];

  ::pbv1::QueuedCommand command;
  command.set_command_id(21);
  auto* upload = command.mutable_binary_upload();
  upload->set_path("/bin/ls");
  (*upload->mutable_signed_post()->mutable_form_values())["key"] = "objects/abc";

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 21);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertTrue(result->has_binary_upload());
  XCTAssertEqual(result->binary_upload().disposition(),
                 ::pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED);
  XCTAssertEqual(result->binary_upload().sha256_computed(), "abc123");

  // santad received the request as sent, presigned POST included.
  XCTAssertEqual(self.binaryUploadCallCount, 1u);
  ::pbv1::BinaryUploadRequest forwarded;
  XCTAssertTrue(forwarded.ParseFromArray(self.lastBinaryUploadRequestData.bytes,
                                         (int)self.lastBinaryUploadRequestData.length));
  XCTAssertEqual(forwarded.path(), "/bin/ls");
  XCTAssertEqual(forwarded.signed_post().form_values().at("key"), "objects/abc");
}

- (void)testExecuteQueuedCommandBinaryUploadUnparseableReply {
  [self stubDaemonBinaryUploadReplyData:nil];

  ::pbv1::QueuedCommand command;
  command.set_command_id(23);
  command.mutable_binary_upload()->set_path("/bin/ls");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertEqual(result->binary_upload().disposition(),
                 ::pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
  XCTAssertGreaterThan(result->binary_upload().message().size(), 0u);
}

- (void)testExecuteQueuedCommandBinaryUploadNoDaemonConnection {
  // The fake sync delegate has no daemon connection, so the request can't be
  // handed off; the command still completes, reporting the failure.
  ::pbv1::QueuedCommand command;
  command.set_command_id(29);
  command.mutable_binary_upload()->set_path("/bin/ls");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_COMPLETE);
  XCTAssertEqual(result->binary_upload().disposition(),
                 ::pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
  XCTAssertGreaterThan(result->binary_upload().message().size(), 0u);
}

- (void)testExecuteQueuedCommandBinaryUploadRejectedWhenNotAllowed {
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(@[ @"kill" ]);
  [self
      stubDaemonBinaryUploadReplyData:[self
                                          serializedBinaryUploadResponseWithDisposition:
                                              pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED
                                                                         sha256Computed:"abc123"]];

  ::pbv1::QueuedCommand command;
  command.set_command_id(31);
  command.mutable_binary_upload()->set_path("/bin/ls");

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_REJECTED);
  XCTAssertEqual(result->result_case(), ::pbv1::CommandResult::RESULT_NOT_SET);
  XCTAssertEqual(self.binaryUploadCallCount, 0u, @"Rejected commands should not reach santad");
}

- (void)testExecuteQueuedCommandUnsetFails {
  ::pbv1::QueuedCommand command;
  command.set_command_id(37);

  ::pbv1::CommandResult* result = [self.handler executeQueuedCommand:command onArena:self.arena];

  XCTAssertEqual(result->command_id(), 37);
  XCTAssertEqual(result->host_status(), ::pbv1::CommandResult::HOST_STATUS_FAILED);
  XCTAssertGreaterThan(result->error_message().size(), 0u);
  XCTAssertEqual(result->result_case(), ::pbv1::CommandResult::RESULT_NOT_SET);
}

#pragma mark - shouldPostDeliveredAckForCommand

- (void)testShouldPostDeliveredAckOnlyForLongRunningCommands {
  ::pbv1::QueuedCommand eventUpload;
  eventUpload.mutable_event_upload()->add_paths("/Applications/Safari.app");
  XCTAssertTrue([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:eventUpload]);

  ::pbv1::QueuedCommand binaryUpload;
  binaryUpload.mutable_binary_upload()->set_path("/bin/ls");
  XCTAssertTrue([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:binaryUpload]);

  ::pbv1::QueuedCommand kill;
  kill.mutable_kill()->set_team_id("EQHXZ8M8AV");
  XCTAssertFalse([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:kill],
                 @"Kill is fast enough to post straight to COMPLETE");

  ::pbv1::QueuedCommand packageInventory;
  packageInventory.mutable_package_inventory();
  XCTAssertTrue([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:packageInventory]);

  ::pbv1::QueuedCommand unset;
  XCTAssertFalse([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:unset]);
}

- (void)testShouldNotPostDeliveredAckForDisallowedCommand {
  OCMStub([self.mockConfigurator allowedSantaCommands]).andReturn(@[ @"event_upload" ]);

  ::pbv1::QueuedCommand eventUpload;
  eventUpload.mutable_event_upload()->add_paths("/Applications/Safari.app");
  XCTAssertTrue([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:eventUpload]);

  ::pbv1::QueuedCommand binaryUpload;
  binaryUpload.mutable_binary_upload()->set_path("/bin/ls");
  XCTAssertFalse([SNTSantaCommandHandler shouldPostDeliveredAckForCommand:binaryUpload],
                 @"DELIVERED means 'will execute it'");
}

#pragma mark - handleEventUploadRequest completion

- (void)testHandleEventUploadCompletionInvokedOnceAfterAllPaths {
  ::pbv1::EventUploadRequest request;
  request.add_paths("/Applications/Safari.app");
  request.add_paths("/Applications/Mail.app");

  __block NSUInteger completionCount = 0;
  __block NSError* completionError = nil;
  ::pbv1::EventUploadResponse* response = [self.handler handleEventUploadRequest:request
                                                                         onArena:self.arena
                                                                      completion:^(NSError* error) {
                                                                        completionCount++;
                                                                        completionError = error;
                                                                      }];

  XCTAssertFalse(response->has_error());
  XCTAssertEqual(completionCount, 1u, @"Completion should fire exactly once");
  XCTAssertNil(completionError);
}

- (void)testHandleEventUploadValidationFailureDoesNotInvokeCompletion {
  ::pbv1::EventUploadRequest request;

  __block BOOL completionInvoked = NO;
  ::pbv1::EventUploadResponse* response = [self.handler handleEventUploadRequest:request
                                                                         onArena:self.arena
                                                                      completion:^(NSError* error) {
                                                                        completionInvoked = YES;
                                                                      }];

  XCTAssertEqual(response->error(), ::pbv1::EventUploadResponse::ERROR_INVALID_PATH);
  XCTAssertFalse(completionInvoked);
}

- (void)testHandleEventUploadNoDelegate {
  SNTSantaCommandHandler* handler = [[SNTSantaCommandHandler alloc] initWithSyncDelegate:nil];

  ::pbv1::EventUploadRequest request;
  request.add_paths("/Applications/Safari.app");

  __block BOOL completionInvoked = NO;
  ::pbv1::EventUploadResponse* response = [handler handleEventUploadRequest:request
                                                                    onArena:self.arena
                                                                 completion:^(NSError* error) {
                                                                   completionInvoked = YES;
                                                                 }];

  XCTAssertEqual(response->error(), ::pbv1::EventUploadResponse::ERROR_INTERNAL);
  XCTAssertFalse(completionInvoked);
}

@end
