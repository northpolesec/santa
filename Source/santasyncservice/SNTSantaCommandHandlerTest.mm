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

#import "Source/common/SNTConfigurator.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+EventUpload.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+Kill.h"
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
- (MOLXPCConnection*)daemonConnection {
  return nil;
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
@property SNTFakeCommandSyncDelegate* fakeSyncDelegate;
@property SNTSantaCommandHandler* handler;
@property google::protobuf::Arena* arena;
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
  delete self.arena;
  self.arena = nullptr;
  [super tearDown];
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
