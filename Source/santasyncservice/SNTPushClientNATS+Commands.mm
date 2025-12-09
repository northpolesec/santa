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

#import "Source/santasyncservice/SNTPushClientNATS.h"

#include <google/protobuf/descriptor.h>

#import "Source/common/SNTLogging.h"
#include "absl/cleanup/cleanup.h"
#include "commands/v1.pb.h"

__BEGIN_DECLS

// Include NATS C client header
#import "src/nats.h"

__END_DECLS

// Forward declaration - implementation is in SNTPushClientNATS.mm
NSString *ResponseCodeToString(santa::commands::v1::SantaCommandResponseCode code);

// Helper function to convert command type to readable string
// Note: CommandCase is not a protobuf enum, so we use a switch for readability
static NSString *CommandTypeToString(
    santa::commands::v1::SantaCommandRequest::CommandCase commandCase) {
  switch (commandCase) {
    case santa::commands::v1::SantaCommandRequest::kPing: return @"Ping";
    case santa::commands::v1::SantaCommandRequest::COMMAND_NOT_SET: return @"NOT_SET";
    default: return [NSString stringWithFormat:@"UNKNOWN(%d)", static_cast<int>(commandCase)];
  }
}

// Forward declaration of private interface to access private properties
@interface SNTPushClientNATS ()
@property(atomic) BOOL isShuttingDown;
@property(nonatomic) dispatch_queue_t messageQueue;
@property(nonatomic) dispatch_queue_t connectionQueue;
@property(nonatomic) natsConnection *conn;
- (BOOL)isConnectionAlive;
- (void)publishResponse:(const santa::commands::v1::SantaCommandResponse &)response
           toReplyTopic:(NSString *)replyTopic;
@end

// Category for command handling methods
@interface SNTPushClientNATS (Commands)
- (santa::commands::v1::SantaCommandResponse)handlePingCommand:
    (const santa::commands::v1::PingRequest &)pingRequest;
- (santa::commands::v1::SantaCommandResponse)dispatchSantaCommandToHandler:
    (const santa::commands::v1::SantaCommandRequest &)command;
@end

@implementation SNTPushClientNATS (Commands)

// Handle PingRequest command
// Always returns a successful response. Failures are handled by the caller.
- (santa::commands::v1::SantaCommandResponse)handlePingCommand:
    (const santa::commands::v1::PingRequest &)pingRequest {
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL);
  response.mutable_ping();

  // Verify the code was set correctly
  santa::commands::v1::SantaCommandResponseCode code = response.code();
  LOGD(@"NATS: Ping response code set to: %d (%@)", static_cast<int>(code),
       ResponseCodeToString(code));

  return response;
}

// Handle KillRequest command
- (santa::commands::v1::SantaCommandResponse)handleKillCommand:
    (const santa::commands::v1::KillRequest &)killRequest {
  // TODO: This is just a placeholder for now.
  santa::commands::v1::SantaCommandResponse response;
  response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_SUCCESSFUL);
  (void)response.mutable_kill();

  // Verify the code was set correctly
  LOGD(@"NATS: Kill response code set to: %d (%@)", static_cast<int>(response.code()),
       ResponseCodeToString(response.code()));

  return response;
}

// Dispatch Santa command to appropriate handler based on command type
- (santa::commands::v1::SantaCommandResponse)dispatchSantaCommandToHandler:
    (const santa::commands::v1::SantaCommandRequest &)command {
  santa::commands::v1::SantaCommandResponse response;

  santa::commands::v1::SantaCommandRequest::CommandCase commandCase = command.command_case();
  switch (commandCase) {
    case santa::commands::v1::SantaCommandRequest::kPing:
      LOGI(@"NATS: Dispatching PingRequest command");
      response = [self handlePingCommand:command.ping()];
      break;

    case santa::commands::v1::SantaCommandRequest::kKill:
      LOGI(@"NATS: Dispatching KillRequest command");
      response = [self handleKillCommand:command.kill()];
      break;

    case santa::commands::v1::SantaCommandRequest::COMMAND_NOT_SET:
    default:
      LOGE(@"NATS: Unknown or unset command type: %@ (%d)", CommandTypeToString(commandCase),
           static_cast<int>(commandCase));
      response.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR);
      break;
  }

  return response;
}

@end

// NATS command message handler - handles serialization/deserialization and
// dispatches to handlers
static void CommandMessageHandlerImpl(natsConnection *nc, natsSubscription *sub, natsMsg *msg,
                                      SNTPushClientNATS *self) {
  absl::Cleanup glob_cleaup = ^{
    // Destroy the message on return.
    if (msg) {
      natsMsg_Destroy(msg);
    }
  };

  if (!self || !msg) {
    return;
  }

  if (self.isShuttingDown) {
    return;
  }

  NSString *msgSubject = @(natsMsg_GetSubject(msg) ?: "<unknown>");
  NSString *replyTopic = natsMsg_GetReply(msg) ? @(natsMsg_GetReply(msg)) : nil;

  LOGD(@"NATS: Received command message on subject '%@' with reply '%@'", msgSubject,
       replyTopic ?: @"<no reply>");

  if (!replyTopic) {
    LOGW(@"NATS: Command message on %@ has no reply topic, ignoring", msgSubject);
    return;
  }

  if (natsMsg_GetDataLength(msg) <= 0) {
    LOGE(@"NATS: Command message on %@ has no data", msgSubject);
    // Try to send error response, but don't fail if that also fails
    santa::commands::v1::SantaCommandResponse errorResponse;
    errorResponse.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR);
    [self publishResponse:errorResponse toReplyTopic:replyTopic];
    return;
  }

  // Deserialize the message to SantaCommandRequest
  // Note: We must extract all data from msg before destroying it, as NATS owns the message
  // and will free it after this callback returns
  santa::commands::v1::SantaCommandRequest command;
  if (!command.ParseFromArray(natsMsg_GetData(msg), natsMsg_GetDataLength(msg))) {
    LOGE(@"NATS: Failed to parse SantaCommandRequest from message on %@", msgSubject);
    // Try to send error response, but don't fail if that also fails
    santa::commands::v1::SantaCommandResponse errorResponse;
    errorResponse.set_code(santa::commands::v1::SANTA_COMMAND_RESPONSE_CODE_ERROR);
    [self publishResponse:errorResponse toReplyTopic:replyTopic];
    return;
  }

  // Process on message queue to serialize handling of messages
  // Failures are logged but don't crash the client
  dispatch_async(self.messageQueue, ^{
    if (self.isShuttingDown) {
      return;
    }

    santa::commands::v1::SantaCommandResponse response =
        [self dispatchSantaCommandToHandler:command];

    // Publish the response
    [self publishResponse:response toReplyTopic:replyTopic];
  });
}

__BEGIN_DECLS

// NATS-compatible wrapper that converts void *closure to SNTPushClientNATS *
void commandMessageHandler(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure) {
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  CommandMessageHandlerImpl(nc, sub, msg, self);
}

__END_DECLS
