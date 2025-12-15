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
#include "Source/common/String.h"
#include "absl/cleanup/cleanup.h"
#include "commands/v1.pb.h"

__BEGIN_DECLS

// Include NATS C client header
#import "src/nats.h"

__END_DECLS

namespace pbv1 = ::santa::commands::v1;
using santa::StringToNSString;

// Forward declaration of private interface to access private properties
@interface SNTPushClientNATS ()
@property(atomic) BOOL isShuttingDown;
@property(nonatomic) dispatch_queue_t messageQueue;
@property(nonatomic) dispatch_queue_t connectionQueue;
@property(nonatomic) natsConnection *conn;
- (BOOL)isConnectionAlive;
- (void)publishResponse:(const ::pbv1::SantaCommandResponse &)response
           toReplyTopic:(NSString *)replyTopic;
@end

// Category for command handling methods
@interface SNTPushClientNATS (Commands)
- (::pbv1::PingResponse *)handlePingRequest:(const ::pbv1::PingRequest &)pingRequest
                            withCommandUUID:(NSString *)uuid
                                    onArena:(google::protobuf::Arena *)arena;
- (::pbv1::KillResponse *)handleKillRequest:(const ::pbv1::KillRequest &)killRequest
                            withCommandUUID:(NSString *)uuid
                                    onArena:(google::protobuf::Arena *)arena;
- (::pbv1::SantaCommandResponse *)dispatchSantaCommandToHandler:
                                      (const ::pbv1::SantaCommandRequest &)command
                                                        onArena:(google::protobuf::Arena *)arena;
@end

@implementation SNTPushClientNATS (Commands)

// Handle PingRequest command
// Always returns a successful response. Failures are handled by the caller.
- (::pbv1::PingResponse *)handlePingRequest:(const ::pbv1::PingRequest &)pingRequest
                            withCommandUUID:(NSString *)uuid
                                    onArena:(google::protobuf::Arena *)arena {
  return google::protobuf::Arena::Create<::pbv1::PingResponse>(arena);
}

// Handle KillRequest command
- (::pbv1::KillResponse *)handleKillRequest:(const ::pbv1::KillRequest &)pbRequest
                            withCommandUUID:(NSString *)uuid
                                    onArena:(google::protobuf::Arena *)arena {
  // TODO: This is just a placeholder for now.
  return google::protobuf::Arena::Create<::pbv1::KillResponse>(arena);
}

// Dispatch Santa command to appropriate handler based on command type
- (::pbv1::SantaCommandResponse *)dispatchSantaCommandToHandler:
                                      (const ::pbv1::SantaCommandRequest &)command
                                                        onArena:(google::protobuf::Arena *)arena {
  auto response = google::protobuf::Arena::Create<::pbv1::SantaCommandResponse>(arena);

  NSString *uuid = StringToNSString(command.uuid());
  if (![[NSUUID alloc] initWithUUIDString:uuid]) {
    LOGE(@"NATS: Invalid command uuid: \"%@\"", uuid);
    response->set_error(::pbv1::SantaCommandResponse::ERROR_INVALID_UUID);
    return response;
  }

  ::pbv1::SantaCommandRequest::CommandCase commandCase = command.command_case();
  switch (commandCase) {
    case ::pbv1::SantaCommandRequest::kPing: {
      LOGI(@"NATS: Dispatching PingRequest command");
      auto *pingResponse = [self handlePingRequest:command.ping()
                                   withCommandUUID:uuid
                                           onArena:arena];
      response->set_allocated_ping(pingResponse);
      break;
    }

    case ::pbv1::SantaCommandRequest::kKill: {
      LOGI(@"NATS: Dispatching KillRequest command");
      auto *killResponse = [self handleKillRequest:command.kill()
                                   withCommandUUID:uuid
                                           onArena:arena];
      response->set_allocated_kill(killResponse);
      break;
    }

    case ::pbv1::SantaCommandRequest::COMMAND_NOT_SET:
    default:
      LOGE(@"NATS: Unknown or unset command type: %d", static_cast<int>(commandCase));
      response->set_error(::pbv1::SantaCommandResponse::ERROR_UNKNOWN_REQUEST_TYPE);
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
    ::pbv1::SantaCommandResponse errorResponse;
    errorResponse.set_error(::pbv1::SantaCommandResponse::ERROR_INVALID_DATA);
    [self publishResponse:errorResponse toReplyTopic:replyTopic];
    return;
  }

  // Deserialize the message to SantaCommandRequest
  // Note: We must extract all data from msg before destroying it, as NATS owns the message
  // and will free it after this callback returns
  ::pbv1::SantaCommandRequest command;
  if (!command.ParseFromArray(natsMsg_GetData(msg), natsMsg_GetDataLength(msg))) {
    LOGE(@"NATS: Failed to parse SantaCommandRequest from message on %@", msgSubject);
    // Try to send error response, but don't fail if that also fails
    ::pbv1::SantaCommandResponse errorResponse;
    errorResponse.set_error(::pbv1::SantaCommandResponse::ERROR_DESERIALIZATION);
    [self publishResponse:errorResponse toReplyTopic:replyTopic];
    return;
  }

  // Process on message queue to serialize handling of messages
  // Failures are logged but don't crash the client
  dispatch_async(self.messageQueue, ^{
    if (self.isShuttingDown) {
      return;
    }

    google::protobuf::Arena arena;
    ::pbv1::SantaCommandResponse *response = [self dispatchSantaCommandToHandler:command
                                                                         onArena:&arena];

    // Publish the response
    [self publishResponse:*response toReplyTopic:replyTopic];
  });
}

__BEGIN_DECLS

// NATS-compatible wrapper that converts void *closure to SNTPushClientNATS *
void commandMessageHandler(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure) {
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  CommandMessageHandlerImpl(nc, sub, msg, self);
}

__END_DECLS
