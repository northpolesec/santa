/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/santasyncservice/SNTPushClientNATS.h"

#include <CommonCrypto/CommonHMAC.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#include "Source/common/String.h"
#import "Source/santasyncservice/SNTBinaryUploader.h"
#include "absl/cleanup/cleanup.h"
#include "commands/v1.pb.h"

__BEGIN_DECLS

// Include NATS C client header
#import "src/nats.h"

__END_DECLS

namespace pbv1 = ::santa::commands::v1;
using santa::StringToNSString;

// Semi-arbitrary number of seconds to wait for santad to finish killing processes
static constexpr int64_t kKillResponseTimeoutSeconds = 90;

// Maximum age in seconds for command timestamps (5 minutes)
static constexpr int64_t kMaxCommandAgeSeconds = 300;

// Maximum size of the nonce cache
// Semi-arbitrary cap, averaging 1 command per second per time window
static constexpr NSUInteger kMaxCommandNonceCacheCount = kMaxCommandAgeSeconds;

namespace {

bool VerifyCommandRequestHMAC(const ::pbv1::SantaCommandRequest& command, NSData* hmacKey) {
  if (hmacKey.length == 0) {
    LOGE(@"NATS: HMAC verification failed - no key available");
    return false;
  }

  if (command.hmac().length() != CC_SHA256_DIGEST_LENGTH) {
    LOGE(@"NATS: HMAC verification failed - invalid HMAC length (%zu)", command.hmac().length());
    return false;
  }

  // Create a copy of the command and clear the HMAC field for verification
  ::pbv1::SantaCommandRequest commandCopy = command;
  commandCopy.clear_hmac();

  // Serialize deterministically so map fields (e.g.
  // BinaryUploadRequest.signed_post.form_values) emit a stable byte order
  // matching what the signer used. Non-deterministic serialization makes
  // the HMAC depend on map iteration order, which differs across language
  // runtimes — santa's C++ output would not match workshop's Go output.
  std::string serialized;
  {
    google::protobuf::io::StringOutputStream stringStream(&serialized);
    google::protobuf::io::CodedOutputStream codedStream(&stringStream);
    codedStream.SetSerializationDeterministic(true);
    if (!commandCopy.SerializeToCodedStream(&codedStream)) {
      LOGE(@"NATS: HMAC verification failed - could not serialize command");
      return false;
    }
  }

  unsigned char computedHMAC[CC_SHA256_DIGEST_LENGTH];
  CCHmac(kCCHmacAlgSHA256, hmacKey.bytes, hmacKey.length, serialized.data(), serialized.size(),
         computedHMAC);

  // Constant-time comparison
  if (timingsafe_bcmp(computedHMAC, command.hmac().data(), CC_SHA256_DIGEST_LENGTH) != 0) {
    LOGE(@"NATS: HMAC verification failed - signature mismatch");
    // Diagnostic: hex-dump the inputs so we can compare against the
    // workshop-side equivalents. Remove after the workshop/santa HMAC
    // pipeline is verified end-to-end for binary_upload.
    auto hexify = ^NSString*(const void* data, size_t len) {
      NSMutableString* s = [NSMutableString stringWithCapacity:len * 2];
      const unsigned char* p = (const unsigned char*)data;
      for (size_t i = 0; i < len; i++) [s appendFormat:@"%02x", p[i]];
      return s;
    };
    LOGE(@"NATS: HMAC diag: command_case=%d uuid=%s issued_at=%lld",
         static_cast<int>(command.command_case()), command.uuid().c_str(),
         (long long)command.issued_at());
    LOGE(@"NATS: HMAC diag: signed_bytes (%zu bytes) = %@", serialized.size(),
         hexify(serialized.data(), serialized.size()));
    LOGE(@"NATS: HMAC diag: received_hmac = %@",
         hexify(command.hmac().data(), command.hmac().length()));
    LOGE(@"NATS: HMAC diag: computed_hmac = %@", hexify(computedHMAC, CC_SHA256_DIGEST_LENGTH));
    LOGE(@"NATS: HMAC diag: hmac_key first4=%@ last4=%@ key_len=%lu",
         hmacKey.length >= 4 ? hexify(hmacKey.bytes, 4) : @"?",
         hmacKey.length >= 4 ? hexify((const unsigned char*)hmacKey.bytes + hmacKey.length - 4, 4)
                             : @"?",
         (unsigned long)hmacKey.length);
    return false;
  }

  LOGD(@"NATS: HMAC verification succeeded");
  return true;
}

bool VerifyCommandRequestTimestamp(const ::pbv1::SantaCommandRequest& command) {
  int64_t now = static_cast<int64_t>(time(nullptr));
  int64_t issued_at = command.issued_at();
  int64_t age = now - issued_at;

  // Check if command is too old or from too far in the future. Some skew is permitted.
  if (age > kMaxCommandAgeSeconds || age < -kMaxCommandAgeSeconds) {
    LOGE(@"NATS: Timestamp verification failed (age: %lld seconds)", age);
    return false;
  }

  LOGD(@"NATS: Timestamp verification succeeded (age: %lld seconds)", age);
  return true;
}

void SetKillResponseError(SNTKillResponseError error, ::pbv1::KillResponse* pbResponse) {
  switch (error) {
    case SNTKillResponseErrorListPids:
      pbResponse->set_error(::pbv1::KillResponse::ERROR_LIST_PIDS);
      break;
    case SNTKillResponseErrorInvalidRequest:
      pbResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL);
      break;
    case SNTKillResponseErrorNone:
      // Do not set the error if there was none
      break;
    default: pbResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL); break;
  }
}

void SetKilledProcessError(SNTKilledProcessError error, ::pbv1::KillResponse::Process* pbProcess) {
  switch (error) {
    case SNTKilledProcessErrorUnknown:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INTERNAL);
      break;
    case SNTKilledProcessErrorInvalidTarget:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INVALID_TARGET);
      break;
    case SNTKilledProcessErrorNotPermitted:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_OPERATION_NOT_PERMITTED);
      break;
    case SNTKilledProcessErrorNoSuchProcess:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_NO_SUCH_PROCESS);
      break;
    case SNTKilledProcessErrorInvalidArgument:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INVALID_ARGUMENT);
      break;
    case SNTKilledProcessErrorBootSessionMismatch:
      pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_BOOT_SESSION_MISMATCH);
      break;
    case SNTKilledProcessErrorNone:
      // Do not set the error if there was none
      break;
    default: pbProcess->set_error(::pbv1::KillResponse::KILL_ERROR_INTERNAL); break;
  }
}

}  // namespace

// Forward declaration of private interface to access private properties
@interface SNTPushClientNATS ()
@property(atomic) BOOL isShuttingDown;
@property(nonatomic) dispatch_queue_t messageQueue;
@property(nonatomic) dispatch_queue_t connectionQueue;
@property(nonatomic) natsConnection* conn;
@property(weak) id<SNTPushNotificationsSyncDelegate> syncDelegate;
@property(nonatomic, copy) NSData* hmacKey;
@property(nonatomic) NSMutableSet<NSString*>* currentNonces;
@property(nonatomic) NSMutableSet<NSString*>* previousNonces;
@property(nonatomic) int64_t lastRotationTime;
@property(nonatomic) SNTBinaryUploader* binaryUploader;

- (BOOL)isConnectionAlive;
- (void)publishResponse:(const ::pbv1::SantaCommandResponse&)response
           toReplyTopic:(NSString*)replyTopic;
@end

// Category for command handling methods
@interface SNTPushClientNATS (Commands)
- (::pbv1::PingResponse*)handlePingRequest:(const ::pbv1::PingRequest&)pingRequest
                           withCommandUUID:(NSString*)uuid
                                   onArena:(google::protobuf::Arena*)arena;
- (::pbv1::KillResponse*)handleKillRequest:(const ::pbv1::KillRequest&)killRequest
                           withCommandUUID:(NSString*)uuid
                                   onArena:(google::protobuf::Arena*)arena;
- (::pbv1::EventUploadResponse*)handleEventUploadRequest:
                                    (const ::pbv1::EventUploadRequest&)eventUploadRequest
                                         withCommandUUID:(NSString*)uuid
                                                 onArena:(google::protobuf::Arena*)arena;
- (::pbv1::BinaryUploadResponse*)handleBinaryUploadRequest:
                                     (const ::pbv1::BinaryUploadRequest&)binaryUploadRequest
                                                replyTopic:(NSString*)replyTopic
                                                   onArena:(google::protobuf::Arena*)arena;
- (::pbv1::SantaCommandResponse*)dispatchSantaCommandToHandler:
                                     (const ::pbv1::SantaCommandRequest&)command
                                                       onArena:(google::protobuf::Arena*)arena;
- (::pbv1::SantaCommandResponse*)dispatchSantaCommandToHandler:
                                     (const ::pbv1::SantaCommandRequest&)command
                                                       onArena:(google::protobuf::Arena*)arena
                                                    replyTopic:(NSString*)replyTopic;
- (BOOL)checkAndRecordNonce:(NSString*)uuid;
@end

@implementation SNTPushClientNATS (Commands)

// Check and record a nonce (UUID) for replay protection
// Returns YES if the nonce is new, NO if it's a replay
// Note: Must be called from messageQueue for thread safety
- (BOOL)checkAndRecordNonce:(NSString*)uuid {
  // Rotate cache if needed (lazy rotation)
  // Lazy rotation is fine for now because command volume will be very low.
  int64_t now = time(nullptr);
  if (now - self.lastRotationTime >= kMaxCommandAgeSeconds) {
    LOGD(@"NATS: Rotating nonce cache (current: %lu, previous: %lu)",
         (unsigned long)self.currentNonces.count, (unsigned long)self.previousNonces.count);
    self.previousNonces = self.currentNonces;
    self.currentNonces = [NSMutableSet set];
    self.lastRotationTime = now;
  }

  // Throttle number of allowed commands per time window
  if (self.currentNonces.count >= kMaxCommandNonceCacheCount) {
    return NO;
  }

  // Check for replay
  if ([self.currentNonces containsObject:uuid] || [self.previousNonces containsObject:uuid]) {
    return NO;
  }

  [self.currentNonces addObject:uuid];
  return YES;
}

// Handle PingRequest command
// Always returns a successful response. Failures are handled by the caller.
- (::pbv1::PingResponse*)handlePingRequest:(const ::pbv1::PingRequest&)pingRequest
                           withCommandUUID:(NSString*)uuid
                                   onArena:(google::protobuf::Arena*)arena {
  return google::protobuf::Arena::Create<::pbv1::PingResponse>(arena);
}

// Handle KillRequest command
- (::pbv1::KillResponse*)handleKillRequest:(const ::pbv1::KillRequest&)pbKillReq
                           withCommandUUID:(NSString*)uuid
                                   onArena:(google::protobuf::Arena*)arena {
  auto pbKillResponse = google::protobuf::Arena::Create<::pbv1::KillResponse>(arena);
  SNTKillRequest* req;
  switch (pbKillReq.process_case()) {
    case ::pbv1::KillRequest::kRunningProcess:
      req = [[SNTKillRequestRunningProcess alloc]
             initWithUUID:uuid
                      pid:pbKillReq.running_process().pid()
               pidversion:pbKillReq.running_process().pidversion()
          bootSessionUUID:StringToNSString(pbKillReq.running_process().boot_session_uuid())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_RUNNING_PROCESS);
      }
      break;
    case ::pbv1::KillRequest::kCdhash:
      req = [[SNTKillRequestCDHash alloc] initWithUUID:uuid
                                                cdHash:StringToNSString(pbKillReq.cdhash())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_CDHASH);
      }
      break;
    case ::pbv1::KillRequest::kSigningId:
      req = [[SNTKillRequestSigningID alloc] initWithUUID:uuid
                                                signingID:StringToNSString(pbKillReq.signing_id())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_SIGNING_ID);
      }
      break;
    case ::pbv1::KillRequest::kTeamId:
      req = [[SNTKillRequestTeamID alloc] initWithUUID:uuid
                                                teamID:StringToNSString(pbKillReq.team_id())];
      if (!req) {
        pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INVALID_TEAM_ID);
      }
      break;
    default: pbKillResponse->set_error(::pbv1::KillResponse::ERROR_UNKNOWN_PROCESS_TYPE);
  }

  if (!req) {
    return pbKillResponse;
  }

  id<SNTPushNotificationsSyncDelegate> strongSyncDelegate = self.syncDelegate;
  if (!strongSyncDelegate) {
    pbKillResponse->set_error(::pbv1::KillResponse::ERROR_INTERNAL);
    return pbKillResponse;
  }

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block SNTKillResponse* resp;
  [[[strongSyncDelegate daemonConnection] remoteObjectProxy]
      killProcesses:req
              reply:^(SNTKillResponse* killResponse) {
                resp = killResponse;
                dispatch_semaphore_signal(sema);
              }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, kKillResponseTimeoutSeconds *
                                                                         NSEC_PER_SEC)) != 0) {
    pbKillResponse->set_error(::santa::commands::v1::KillResponse::ERROR_TIMEOUT);
    return pbKillResponse;
  }

  SetKillResponseError(resp.error, pbKillResponse);

  for (SNTKilledProcess* killedProc in resp.killedProcesses) {
    auto pbProc = google::protobuf::Arena::Create<::pbv1::KillResponse::Process>(arena);

    pbProc->set_pid(killedProc.pid);
    pbProc->set_pidversion(killedProc.pidversion);
    SetKilledProcessError(killedProc.error, pbProc);

    pbKillResponse->mutable_processes()->UnsafeArenaAddAllocated(pbProc);
  }

  return pbKillResponse;
}

// Handle EventUploadRequest command
- (::pbv1::EventUploadResponse*)handleEventUploadRequest:
                                    (const ::pbv1::EventUploadRequest&)eventUploadRequest
                                         withCommandUUID:(NSString*)uuid
                                                 onArena:(google::protobuf::Arena*)arena {
  auto pbResponse = google::protobuf::Arena::Create<::pbv1::EventUploadResponse>(arena);

  NSString* path = StringToNSString(eventUploadRequest.path());
  if (path.length == 0) {
    LOGE(@"NATS: EventUploadRequest has empty path");
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INVALID_PATH);
    return pbResponse;
  }

  id<SNTPushNotificationsSyncDelegate> strongSyncDelegate = self.syncDelegate;
  if (!strongSyncDelegate) {
    LOGE(@"NATS: EventUploadRequest failed - no sync delegate");
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INTERNAL);
    return pbResponse;
  }

  // Fire off the event upload asynchronously - don't wait for completion
  [strongSyncDelegate
      eventUploadForPath:path
                   reply:^(NSError* error) {
                     if (error) {
                       LOGE(@"NATS: EventUploadRequest failed for path %@: %@", path, error);
                     } else {
                       LOGI(@"NATS: EventUploadRequest completed for path %@", path);
                     }
                   }];

  return pbResponse;
}

// Handle BinaryUploadRequest command.
//
// When replyTopic is non-nil the uploader is invoked asynchronously and this
// method returns nullptr so the dispatch caller skips publishing a
// synchronous response — the uploader will publish its own reply from its
// serial queue when the upload settles.
//
// When replyTopic is nil (only happens in test calls that go through the
// 2-arg dispatch shim), this returns a BinaryUploadResponse with
// DISPOSITION_INTERNAL_ERROR so the caller has something to assert on.
- (::pbv1::BinaryUploadResponse*)handleBinaryUploadRequest:
                                     (const ::pbv1::BinaryUploadRequest&)binaryUploadRequest
                                                replyTopic:(NSString*)replyTopic
                                                   onArena:(google::protobuf::Arena*)arena {
  auto* pbResponse = google::protobuf::Arena::Create<::pbv1::BinaryUploadResponse>(arena);

  if (replyTopic.length == 0) {
    pbResponse->set_disposition(::pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    pbResponse->set_message("no reply topic");
    return pbResponse;
  }

  SNTBinaryUploader* uploader = self.binaryUploader;
  if (!uploader) {
    pbResponse->set_disposition(::pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    pbResponse->set_message("uploader not initialized");
    return pbResponse;
  }

  [uploader handleUploadRequest:binaryUploadRequest replyTopic:replyTopic];
  // Returning nullptr signals the caller to skip the central publish — the
  // uploader will publish its own reply asynchronously.
  return nullptr;
}

// 2-arg shim used by tests that don't care about the reply topic. Forwards
// to the 3-arg form with replyTopic:nil so binary_upload synthesizes an
// INTERNAL_ERROR (since it has no way to publish asynchronously without a
// subject).
- (::pbv1::SantaCommandResponse*)dispatchSantaCommandToHandler:
                                     (const ::pbv1::SantaCommandRequest&)command
                                                       onArena:(google::protobuf::Arena*)arena {
  return [self dispatchSantaCommandToHandler:command onArena:arena replyTopic:nil];
}

// Dispatch Santa command to appropriate handler based on command type.
// Returns nullptr for binary_upload when replyTopic is non-nil (the uploader
// publishes its own reply asynchronously). The caller — CommandMessageHandlerImpl
// or the 2-arg shim — must check for nullptr before publishing.
- (::pbv1::SantaCommandResponse*)dispatchSantaCommandToHandler:
                                     (const ::pbv1::SantaCommandRequest&)command
                                                       onArena:(google::protobuf::Arena*)arena
                                                    replyTopic:(NSString*)replyTopic {
  auto response = google::protobuf::Arena::Create<::pbv1::SantaCommandResponse>(arena);

  // Verify HMAC signature first
  if (!VerifyCommandRequestHMAC(command, self.hmacKey)) {
    LOGE(@"NATS: Command rejected - HMAC verification failed");
    response->set_error(::pbv1::SantaCommandResponse::ERROR_INVALID_DATA);
    return response;
  }

  if (!VerifyCommandRequestTimestamp(command)) {
    LOGE(@"NATS: Command rejected - timestamp verification failed");
    response->set_error(::pbv1::SantaCommandResponse::ERROR_INVALID_DATA);
    return response;
  }

  NSString* uuid = StringToNSString(command.uuid());
  if (![[NSUUID alloc] initWithUUIDString:uuid]) {
    LOGE(@"NATS: Invalid command uuid: \"%@\"", uuid);
    response->set_error(::pbv1::SantaCommandResponse::ERROR_INVALID_UUID);
    return response;
  }

  if (![self checkAndRecordNonce:uuid]) {
    LOGE(@"NATS: Command rejected - nonce already used (uuid: %@)", uuid);
    response->set_error(::pbv1::SantaCommandResponse::ERROR_INVALID_DATA);
    return response;
  }

  ::pbv1::SantaCommandRequest::CommandCase commandCase = command.command_case();

  // Check if command type is allowed by client configuration
  // No default case — compiler enforces all proto cases are handled (-Werror + -Wswitch)
  NSString* commandName = nil;
  switch (commandCase) {
    case ::pbv1::SantaCommandRequest::kPing: commandName = @"ping"; break;
    case ::pbv1::SantaCommandRequest::kKill: commandName = @"kill"; break;
    case ::pbv1::SantaCommandRequest::kEventUpload: commandName = @"event_upload"; break;
    case ::pbv1::SantaCommandRequest::kBinaryUpload: commandName = @"binary_upload"; break;
    case ::pbv1::SantaCommandRequest::COMMAND_NOT_SET: break;
  }

  if (commandName) {
    NSArray<NSString*>* allowed = [[SNTConfigurator configurator] allowedSantaCommands];
    if (allowed && ![allowed containsObject:commandName]) {
      LOGW(@"NATS: Command '%@' rejected - not in AllowedSantaCommands", commandName);
      response->set_error(::pbv1::SantaCommandResponse::ERROR_COMMAND_DISABLED);
      return response;
    }
  }

  switch (commandCase) {
    case ::pbv1::SantaCommandRequest::kPing: {
      LOGI(@"NATS: Dispatching PingRequest command");
      auto* pingResponse = [self handlePingRequest:command.ping()
                                   withCommandUUID:uuid
                                           onArena:arena];
      response->unsafe_arena_set_allocated_ping(pingResponse);
      break;
    }

    case ::pbv1::SantaCommandRequest::kKill: {
      LOGI(@"NATS: Dispatching KillRequest command");
      auto* killResponse = [self handleKillRequest:command.kill()
                                   withCommandUUID:uuid
                                           onArena:arena];
      response->unsafe_arena_set_allocated_kill(killResponse);
      break;
    }

    case ::pbv1::SantaCommandRequest::kEventUpload: {
      LOGI(@"NATS: Dispatching EventUploadRequest command");
      auto* eventUploadResponse = [self handleEventUploadRequest:command.event_upload()
                                                 withCommandUUID:uuid
                                                         onArena:arena];
      response->unsafe_arena_set_allocated_event_upload(eventUploadResponse);
      break;
    }

    case ::pbv1::SantaCommandRequest::kBinaryUpload: {
      LOGI(@"NATS: Dispatching BinaryUploadRequest command");
      auto* buResponse = [self handleBinaryUploadRequest:command.binary_upload()
                                              replyTopic:replyTopic
                                                 onArena:arena];
      if (buResponse == nullptr) {
        // Hand-off succeeded; the uploader will publish its own reply.
        return nullptr;
      }
      response->unsafe_arena_set_allocated_binary_upload(buResponse);
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
static void CommandMessageHandlerImpl(natsConnection* nc, natsSubscription* sub, natsMsg* msg,
                                      SNTPushClientNATS* self) {
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

  NSString* msgSubject = @(natsMsg_GetSubject(msg) ?: "<unknown>");
  NSString* replyTopic = natsMsg_GetReply(msg) ? @(natsMsg_GetReply(msg)) : nil;

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
    ::pbv1::SantaCommandResponse* response =
        [self dispatchSantaCommandToHandler:command onArena:&arena replyTopic:replyTopic];

    if (response == nullptr) {
      // The handler took ownership of the reply path (binary_upload). It
      // will publish via its own queue when the upload settles.
      return;
    }

    // Publish the response
    [self publishResponse:*response toReplyTopic:replyTopic];
  });
}

__BEGIN_DECLS

// NATS-compatible wrapper that converts void *closure to SNTPushClientNATS *
void commandMessageHandler(natsConnection* nc, natsSubscription* sub, natsMsg* msg, void* closure) {
  SNTPushClientNATS* self = (__bridge SNTPushClientNATS*)closure;
  CommandMessageHandlerImpl(nc, sub, msg, self);
}

__END_DECLS
