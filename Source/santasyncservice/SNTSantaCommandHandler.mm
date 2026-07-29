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

#import "Source/santasyncservice/SNTSantaCommandHandler.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+BinaryUpload.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+EventUpload.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+Kill.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+PackageInventory.h"

namespace pbv1 = ::santa::commands::v1;
using santa::NSStringToUTF8String;

namespace {

// The AllowedSantaCommands name for a queued command, or nil when no command is
// set (that case is reported as FAILED rather than gated by the allowlist).
// No default case — compiler enforces all proto cases are handled
// (-Werror + -Wswitch)
NSString* CommandName(const ::pbv1::QueuedCommand& command) {
  switch (command.command_case()) {
    case ::pbv1::QueuedCommand::kKill: return @"kill";
    case ::pbv1::QueuedCommand::kEventUpload: return @"event_upload";
    case ::pbv1::QueuedCommand::kBinaryUpload: return @"binary_upload";
    case ::pbv1::QueuedCommand::kPackageInventory: return @"package_inventory";
    case ::pbv1::QueuedCommand::COMMAND_NOT_SET: return nil;
  }
}

}  // namespace

@implementation SNTSantaCommandHandler

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate {
  self = [super init];
  if (self) {
    _syncDelegate = syncDelegate;
  }
  return self;
}

+ (BOOL)isCommandAllowed:(NSString*)commandName {
  NSArray<NSString*>* allowed = [[SNTConfigurator configurator] allowedSantaCommands];
  return !allowed || [allowed containsObject:commandName];
}

+ (BOOL)shouldPostDeliveredAckForCommand:(const ::pbv1::QueuedCommand&)command {
  // Uploads and package-inventory scans can run for minutes; acking first lets
  // the server show them in flight instead of untouched while they run.
  // Everything else is fast enough to post straight to COMPLETE.
  switch (command.command_case()) {
    case ::pbv1::QueuedCommand::kEventUpload:
    case ::pbv1::QueuedCommand::kBinaryUpload:
    case ::pbv1::QueuedCommand::kPackageInventory: break;
    default: return NO;
  }

  // DELIVERED means "will execute it", so don't ack a command that is about to
  // be rejected by the allowlist.
  NSString* commandName = CommandName(command);
  return commandName && [self isCommandAllowed:commandName];
}

- (::pbv1::CommandResult*)executeQueuedCommand:(const ::pbv1::QueuedCommand&)command
                                       onArena:(google::protobuf::Arena*)arena {
  auto result = google::protobuf::Arena::Create<::pbv1::CommandResult>(arena);
  result->set_command_id(command.command_id());

  // Check if the command type is allowed by client configuration.
  NSString* commandName = CommandName(command);
  if (commandName && ![SNTSantaCommandHandler isCommandAllowed:commandName]) {
    LOGW(@"SantaCommand: Command '%@' rejected - not in AllowedSantaCommands", commandName);
    result->set_host_status(::pbv1::CommandResult::HOST_STATUS_REJECTED);
    result->set_error_message(
        NSStringToUTF8String([NSString stringWithFormat:@"command '%@' is not in the agent's "
                                                        @"AllowedSantaCommands configuration",
                                                        commandName]));
    return result;
  }

  switch (command.command_case()) {
    case ::pbv1::QueuedCommand::kKill: {
      LOGI(@"SantaCommand: Executing queued KillRequest command %lld",
           (long long)command.command_id());
      NSString* identifier = [NSString stringWithFormat:@"%lld", (long long)command.command_id()];
      auto* killResponse = [self handleKillRequest:command.kill()
                                    withIdentifier:identifier
                                           onArena:arena];
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_COMPLETE);
      result->unsafe_arena_set_allocated_kill(killResponse);
      break;
    }

    case ::pbv1::QueuedCommand::kEventUpload: {
      LOGI(@"SantaCommand: Executing queued EventUploadRequest command %lld",
           (long long)command.command_id());
      // Queued commands run serially at the end of a sync, so unlike the NATS
      // path this blocks until the upload finishes and the posted result
      // reflects the actual outcome.
      std::string errorMessage;
      auto* uploadResponse = [self handleEventUploadRequestAndWait:command.event_upload()
                                                           onArena:arena
                                                      errorMessage:&errorMessage];
      if (!errorMessage.empty()) {
        result->set_error_message(errorMessage);
      }
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_COMPLETE);
      result->unsafe_arena_set_allocated_event_upload(uploadResponse);
      break;
    }

    case ::pbv1::QueuedCommand::kBinaryUpload: {
      LOGI(@"SantaCommand: Executing queued BinaryUploadRequest command %lld",
           (long long)command.command_id());
      // Like event upload, this blocks until santad reports the upload's
      // outcome so the posted result reflects what actually happened.
      auto* uploadResponse = [self handleBinaryUploadRequestAndWait:command.binary_upload()
                                                            onArena:arena];
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_COMPLETE);
      result->unsafe_arena_set_allocated_binary_upload(uploadResponse);
      break;
    }

    case ::pbv1::QueuedCommand::kPackageInventory: {
      LOGI(@"SantaCommand: Executing queued PackageInventoryRequest command %lld",
           (long long)command.command_id());
      // Runs serially at the end of a sync and blocks until santad's scan
      // finishes, so the posted result reflects the actual outcome.
      std::string errorMessage;
      auto* scanResponse = [self handlePackageInventoryRequest:command.package_inventory()
                                                       onArena:arena
                                                  errorMessage:&errorMessage];
      if (!errorMessage.empty()) {
        result->set_error_message(errorMessage);
      }
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_COMPLETE);
      result->unsafe_arena_set_allocated_package_inventory(scanResponse);
      break;
    }

    case ::pbv1::QueuedCommand::COMMAND_NOT_SET:
    default:
      LOGE(@"SantaCommand: Unknown or unset queued command type: %d",
           static_cast<int>(command.command_case()));
      result->set_host_status(::pbv1::CommandResult::HOST_STATUS_FAILED);
      result->set_error_message("unknown or unset command type");
      break;
  }

  return result;
}

@end
