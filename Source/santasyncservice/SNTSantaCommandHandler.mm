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
#import "Source/santasyncservice/SNTSantaCommandHandler+EventUpload.h"
#import "Source/santasyncservice/SNTSantaCommandHandler+Kill.h"

namespace pbv1 = ::santa::commands::v1;
using santa::NSStringToUTF8String;

@interface SNTSantaCommandHandler ()
@property(weak) id<SNTPushNotificationsSyncDelegate> syncDelegate;
@end

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

- (::pbv1::CommandResult*)executeQueuedCommand:(const ::pbv1::QueuedCommand&)command
                                       onArena:(google::protobuf::Arena*)arena {
  auto result = google::protobuf::Arena::Create<::pbv1::CommandResult>(arena);
  result->set_command_id(command.command_id());

  // Check if the command type is allowed by client configuration.
  // No default case — compiler enforces all proto cases are handled (-Werror + -Wswitch)
  NSString* commandName = nil;
  switch (command.command_case()) {
    case ::pbv1::QueuedCommand::kKill: commandName = @"kill"; break;
    case ::pbv1::QueuedCommand::kEventUpload: commandName = @"event_upload"; break;
    case ::pbv1::QueuedCommand::COMMAND_NOT_SET: break;
  }

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
