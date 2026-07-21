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

#include <google/protobuf/arena.h>

#import "Source/santasyncservice/SNTPushNotifications.h"
#include "commands/v1.pb.h"

/// Executes Santa commands independently of the transport that delivered them.
/// Both the NATS push client (request-reply) and the HTTP sync command drain
/// call into this handler; transport concerns (envelope verification, replies,
/// queue acknowledgment) stay with the callers.
///
/// Per-command execution lives in one category (and file) per command:
/// SNTSantaCommandHandler+Kill and SNTSantaCommandHandler+EventUpload.
@interface SNTSantaCommandHandler : NSObject

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate;

/// Returns YES if the named command is permitted by the AllowedSantaCommands
/// configuration. An unset config allows all commands; an empty list blocks all.
+ (BOOL)isCommandAllowed:(NSString*)commandName;

/// Execute one queued command (HTTP delivery) and block until it finishes,
/// returning the result to post back to the server. Never returns nullptr.
- (santa::commands::v1::CommandResult*)executeQueuedCommand:
                                           (const santa::commands::v1::QueuedCommand&)command
                                                    onArena:(google::protobuf::Arena*)arena;

@end
