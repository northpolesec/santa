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

#import "Source/santasyncservice/SNTSyncCommands.h"

#include "Source/common/String.h"
#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"
#include "commands/v1.pb.h"
#include "google/protobuf/arena.h"
#include "syncv2/v2.pb.h"

using santa::NSStringToUTF8String;

namespace pbv1 = ::santa::commands::v1;
namespace pbv2 = ::santa::sync::v2;

// Upper bound on commands executed in a single sync. The server delivers one
// command per exchange and bounds its own queue depth, so this is purely a
// guard against a misbehaving server keeping the loop alive forever.
static const NSUInteger kMaxCommandsPerSync = 50;

@interface SNTSyncCommands ()
@property(nonatomic) SNTSantaCommandHandler* commandHandler;
@end

@implementation SNTSyncCommands

- (instancetype)initWithState:(SNTSyncState*)state
               commandHandler:(SNTSantaCommandHandler*)commandHandler {
  self = [super initWithState:state];
  if (self) {
    _commandHandler = commandHandler;
  }
  return self;
}

- (NSURL*)stageURL {
  NSString* stageName = [@"commands" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

// Posts an ack-only DELIVERED result for `commandId` so the server reflects
// in-progress state while the command executes. The server withholds new
// commands while one is in flight, so the ack response is discarded.
- (BOOL)postDeliveredAckForCommandID:(int64_t)commandId onArena:(google::protobuf::Arena*)arena {
  auto req = google::protobuf::Arena::Create<pbv2::CommandsRequest>(arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
  pbv1::CommandResult* result = req->mutable_result();
  result->set_command_id(commandId);
  result->set_host_status(::pbv1::CommandResult::HOST_STATUS_DELIVERED);

  pbv2::CommandsResponse response;
  NSError* err = [self performRequest:[self requestWithMessage:req]
                          intoMessage:&response
                              timeout:30];
  if (err) {
    SLOGE(@"Failed to post delivered ack for command %lld: %@", (long long)commandId, err);
    return NO;
  }
  return YES;
}

- (BOOL)sync {
  google::protobuf::Arena arena;

  // The first exchange carries no result; it just asks for the next queued
  // command.
  auto req = google::protobuf::Arena::Create<pbv2::CommandsRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));

  NSUInteger executed = 0;
  while (true) {
    pbv2::CommandsResponse response;
    NSError* err = [self performRequest:[self requestWithMessage:req]
                            intoMessage:&response
                                timeout:30];
    if (err) {
      SLOGE(@"Failed to fetch queued commands: %@", err);
      return NO;
    }

    if (!response.has_command()) {
      if (executed) {
        SLOGI(@"Executed %lu queued command(s)", (unsigned long)executed);
      }
      return YES;
    }

    if (executed >= kMaxCommandsPerSync) {
      // The unexecuted command was never acknowledged, so it remains queued
      // server-side and is delivered again on the next sync.
      SLOGW(@"Queued command limit (%lu) reached; remaining commands deferred to next sync",
            (unsigned long)kMaxCommandsPerSync);
      return YES;
    }

    const pbv1::QueuedCommand& command = response.command();

    // Event uploads can run for minutes, so ack DELIVERED first: the server
    // shows the command in flight instead of untouched while the upload runs.
    // Kill is fast and posts straight to COMPLETE (the state machine allows
    // skipping the ack). Commands the handler will reject are not acked —
    // DELIVERED means "will execute it". An ack failure aborts the drain like
    // any other transport failure: the command was never executed and, unless
    // the ack landed with only its response lost, is still queued server-side
    // for the next sync.
    if (command.command_case() == ::pbv1::QueuedCommand::kEventUpload &&
        [SNTSantaCommandHandler isCommandAllowed:@"event_upload"] &&
        ![self postDeliveredAckForCommandID:command.command_id() onArena:&arena]) {
      return NO;
    }

    // Execute the command, then post its result back. The server responds
    // with the next queued command until its queue is drained.
    pbv1::CommandResult* result = [self.commandHandler executeQueuedCommand:command onArena:&arena];
    executed++;

    req = google::protobuf::Arena::Create<pbv2::CommandsRequest>(&arena);
    req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
    req->unsafe_arena_set_allocated_result(result);
  }
}

@end
