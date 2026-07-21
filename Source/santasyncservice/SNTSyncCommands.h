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

#import "Source/santasyncservice/SNTSyncStage.h"

@class SNTSantaCommandHandler;

/// Drains the server-side command queue at the end of a sync. Exchanges are
/// strictly 1:1: each request posts the result of the previously executed
/// command (none on the first exchange) and the server replies with at most
/// one queued command; the loop runs until the server has nothing left.
/// Long-running commands (event upload) additionally post an ack-only
/// DELIVERED result before executing so the server reflects in-progress
/// state; fast commands (kill) post straight to COMPLETE. Commands execute
/// serially and nothing is persisted client-side: commands that don't run
/// (failure, cap, crash) stay queued server-side and are delivered again on
/// the next sync.
@interface SNTSyncCommands : SNTSyncStage

- (nullable instancetype)initWithState:(nonnull SNTSyncState*)state
                        commandHandler:(nonnull SNTSantaCommandHandler*)commandHandler;

@end
