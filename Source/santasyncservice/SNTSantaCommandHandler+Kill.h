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

#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#include "commands/v1.pb.h"

/// Kill command execution, shared by every command transport.
@interface SNTSantaCommandHandler (Kill)

/// Kill the requested processes via santad. Blocks until santad replies or the
/// request times out. `identifier` is an opaque per-command id used for
/// tracking (the NATS command UUID or the queued command id).
- (santa::commands::v1::KillResponse*)handleKillRequest:
                                          (const santa::commands::v1::KillRequest&)request
                                         withIdentifier:(NSString*)identifier
                                                onArena:(google::protobuf::Arena*)arena;

@end
