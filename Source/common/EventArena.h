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

#ifndef SANTA_COMMON_EVENTARENA_H
#define SANTA_COMMON_EVENTARENA_H

#include <cstddef>

#include "google/protobuf/arena.h"

namespace santa {

// Large enough that typical events, including execs, need no heap arena blocks.
inline constexpr size_t kEventArenaInitialBlockSize = 8 * 1024;

// Arena for serializing one event, with its first block on the stack. Events
// that outgrow it get heap blocks as usual.
class EventArena {
 public:
  EventArena() : arena_(initial_block_, sizeof(initial_block_)) {}
  google::protobuf::Arena* get() { return &arena_; }

 private:
  // Declared before arena_ so that it outlives the arena.
  alignas(8) char initial_block_[kEventArenaInitialBlockSize];
  google::protobuf::Arena arena_;
};

}  // namespace santa

#endif  // SANTA_COMMON_EVENTARENA_H
