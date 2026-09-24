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

#ifndef SANTA_SANTAD_RECENTBLOCKS_H
#define SANTA_SANTAD_RECENTBLOCKS_H

#import <Foundation/Foundation.h>

#include <sys/types.h>

#include "Source/common/RingBuffer.h"
#include "absl/synchronization/mutex.h"

namespace santa {

// Keys of the dictionaries returned by Since(). Values are property-list types
// only, so the array can cross XPC without any class whitelisting.
extern NSString* const kRecentBlockTimestamp;
extern NSString* const kRecentBlockPath;
extern NSString* const kRecentBlockReason;
extern NSString* const kRecentBlockSHA256;
extern NSString* const kRecentBlockPID;
extern NSString* const kRecentBlockPPID;
extern NSString* const kRecentBlockUID;

// A small in-memory record of the executions this daemon most recently denied,
// so a caller that only saw a process die with SIGKILL can find out that Santa
// was the cause. Entries are never persisted and are lost when santad restarts.
class RecentBlocks {
 public:
  static constexpr size_t kCapacity = 32;

  RecentBlocks() : blocks_(kCapacity) {}

  // No copies, no moves
  RecentBlocks(const RecentBlocks& other) = delete;
  RecentBlocks& operator=(const RecentBlocks& other) = delete;
  RecentBlocks(RecentBlocks&& other) = delete;
  RecentBlocks& operator=(RecentBlocks&& rhs) = delete;

  // Record a denied execution, timestamped now. Oldest entries are dropped once
  // the buffer is full.
  void Record(pid_t pid, pid_t ppid, uid_t uid, NSString* path, NSString* sha256, NSString* reason);

  // Blocks recorded at or after `since`, oldest first. Only blocks of
  // executions run by `caller_uid` are returned unless the caller is root:
  // which binaries another user tried to run is not theirs to see.
  NSArray<NSDictionary*>* Since(NSDate* since, uid_t caller_uid);

 private:
  RingBuffer<NSDictionary*> blocks_ ABSL_GUARDED_BY(lock_);
  absl::Mutex lock_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_RECENTBLOCKS_H
