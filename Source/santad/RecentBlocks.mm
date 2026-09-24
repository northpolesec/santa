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

#include "Source/santad/RecentBlocks.h"

namespace santa {

NSString* const kRecentBlockTimestamp = @"timestamp";
NSString* const kRecentBlockPath = @"path";
NSString* const kRecentBlockReason = @"reason";
NSString* const kRecentBlockSHA256 = @"sha256";
NSString* const kRecentBlockPID = @"pid";
NSString* const kRecentBlockPPID = @"ppid";
NSString* const kRecentBlockUID = @"uid";

void RecentBlocks::Record(pid_t pid, pid_t ppid, uid_t uid, NSString* path, NSString* sha256,
                          NSString* reason) {
  NSDictionary* block = @{
    kRecentBlockTimestamp : @([[NSDate date] timeIntervalSince1970]),
    kRecentBlockPath : path ?: @"",
    kRecentBlockReason : reason ?: @"",
    kRecentBlockSHA256 : sha256 ?: @"",
    kRecentBlockPID : @(pid),
    kRecentBlockPPID : @(ppid),
    kRecentBlockUID : @(uid),
  };

  absl::MutexLock lock(lock_);
  blocks_.Enqueue(block);
}

NSArray<NSDictionary*>* RecentBlocks::Since(NSDate* since, uid_t caller_uid) {
  NSTimeInterval cutoff = [since timeIntervalSince1970];
  NSMutableArray<NSDictionary*>* matches = [NSMutableArray array];

  absl::MutexLock lock(lock_);
  for (NSDictionary* block : blocks_) {
    if ([block[kRecentBlockTimestamp] doubleValue] < cutoff) {
      continue;
    }
    if (caller_uid != 0 && [block[kRecentBlockUID] unsignedIntValue] != caller_uid) {
      continue;
    }
    [matches addObject:block];
  }

  return matches;
}

}  // namespace santa
