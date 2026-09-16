/// Copyright 2022 Google LLC
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

#ifndef SANTA_COMMON_SYSTEMRESOURCES_H
#define SANTA_COMMON_SYSTEMRESOURCES_H

#import <Foundation/Foundation.h>
#include <mach/mach_time.h>
#include <sys/cdefs.h>
#include <sys/proc_info.h>
#include <sys/types.h>
#include <time.h>

#include <optional>
#include <vector>

struct SantaTaskInfo {
  uint64_t virtual_size;
  uint64_t resident_size;
  uint64_t total_user_nanos;
  uint64_t total_system_nanos;
};

// Convert mach absolute time to nanoseconds
uint64_t MachTimeToNanos(uint64_t mach_time);

// Convert nanoseconds to mach absolute time
uint64_t NanosToMachTime(uint64_t nanos);

// Add some number of nanoseconds to a given mach time and return the new result
uint64_t AddNanosecondsToMachTime(uint64_t ns, uint64_t machTime);

// Get the current system uptime in nanoseconds (monotonic clock)
static inline uint64_t GetCurrentUptime() {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC);
}

// Get the result of proc_pidinfo with the PROC_PIDTASKINFO flavor
std::optional<SantaTaskInfo> GetTaskInfo();

// Get a list of all current pids
std::optional<std::vector<pid_t>> GetPidList();

// Get the st_dev shared by the volumes of the boot volume group.
//
// The system and data volumes of an APFS volume group are presented as a single
// device, so this identifies "the volumes this machine booted from" rather than
// any single volume. It also differs from the f_fsid statfs reports for the
// same file, so the two are not interchangeable.
//
// Resolved once per process. Returns std::nullopt if it could not be
// determined.
std::optional<dev_t> GetBootVolumeGroupDev();

// Debug builds only. GetBootVolumeGroupDev feeds the check that decides whether
// a caller-supplied stat may be accepted without comparison, so an override
// that relaxes it must not be reachable in a shipping binary. The storage
// backing them is compiled out with them.
#ifdef DEBUG

// Override the value returned by GetBootVolumeGroupDev. Pass std::nullopt to
// restore normal resolution. Tests only.
void SetBootVolumeGroupDevForTesting(std::optional<dev_t> dev);

// Force GetBootVolumeGroupDev to report the device as undetermined, which
// SetBootVolumeGroupDevForTesting(std::nullopt) cannot express -- it restores
// normal resolution. Takes precedence over any value override. Tests only.
void SetBootVolumeGroupDevUnavailableForTesting(bool unavailable);

#endif  // DEBUG

#endif  // SANTA_COMMON_SYSTEMRESOURCES_H
