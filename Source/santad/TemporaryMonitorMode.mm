/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/TemporaryMonitorMode.h"

#include <mach/mach_time.h>

#include "Source/common/Pinning.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/SystemResources.h"

namespace santa {

static NSString *const kStateTempMonitorModeBootSessionUUIDKey = @"UUID";
static NSString *const kStateTempMonitorModeDeadlineKey = @"Deadline";
static NSString *const kStateTempMonitorModeSavedSyncURLKey = @"SyncURL";

std::shared_ptr<TemporaryMonitorMode> TemporaryMonitorMode::Create(
    SNTConfigurator *configurator, SNTNotificationQueue *notification_queue) {
  auto tmm = std::make_shared<TemporaryMonitorMode>(PassKey(), configurator, notification_queue);

  // NB: SetupFromState Is split out of the constructor since it could
  // potentially start the timer, which would take a weak reference before
  // construction was complete.
  tmm->SetupFromState(PassKey(), [configurator savedTemporaryMonitorModeState]);

  return tmm;
}

TemporaryMonitorMode::TemporaryMonitorMode(PassKey, SNTConfigurator *configurator,
                                           SNTNotificationQueue *notification_queue)
    : Timer(kMinTemporaryMonitorModeMinutes, kMaxTemporaryMonitorModeMinutes,
            Timer::OnStart::kWaitOneCycle, "Temporary Monitor Mode",
            Timer::RescheduleMode::kTrailingEdge, QOS_CLASS_USER_INITIATED),
      configurator_(configurator),
      notification_queue_(notification_queue),
      deadline_(0) {}

void TemporaryMonitorMode::SetupFromState(PassKey, NSDictionary *tmm) {
  uint32_t secs_remaining = static_cast<uint32_t>(
      std::min(GetSecondsRemainingFromInitialState(tmm, [SNTSystemInfo bootSessionUUID],
                                                   configurator_.syncBaseURL),
               static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
  if (secs_remaining < kMinAllowedStateRemainingSeconds) {
    [configurator_ leaveTemporaryMonitorMode];
  } else {
    absl::MutexLock lock(&lock_);
    BeginLocked(secs_remaining);
    // TODO: current_uuid_ = state UUID
    // TODO: Emit "restart" audit event
  }
}

// When reading Temporary Monitor Mode state, all of the following
// conditions must be true, otherwise the state is discarded:
//   0. All types must meet expectations
//   1. The saved boot session UUID must match the current boot session UUID
//   2. The saved sync URL must match the current SyncBaseURL
//   3. The current SyncBaseURL must be pinned
uint64_t TemporaryMonitorMode::GetSecondsRemainingFromInitialState(NSDictionary *tmm,
                                                                   NSString *currentBootSessionUUID,
                                                                   NSURL *syncURL) {
  if (![tmm[kStateTempMonitorModeBootSessionUUIDKey] isKindOfClass:[NSString class]] ||
      ![tmm[kStateTempMonitorModeDeadlineKey] isKindOfClass:[NSNumber class]] ||
      ![tmm[kStateTempMonitorModeSavedSyncURLKey] isKindOfClass:[NSString class]]) {
    return 0;
  }

  if (![tmm[kStateTempMonitorModeBootSessionUUIDKey] isEqualToString:currentBootSessionUUID]) {
    // Reboot detected, do not attempt to re-enter Monitor Mode
    // TODO: Emit audit event
    return 0;
  }

  if (![tmm[kStateTempMonitorModeSavedSyncURLKey] isEqualToString:syncURL.host] ||
      !santa::IsDomainPinned(syncURL)) {
    // SyncBaseURL changed or is not pinned, do not attempt to re-enter Monitor Mode automatically.
    // Revoke the mode transition authorization as well so the machine is no longer eligible.
    Revoke();
    // TODO: Emit audit event
    return 0;
  }

  NSNumber *deadline = tmm[kStateTempMonitorModeDeadlineKey];
  if (!deadline) {
    return 0;
  }

  std::optional<uint64_t> secs_remaining = SecondsRemaining([deadline unsignedLongLongValue]);
  if (secs_remaining.has_value()) {
    return *secs_remaining;
  } else {
    // TODO: Emit "expired" audit event
    return 0;
  }
}

void TemporaryMonitorMode::NewModeTransitionReceived(SNTModeTransition *mode_transition) {
  if (mode_transition.type == SNTModeTransitionTypeRevoke) {
    if (Revoke()) {
      LOGI(@"Temporary Monitor Mode session revoked due to policy change.");
    }
  } else {
    [configurator_ setSyncServerModeTransition:mode_transition];
  }
}

uint32_t TemporaryMonitorMode::RequestMinutes(NSNumber *requested_duration, NSError **err) {
  SNTModeTransition *mode_transition = [configurator_ modeTransition];
  if (mode_transition.type != SNTModeTransitionTypeOnDemand) {
    [SNTError populateError:err
                 withFormat:@"This machine does not currently have a "
                            @"policy allowing temporary Monitor Mode."];
    return 0;
  }

  SNTClientMode clientMode = [configurator_ clientMode];
  if (!(clientMode == SNTClientModeLockdown ||
        (clientMode == SNTClientModeMonitor && [configurator_ inTemporaryMonitorMode]))) {
    [SNTError populateError:err
                 withFormat:@"Machine must be in Lockdown Mode in order to "
                            @"transition to temporary Monitor Mode."];
    return 0;
  }

  if (!santa::IsDomainPinned(configurator_.syncBaseURL)) {
    [SNTError populateError:err
                 withFormat:@"This machine is not configured with a sync "
                            @"server that supports temporary Monitor Mode."];
    return 0;
  }

  __block BOOL auth_success = NO;
  [notification_queue_ authorizeTemporaryMonitorMode:^(BOOL authenticated) {
    auth_success = authenticated;
  }];

  if (!auth_success) {
    [SNTError populateError:err withFormat:@"User authorization failed."];
    return 0;
  }

  uint32_t duration_min = [mode_transition getDurationMinutes:requested_duration];

  absl::MutexLock lock(&lock_);
  if (BeginLocked(duration_min * 60)) {
    // TODO: Emit "on demand" audit event
    current_uuid_ = [NSUUID UUID];
  } else {
    // TODO: Emit "on demand refresh" audit event
  }

  return duration_min;
}

std::optional<uint64_t> TemporaryMonitorMode::SecondsRemaining() const {
  absl::ReaderMutexLock lock(&lock_);
  if (IsStarted()) {
    return SecondsRemaining(deadline_);
  } else {
    return std::nullopt;
  }
}

std::optional<uint64_t> TemporaryMonitorMode::SecondsRemaining(uint64_t deadline_mach_time) {
  uint64_t current_mach_time = mach_continuous_time();
  if (deadline_mach_time <= current_mach_time) {
    return std::nullopt;
  } else {
    return MachTimeToNanos(deadline_mach_time - current_mach_time) / NSEC_PER_SEC;
  }
}

bool TemporaryMonitorMode::BeginLocked(uint32_t seconds) {
  bool did_start_new_timer = StartTimerWithInterval(seconds);

  uint64_t deadline = AddNanosecondsToMachTime(seconds * NSEC_PER_SEC, mach_continuous_time());

  [configurator_ enterTemporaryMonitorMode:@{
    kStateTempMonitorModeBootSessionUUIDKey : [SNTSystemInfo bootSessionUUID],
    kStateTempMonitorModeDeadlineKey : @(deadline),
    kStateTempMonitorModeSavedSyncURLKey : configurator_.syncBaseURL.host,
  }];

  deadline_ = deadline;

  return did_start_new_timer;
}

bool TemporaryMonitorMode::Cancel() {
  absl::MutexLock lock(&lock_);
  if (EndLocked()) {
    // TODO: Emit "cancelled" audit event
    current_uuid_ = nil;
    return true;
  } else {
    return false;
  }
}

bool TemporaryMonitorMode::Revoke() {
  absl::MutexLock lock(&lock_);
  [configurator_ setSyncServerModeTransition:[[SNTModeTransition alloc] initRevocation]];
  if (EndLocked()) {
    // TODO: Emit "revoked" audit event
    current_uuid_ = nil;
    return true;
  } else {
    return false;
  }
}

bool TemporaryMonitorMode::EndLocked() {
  if (StopTimer()) {
    [configurator_ leaveTemporaryMonitorMode];
    return true;
  } else {
    return false;
  }
}

bool TemporaryMonitorMode::OnTimer() {
  absl::MutexLock lock(&lock_);
  [configurator_ leaveTemporaryMonitorMode];

  // TODO: Emit "expired" audit event
  current_uuid_ = nil;

  // Don't restart the timer
  return false;
}

bool TemporaryMonitorMode::StartTimer() {
  return Timer<TemporaryMonitorMode>::StartTimer();
}

bool TemporaryMonitorMode::StartTimerWithInterval(uint32_t interval_seconds) {
  return Timer<TemporaryMonitorMode>::StartTimerWithInterval(interval_seconds);
}

bool TemporaryMonitorMode::StopTimer() {
  return Timer<TemporaryMonitorMode>::StopTimer();
}

}  // namespace santa
