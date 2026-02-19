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

#import "Source/common/MOLXPCConnection.h"
#include "Source/common/Pinning.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#include "Source/common/SystemResources.h"

NSString *const kStateTempMonitorModeBootUUIDKey = @"BootUUID";
NSString *const kStateTempMonitorModeDeadlineKey = @"Deadline";
NSString *const kStateTempMonitorModeSavedSyncURLKey = @"SyncURL";
NSString *const kStateTempMonitorModeSessionUUIDKey = @"SessionUUID";

namespace santa {

std::shared_ptr<TemporaryMonitorMode> TemporaryMonitorMode::Create(
    SNTConfigurator *configurator, SNTNotificationQueue *notification_queue,
    HandleAuditEventBlock handle_audit_event_block) {
  auto tmm = std::make_shared<TemporaryMonitorMode>(PassKey(), configurator, notification_queue,
                                                    handle_audit_event_block);

  // NB: SetupFromState Is split out of the constructor since it could
  // potentially start the timer, which would take a weak reference before
  // construction was complete.
  tmm->SetupFromState(PassKey(), [configurator savedTemporaryMonitorModeState]);

  return tmm;
}

TemporaryMonitorMode::TemporaryMonitorMode(PassKey, SNTConfigurator *configurator,
                                           SNTNotificationQueue *notification_queue,
                                           HandleAuditEventBlock handle_audit_event_block)
    : Timer(kMinTemporaryMonitorModeMinutes, kMaxTemporaryMonitorModeMinutes,
            Timer::OnStart::kWaitOneCycle, "Temporary Monitor Mode",
            Timer::RescheduleMode::kTrailingEdge, QOS_CLASS_USER_INITIATED),
      configurator_(configurator),
      notification_queue_(notification_queue),
      handle_audit_event_block_([handle_audit_event_block copy]),
      deadline_(0) {}

void TemporaryMonitorMode::SetupFromState(PassKey, NSDictionary *tmm) {
  std::weak_ptr<TemporaryMonitorMode> weak_self = weak_from_base<TemporaryMonitorMode>();
  kvo_ = @[ [[SNTKVOManager alloc]
      initWithObject:configurator_
            selector:@selector(syncBaseURL)
                type:[NSURL class]
            callback:^(NSURL *oldValue, NSURL *newValue) {
              if ((!newValue && !oldValue) ||
                  ([newValue.absoluteString isEqualToString:oldValue.absoluteString])) {
                return;
              }

              if (auto strong_self = weak_self.lock()) {
                if (strong_self->Revoke(SNTTemporaryMonitorModeLeaveReasonSyncServerChanged)) {
                  LOGI(@"Temporary Monitor Mode session revoked due to SyncBaseURL changing.");
                }
              }
            }] ];

  absl::MutexLock lock(&lock_);
  uint32_t secs_remaining = static_cast<uint32_t>(
      std::min(GetSecondsRemainingFromInitialStateLocked(tmm, [SNTSystemInfo bootSessionUUID],
                                                         configurator_.syncBaseURL),
               static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));
  if (secs_remaining < kMinAllowedStateRemainingSeconds) {
    [configurator_ leaveTemporaryMonitorMode];
    [[notification_queue_.notifierConnection remoteObjectProxy] leaveTemporaryMonitorMode];
  } else {
    BeginLocked(secs_remaining, false);
    handle_audit_event_block_([[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
        initWithUUID:[current_uuid_ UUIDString]
             seconds:secs_remaining
              reason:SNTTemporaryMonitorModeEnterReasonRestart]);
  }
}

// When reading Temporary Monitor Mode state, all of the following
// conditions must be true, otherwise the state is discarded:
//   0. All types must meet expectations
//   1. The saved boot session UUID must match the current boot session UUID
//   2. The saved sync URL must match the current SyncBaseURL
//   3. The current SyncBaseURL must be pinned
//   4. The saved session UUID must be a valid UUID
uint64_t TemporaryMonitorMode::GetSecondsRemainingFromInitialStateLocked(
    NSDictionary *tmm, NSString *currentBootSessionUUID, NSURL *syncURL) {
  if (![tmm[kStateTempMonitorModeBootUUIDKey] isKindOfClass:[NSString class]] ||
      ![tmm[kStateTempMonitorModeDeadlineKey] isKindOfClass:[NSNumber class]] ||
      ![tmm[kStateTempMonitorModeSavedSyncURLKey] isKindOfClass:[NSString class]] ||
      ![tmm[kStateTempMonitorModeSessionUUIDKey] isKindOfClass:[NSString class]]) {
    return 0;
  }

  NSUUID *saved_uuid = [[NSUUID alloc] initWithUUIDString:tmm[kStateTempMonitorModeSessionUUIDKey]];
  if (!saved_uuid) {
    // Invalid config value for saved UUID
    return 0;
  }
  current_uuid_ = saved_uuid;

  if (![tmm[kStateTempMonitorModeBootUUIDKey] isEqualToString:currentBootSessionUUID]) {
    // Reboot detected, do not attempt to re-enter Monitor Mode
    handle_audit_event_block_([[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
        initWithUUID:[current_uuid_ UUIDString]
              reason:SNTTemporaryMonitorModeLeaveReasonReboot]);
    return 0;
  }

  if (![tmm[kStateTempMonitorModeSavedSyncURLKey] isEqualToString:syncURL.host] ||
      !configurator_.isSyncV2Enabled) {
    // SyncBaseURL changed or is not pinned, do not attempt to re-enter Monitor Mode automatically.
    // Revoke the mode transition authorization as well so the machine is no longer eligible.
    RevokeLocked(SNTTemporaryMonitorModeLeaveReasonSyncServerChanged);
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
    handle_audit_event_block_([[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
        initWithUUID:[current_uuid_ UUIDString]
              reason:SNTTemporaryMonitorModeLeaveReasonSessionExpired]);
    return 0;
  }
}

void TemporaryMonitorMode::NewModeTransitionReceived(SNTModeTransition *mode_transition) {
  if (mode_transition.type == SNTModeTransitionTypeRevoke) {
    if (Revoke(SNTTemporaryMonitorModeLeaveReasonRevoked)) {
      LOGI(@"Temporary Monitor Mode session revoked due to policy change.");
    }
  } else {
    [configurator_ setSyncServerModeTransition:mode_transition];
  }

  // Notify the GUI about policy availability
  [[notification_queue_.notifierConnection remoteObjectProxy]
      temporaryMonitorModePolicyAvailable:Available(nil)];
}

bool TemporaryMonitorMode::Available(NSError **err) {
  SNTModeTransition *mode_transition = [configurator_ modeTransition];
  if (mode_transition.type != SNTModeTransitionTypeOnDemand) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTMMNoPolicy
                     format:@"This machine does not currently have a "
                            @"policy allowing temporary Monitor Mode."];
    return false;
  }

  SNTClientMode clientMode = [configurator_ clientMode];
  if (!(clientMode == SNTClientModeLockdown ||
        (clientMode == SNTClientModeMonitor && [configurator_ inTemporaryMonitorMode]))) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTMMNotInLockdown
                     format:@"Machine must be in Lockdown Mode in order to "
                            @"transition to temporary Monitor Mode."];
    return false;
  }

  if (!configurator_.isSyncV2Enabled) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTMMInvalidSyncServer
                     format:@"This machine is not configured with a sync "
                            @"server that supports temporary Monitor Mode."];
    return false;
  }
  return true;
};

uint32_t TemporaryMonitorMode::RequestMinutes(NSNumber *requested_duration, NSError **err) {
  if (!Available(err)) {
    return 0;
  }

  __block BOOL auth_success = NO;
  [notification_queue_ authorizeTemporaryMonitorMode:^(BOOL authenticated) {
    auth_success = authenticated;
  }];

  if (!auth_success) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTMMAuthFailed
                     format:@"User authorization failed."];
    return 0;
  }

  SNTModeTransition *mode_transition = [configurator_ modeTransition];
  uint32_t duration_min = [mode_transition getDurationMinutes:requested_duration];

  absl::MutexLock lock(&lock_);
  SNTTemporaryMonitorModeEnterReason reason;
  if (BeginLocked(duration_min * 60, true)) {
    reason = SNTTemporaryMonitorModeEnterReasonOnDemand;
  } else {
    reason = SNTTemporaryMonitorModeEnterReasonOnDemandRefresh;
  }
  handle_audit_event_block_([[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
      initWithUUID:[current_uuid_ UUIDString]
           seconds:static_cast<uint32_t>(SecondsRemaining(deadline_).value_or(0))
            reason:reason]);

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

bool TemporaryMonitorMode::BeginLocked(uint32_t seconds, bool gen_uuid_on_start) {
  bool did_start_new_timer = StartTimerWithInterval(seconds);
  if (did_start_new_timer && gen_uuid_on_start) {
    current_uuid_ = [NSUUID UUID];
  }

  uint64_t deadline = AddNanosecondsToMachTime(seconds * NSEC_PER_SEC, mach_continuous_time());

  [configurator_ enterTemporaryMonitorMode:@{
    kStateTempMonitorModeBootUUIDKey : [SNTSystemInfo bootSessionUUID],
    kStateTempMonitorModeDeadlineKey : @(deadline),
    kStateTempMonitorModeSavedSyncURLKey : configurator_.syncBaseURL.host,
    kStateTempMonitorModeSessionUUIDKey : [current_uuid_ UUIDString],
  }];

  deadline_ = deadline;

  id<SNTNotifierXPC> rop = [notification_queue_.notifierConnection remoteObjectProxy];
  [rop enterTemporaryMonitorMode:[NSDate dateWithTimeIntervalSinceNow:seconds]];

  return did_start_new_timer;
}

bool TemporaryMonitorMode::Cancel() {
  absl::MutexLock lock(&lock_);
  if (EndLocked()) {
    handle_audit_event_block_([[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
        initWithUUID:[current_uuid_ UUIDString]
              reason:SNTTemporaryMonitorModeLeaveReasonCancelled]);
    current_uuid_ = nil;
    return true;
  } else {
    return false;
  }
}

bool TemporaryMonitorMode::Revoke(SNTTemporaryMonitorModeLeaveReason reason) {
  absl::MutexLock lock(&lock_);
  return RevokeLocked(reason);
}

bool TemporaryMonitorMode::RevokeLocked(SNTTemporaryMonitorModeLeaveReason reason) {
  [configurator_ setSyncServerModeTransition:[[SNTModeTransition alloc] initRevocation]];
  if (EndLocked()) {
    handle_audit_event_block_([[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
        initWithUUID:[current_uuid_ UUIDString]
              reason:reason]);
    current_uuid_ = nil;
    return true;
  } else {
    return false;
  }
}

bool TemporaryMonitorMode::EndLocked() {
  if (StopTimer()) {
    [configurator_ leaveTemporaryMonitorMode];
    [[notification_queue_.notifierConnection remoteObjectProxy] leaveTemporaryMonitorMode];
    return true;
  } else {
    return false;
  }
}

bool TemporaryMonitorMode::OnTimer() {
  absl::MutexLock lock(&lock_);
  [configurator_ leaveTemporaryMonitorMode];
  [[notification_queue_.notifierConnection remoteObjectProxy] leaveTemporaryMonitorMode];

  handle_audit_event_block_([[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
      initWithUUID:[current_uuid_ UUIDString]
            reason:SNTTemporaryMonitorModeLeaveReasonSessionExpired]);
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
