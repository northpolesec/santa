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

#include "Source/santad/TimedSyncSession.h"

#include <dispatch/dispatch.h>
#include <mach/mach_time.h>

#include <algorithm>
#include <limits>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/SystemResources.h"

NSString* const kTimedSessionBootUUIDKey = @"BootUUID";
NSString* const kTimedSessionDeadlineKey = @"Deadline";
NSString* const kTimedSessionSyncURLKey = @"SyncURL";
NSString* const kTimedSessionSessionUUIDKey = @"SessionUUID";

namespace santa {

// Fail-closed timeout for the synchronous GUI authorization callback (Touch ID +
// typing a reason). Generous, but bounded so a hung/stalled GUI cannot hold
// grant_mutex_ and the request handler thread indefinitely.
static constexpr int64_t kAuthTimeoutNSec = 90 * NSEC_PER_SEC;

// Free-text reason is capped before it is logged, audited, or synced.
static constexpr NSUInteger kMaxReasonLength = 512;

TimedSyncSession::TimedSyncSession(uint32_t min_minutes, uint32_t max_minutes, const char* label,
                                   SNTConfigurator* configurator,
                                   SNTNotificationQueue* notification_queue)
    // Session bounds are expressed in minutes; the Timer base clamps its interval
    // in seconds. Convert here so the min/max clamp reflects the real bounds
    // instead of treating a minute count as a second count.
    : Timer(min_minutes * 60, max_minutes * 60, Timer::OnStart::kWaitOneCycle, label,
            Timer::RescheduleMode::kTrailingEdge, QOS_CLASS_USER_INITIATED),
      configurator_(configurator),
      notification_queue_(notification_queue),
      deadline_(0),
      active_(false) {}

TimedSyncSession::~TimedSyncSession() = default;

void TimedSyncSession::SetupFromState() {
  std::weak_ptr<TimedSyncSession> weak_self = weak_from_base<TimedSyncSession>();
  kvo_ = @[
    [[SNTKVOManager alloc]
        initWithObject:configurator_
              selector:@selector(syncBaseURL)
                  type:[NSURL class]
              callback:^(NSURL* oldValue, NSURL* newValue) {
                if ((!newValue && !oldValue) ||
                    ([newValue.absoluteString isEqualToString:oldValue.absoluteString])) {
                  return;
                }
                if (auto strong_self = weak_self.lock()) {
                  if (strong_self->Revoke(strong_self->LeaveReasonSyncServerChanged())) {
                    LOGI(@"Timed sync session revoked due to SyncBaseURL changing.");
                  }
                }
              }],
    // The sync-v2 gate (SyncServerGateSatisfied) is also satisfied by a valid push
    // token chain, so a push-token-only deployment can hold a session with a nil
    // syncBaseURL. Watching syncBaseURL alone would never revoke such a session when
    // its token chain is lost. Watch the chain too and revoke as soon as the gate is
    // no longer satisfied.
    [[SNTKVOManager alloc]
        initWithObject:configurator_
              selector:@selector(pushTokenChain)
                  type:[NSArray class]
              callback:^(NSArray* oldValue, NSArray* newValue) {
                // Ignore no-op fires. pushTokenChain is a KVO dependent key on the
                // whole syncState, so every syncState write fires this callback even
                // when the chain itself is unchanged. Without this guard the Revoke()
                // below -> WriteRevokePolicy() -> setSyncServerModeTransition: would
                // rewrite syncState and synchronously re-enter this callback, re-taking
                // lock_ and deadlocking. The re-entrant fire always carries an unchanged
                // chain (old == new), so the equality check breaks the cycle while still
                // acting on a genuine chain change.
                if ((!newValue && !oldValue) || [newValue isEqualToArray:oldValue]) {
                  return;
                }
                if (auto strong_self = weak_self.lock()) {
                  if (!strong_self->SyncServerGateSatisfied() &&
                      strong_self->Revoke(strong_self->LeaveReasonSyncServerChanged())) {
                    LOGI(@"Timed sync session revoked due to sync-v2 gate no longer being "
                         @"satisfied.");
                  }
                }
              }],
  ];

  absl::MutexLock lock(lock_);
  NSDictionary* state = [configurator_ savedTimedSessionStateForKey:StateKey()];
  if (!state) {
    // Clean startup: no session was ever persisted. GetSecondsRemainingFromStateLocked
    // would return 0 here just as it does for an expired/reboot session, so guard on
    // the raw state to keep the no-state case a genuine no-op instead of emitting a
    // spurious leave notification. There is nothing to revert (the in-memory effect is
    // already clear on a fresh daemon start; a subclass whose effect outlives the
    // daemon must reconcile that in ReapplyEffectOnRestart / its own startup path
    // rather than rely on an incidental revert here).
    return;
  }
  uint32_t secs_remaining = static_cast<uint32_t>(
      std::min(GetSecondsRemainingFromStateLocked(state, [SNTSystemInfo bootSessionUUID],
                                                  configurator_.syncBaseURL),
               static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())));

  if (secs_remaining < kMinAllowedStateRemainingSeconds) {
    // Not resumable. The reboot/expiry leave audit (and sync-change revoke policy)
    // were already produced by GetSecondsRemainingFromStateLocked. Actively revert
    // the effect (TMM: clear the flag, a no-op on a fresh boot; TAM: remove the
    // user from the admin group), clear persisted + extra state, notify the GUI.
    if (RevertEffect()) {
      [configurator_ persistTimedSessionState:nil forKey:StateKey()];
    } else {
      PersistExpiredForRetryLocked();
    }
    NotifyLeave();
    ClearExtraState();
    return;
  }

  // Still valid. Re-establish the effect. The subclass decides whether to resume:
  // TMM always re-applies its in-memory flag; TAM verifies the user is still a
  // group member and ends the session instead of re-adding if it was revoked out
  // of band.
  if (ReapplyEffectOnRestart()) {
    BeginSessionLocked(secs_remaining, /*gen_uuid_on_start=*/false);
    EmitAudit(BuildEnterAuditEvent([current_uuid_ UUIDString], secs_remaining, EnterReasonRestart(),
                                   @""));
  } else {
    // Still time-valid, but the subclass declined to re-apply its effect on
    // restart (TAM: the user is no longer an admin-group member, i.e. the
    // elevation was removed out of band). This is provably not a reboot -- a
    // reboot mismatches the boot-session UUID and is handled above -- so it is
    // recorded with an unattributed reason rather than Reboot.
    EmitAudit(BuildLeaveAuditEvent([current_uuid_ UUIDString], LeaveReasonUnspecified()));
    [configurator_ persistTimedSessionState:nil forKey:StateKey()];
    NotifyLeave();
    ClearExtraState();
  }
}

// When reading persisted session state, all of the following must hold, otherwise
// the state is discarded (return 0):
//   0. All types must meet expectations.
//   1. The saved boot session UUID must match the current boot session UUID.
//   2. The saved sync URL must match the current SyncBaseURL.
//   3. The current SyncBaseURL must be pinned (sync v2 enabled).
//   4. The saved session UUID must be a valid UUID.
//
// The boot-UUID check is evaluated BEFORE the deadline: `Deadline` is a
// mach_continuous_time value whose time base resets on reboot, so comparing a
// previous boot's deadline against the current clock is meaningless. For TMM a
// mis-ordering is benign; for TAM it would mean failing to demote. This ordering
// is load-bearing.
uint64_t TimedSyncSession::GetSecondsRemainingFromStateLocked(NSDictionary* state,
                                                              NSString* current_boot_uuid,
                                                              NSURL* sync_url) {
  if (![state[kTimedSessionBootUUIDKey] isKindOfClass:[NSString class]] ||
      ![state[kTimedSessionDeadlineKey] isKindOfClass:[NSNumber class]] ||
      ![state[kTimedSessionSyncURLKey] isKindOfClass:[NSString class]] ||
      ![state[kTimedSessionSessionUUIDKey] isKindOfClass:[NSString class]]) {
    return 0;
  }

  NSUUID* saved_uuid = [[NSUUID alloc] initWithUUIDString:state[kTimedSessionSessionUUIDKey]];
  if (!saved_uuid) {
    return 0;
  }
  current_uuid_ = saved_uuid;

  // Restore + validate subclass extra state BEFORE any RevertEffect/audit, so the
  // leave paths target the right user / never audit a blank one. Load-bearing.
  if (!RestoreAndValidateExtraState(state)) {
    return 0;
  }

  if (![state[kTimedSessionBootUUIDKey] isEqualToString:current_boot_uuid]) {
    // Reboot detected.
    EmitAudit(BuildLeaveAuditEvent([current_uuid_ UUIDString], LeaveReasonReboot()));
    return 0;
  }

  if (![state[kTimedSessionSyncURLKey] isEqualToString:sync_url.host] ||
      !configurator_.isSyncV2Enabled) {
    // SyncBaseURL changed or is no longer pinned. Revoke eligibility. (No leave
    // audit here: as in the prior TMM behavior, no session was active in memory
    // yet at reconciliation time.)
    WriteRevokePolicy();
    return 0;
  }

  NSNumber* deadline = state[kTimedSessionDeadlineKey];
  std::optional<uint64_t> secs_remaining = SecondsRemaining([deadline unsignedLongLongValue]);
  if (secs_remaining.has_value()) {
    deadline_ = [deadline unsignedLongLongValue];
    return *secs_remaining;
  }

  EmitAudit(BuildLeaveAuditEvent([current_uuid_ UUIDString], LeaveReasonSessionExpired()));
  return 0;
}

bool TimedSyncSession::SyncServerGateSatisfied() {
  return configurator_.isSyncV2Enabled;
}

bool TimedSyncSession::Available() {
  return HasOnDemandPolicy() && SyncServerGateSatisfied() && ExtraPreconditions();
}

TimedSyncSession::GrantOutcome TimedSyncSession::BeginGrant(NSNumber* requested_duration,
                                                            uint32_t* out_minutes) {
  // Granular availability sub-checks (before the off-lock auth).
  if (!HasOnDemandPolicy()) {
    return GrantOutcome::kNoPolicy;
  }
  if (!SyncServerGateSatisfied()) {
    return GrantOutcome::kInvalidSyncServer;
  }
  if (!ExtraPreconditions()) {
    return GrantOutcome::kNotEligible;
  }

  // Authorization runs OFF lock_ (Touch ID + typing a reason). Wrap it with a
  // fail-closed timeout so a hung GUI cannot hold grant_mutex_ indefinitely.
  __block BOOL authenticated = NO;
  __block NSString* reason = nil;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  RequestAuthorization(^(BOOL ok, NSString* r) {
    authenticated = ok;
    reason = r;
    dispatch_semaphore_signal(sema);
  });
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, kAuthTimeoutNSec)) != 0) {
    LOGW(@"Timed sync session authorization timed out; failing closed.");
    return GrantOutcome::kAuthFailed;
  }

  if (reason.length > kMaxReasonLength) {
    reason = [reason substringToIndex:kMaxReasonLength];
  }

  if (PolicyRequiresAuth() && !authenticated) {
    return GrantOutcome::kAuthFailed;
  }
  if (PolicyRequiresJustification() && reason.length == 0) {
    return GrantOutcome::kJustificationRequired;
  }

  // Re-check availability after the auth window: a sync Revoke that arrived while
  // the user was authenticating must not be elevated against.
  if (!Available()) {
    return GrantOutcome::kNotEligible;
  }

  uint32_t minutes = ClampDuration(requested_duration);

  absl::MutexLock lock(lock_);
  NSError* err = nil;
  if (!ApplyEffect(&err)) {
    LOGE(@"Timed sync session failed to apply effect: %@", err.localizedDescription);
    return GrantOutcome::kApplyFailed;
  }
  bool new_session = BeginSessionLocked(minutes * 60, /*gen_uuid_on_start=*/true);
  EmitAudit(BuildEnterAuditEvent(
      [current_uuid_ UUIDString], static_cast<uint32_t>(SecondsRemaining(deadline_).value_or(0)),
      new_session ? EnterReasonOnDemand() : EnterReasonRefresh(), reason ?: @""));
  *out_minutes = minutes;
  return GrantOutcome::kGranted;
}

std::optional<uint64_t> TimedSyncSession::SecondsRemaining() const {
  absl::ReaderMutexLock lock(lock_);
  if (active_) {
    return SecondsRemaining(deadline_);
  }
  return std::nullopt;
}

std::optional<uint64_t> TimedSyncSession::SecondsRemaining(uint64_t deadline_mach_time) {
  uint64_t current_mach_time = mach_continuous_time();
  if (deadline_mach_time <= current_mach_time) {
    return std::nullopt;
  }
  return MachTimeToNanos(deadline_mach_time - current_mach_time) / NSEC_PER_SEC;
}

bool TimedSyncSession::BeginSessionLocked(uint32_t seconds, bool gen_uuid_on_start) {
  bool did_start_new_timer = StartTimerWithInterval(seconds);
  if (did_start_new_timer && gen_uuid_on_start) {
    current_uuid_ = [NSUUID UUID];
  }

  uint64_t deadline = AddNanosecondsToMachTime(seconds * NSEC_PER_SEC, mach_continuous_time());

  NSMutableDictionary* state = [@{
    kTimedSessionBootUUIDKey : [SNTSystemInfo bootSessionUUID],
    kTimedSessionDeadlineKey : @(deadline),
    // syncBaseURL.host is nil when sync v2 is satisfied via the push token chain
    // rather than a pinned URL. Store "" so the literal never receives nil; on
    // restart it won't match a real host, so the session fails closed.
    kTimedSessionSyncURLKey : configurator_.syncBaseURL.host ?: @"",
    kTimedSessionSessionUUIDKey : [current_uuid_ UUIDString],
  } mutableCopy];
  [state addEntriesFromDictionary:ExtraStateToPersist()];
  [configurator_ persistTimedSessionState:state forKey:StateKey()];

  deadline_ = deadline;
  active_ = true;

  NotifyEnter([NSDate dateWithTimeIntervalSinceNow:seconds]);

  return did_start_new_timer;
}

bool TimedSyncSession::EndSessionLocked() {
  if (StopTimer()) {
    [configurator_ persistTimedSessionState:nil forKey:StateKey()];
    active_ = false;
    NotifyLeave();
    return true;
  }
  return false;
}

void TimedSyncSession::PersistExpiredForRetryLocked() {
  // The effect revert failed, so the effect (e.g. TAM admin-group membership) may
  // still be in place. Rather than clearing the persisted state — which would leave
  // the effect stuck on with nothing tracking it — persist an already-expired session
  // record. On the next daemon start, reconciliation reads it, finds it non-resumable
  // (deadline in the past, or a reboot/sync change), and calls RevertEffect again,
  // retrying until the revert succeeds.
  LOGE(@"Timed sync session revert failed; persisting an expired session record so the "
       @"next daemon start retries the revert.");
  NSMutableDictionary* state = [@{
    kTimedSessionBootUUIDKey : [SNTSystemInfo bootSessionUUID],
    kTimedSessionDeadlineKey : @0,  // already in the past -> non-resumable -> retry revert
    kTimedSessionSyncURLKey : configurator_.syncBaseURL.host ?: @"",
    kTimedSessionSessionUUIDKey : current_uuid_ ? [current_uuid_ UUIDString]
                                                : [[NSUUID UUID] UUIDString],
  } mutableCopy];
  [state addEntriesFromDictionary:ExtraStateToPersist()];
  [configurator_ persistTimedSessionState:state forKey:StateKey()];
}

bool TimedSyncSession::EndForReasonLocked(NSInteger leave_reason) {
  if (EndSessionLocked()) {
    // EndSessionLocked already cleared the persisted state; if the revert fails,
    // re-persist an expired record so the next daemon start retries the revert.
    if (!RevertEffect()) {
      PersistExpiredForRetryLocked();
    }
    EmitAudit(BuildLeaveAuditEvent([current_uuid_ UUIDString], leave_reason));
    ClearExtraState();
    current_uuid_ = nil;
    return true;
  }
  return false;
}

bool TimedSyncSession::Cancel() {
  absl::MutexLock lock(lock_);
  return EndForReasonLocked(LeaveReasonCancelled());
}

bool TimedSyncSession::Revoke(NSInteger leave_reason) {
  absl::MutexLock lock(lock_);
  return RevokeLocked(leave_reason);
}

bool TimedSyncSession::RevokeLocked(NSInteger leave_reason) {
  // A revoke is a teardown that additionally records the revoke policy; the
  // teardown itself is shared with EndForReasonLocked so the two cannot diverge.
  WriteRevokePolicy();
  return EndForReasonLocked(leave_reason);
}

bool TimedSyncSession::OnTimer() {
  absl::MutexLock lock(lock_);
  // OnTimer fires only for a running timer, so a session is active. The Timer
  // mixin (trailing edge) has already stopped the timer; just tear down the
  // session state here.
  if (RevertEffect()) {
    [configurator_ persistTimedSessionState:nil forKey:StateKey()];
  } else {
    PersistExpiredForRetryLocked();
  }
  active_ = false;
  NotifyLeave();
  EmitAudit(BuildLeaveAuditEvent([current_uuid_ UUIDString], LeaveReasonSessionExpired()));
  ClearExtraState();
  current_uuid_ = nil;

  // Don't restart the timer.
  return false;
}

bool TimedSyncSession::StartTimer() {
  return Timer<TimedSyncSession>::StartTimer();
}

bool TimedSyncSession::StartTimerWithInterval(uint32_t interval_seconds) {
  return Timer<TimedSyncSession>::StartTimerWithInterval(interval_seconds);
}

bool TimedSyncSession::StopTimer() {
  return Timer<TimedSyncSession>::StopTimer();
}

}  // namespace santa
