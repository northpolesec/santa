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

#ifndef SANTA_SANTAD_TIMEDSYNCSESSION_H
#define SANTA_SANTAD_TIMEDSYNCSESSION_H

#include <memory>
#include <optional>

#import <Foundation/Foundation.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKVOManager.h"
#include "Source/common/Timer.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "absl/synchronization/mutex.h"

// Common persisted session-state keys, shared by every TimedSyncSession feature.
// The top-level state-dict key is provided per-feature via the StateKey() hook.
extern NSString* const kTimedSessionBootUUIDKey;
extern NSString* const kTimedSessionDeadlineKey;
extern NSString* const kTimedSessionSyncURLKey;
extern NSString* const kTimedSessionSessionUUIDKey;

namespace santa {

// Base for a timer-bounded, sync-blessed, self-reverting session (Temporary
// Monitor Mode, Temporary Admin Mode). Owns the timer, the persisted common
// state, reconciliation (including the load-bearing boot-UUID-before-deadline
// ordering and the sync-pin gate), and the grant/cancel/revoke/expiry skeleton.
// All per-feature behavior is provided through the virtual hooks below.
//
// Threading: `grant_mutex_` serializes a whole grant (pre-checks + auth + apply)
// against other grants; `lock_` guards the session fields. Ordering is always
// `grant_mutex_` then `lock_`; nothing takes `grant_mutex_` while holding `lock_`,
// so there is no inversion. Fast readers (SecondsRemaining/Available) take only
// `lock_` and read the `active_` flag rather than Timer::IsStarted(), which
// dispatch_syncs to the timer queue and would deadlock against a firing OnTimer.
class TimedSyncSession : public Timer<TimedSyncSession> {
 public:
  ~TimedSyncSession() override;

  TimedSyncSession(TimedSyncSession&&) = delete;
  TimedSyncSession& operator=(TimedSyncSession&&) = delete;
  TimedSyncSession(const TimedSyncSession&) = delete;
  TimedSyncSession& operator=(const TimedSyncSession&) = delete;

  // Cancel an active session (user-initiated "leave"). Returns true if a session
  // was active.
  bool Cancel();

  // Revoke an active session and write the revoke policy. `leave_reason` is the
  // subclass's leave-reason enum value used for the audit event. Returns true if
  // a session was active.
  bool Revoke(NSInteger leave_reason);

  // Timer<> expiry callback (base implements; subclasses do not override).
  bool OnTimer();

  // Whether the feature is currently available: an on-demand policy is set, the
  // sync server is enabled, and any extra preconditions hold. Granular failure
  // reasons for a denied request are produced by BeginGrant's GrantOutcome.
  bool Available();

  // Seconds remaining in the active session, or nullopt if none.
  std::optional<uint64_t> SecondsRemaining() const;
  static std::optional<uint64_t> SecondsRemaining(uint64_t deadline_mach_time);

  // Outcome of a grant attempt. The base produces these; the subclass maps them
  // to its own NSError codes (and, for TAM, a Denied audit event), so the base
  // stays feature-agnostic.
  enum class GrantOutcome {
    kGranted,
    kNoPolicy,
    kInvalidSyncServer,
    kNotEligible,
    kAuthFailed,
    kJustificationRequired,
    kApplyFailed,
  };

 protected:
  TimedSyncSession(uint32_t min_minutes, uint32_t max_minutes, const char* label,
                   SNTConfigurator* configurator, SNTNotificationQueue* notification_queue);

  // Run reconciliation against the persisted state (call once, post-construction,
  // from the subclass factory). Installs the syncBaseURL KVO watcher.
  void SetupFromState();

  // Shared grant flow. MUST be called with `grant_mutex_` held by the subclass's
  // public request method (held across the whole flow, including the off-lock auth
  // callback, so two grants cannot interleave). On kGranted, *out_minutes is the
  // granted duration.
  GrantOutcome BeginGrant(NSNumber* requested_duration, uint32_t* out_minutes)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(grant_mutex_) ABSL_LOCKS_EXCLUDED(lock_);

  // Reads the lock_-guarded `active_` flag (NOT Timer::IsStarted()).
  bool IsStartedLocked() const ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) { return active_; }

  // Validate + reconcile the persisted state, returning seconds remaining (0 if the
  // session is not resumable). Emits the reboot/expiry leave audit and writes the
  // revoke policy on a sync-server change. Protected so a test peer can exercise it.
  uint64_t GetSecondsRemainingFromStateLocked(NSDictionary* state, NSString* current_boot_uuid,
                                              NSURL* sync_url) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  // End an active session with the given leave reason WITHOUT writing a revoke policy (the
  // feature stays available for immediate re-entry). Returns whether a session was active.
  bool EndForReasonLocked(NSInteger leave_reason) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  // Persists an already-expired (deadline-0) session record carrying
  // ExtraStateToPersist(). The next daemon start finds it non-resumable and
  // retries RevertEffect. Used by teardown paths when a revert fails, and by
  // subclasses to write a provisional record BEFORE applying an effect
  // (persist-before-flip), which BeginSessionLocked then overwrites.
  void PersistExpiredForRetryLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  // ---- Hooks (subclass provides) ----

  // Apply / revert / re-apply the effect. All run UNDER lock_. Apply may fail
  // (TAM); Revert must be best-effort idempotent. ReapplyEffectOnRestart is called
  // for a still-valid session at daemon start: it returns true to keep the session
  // (the effect is re-established) or false to end it (e.g. TAM: the user is no
  // longer a group member, so the elevation was revoked out of band).
  //
  // RevertEffect returns true on success (or when there is nothing to revert) and
  // false if the revert failed and the effect may still be in place. On false the
  // base keeps an already-expired persisted session record instead of clearing it,
  // so the next daemon start reconciles and retries the revert rather than leaving
  // the effect stuck on with nothing tracking it.
  virtual bool ApplyEffect(NSError** err) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) = 0;
  virtual bool RevertEffect() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) = 0;
  virtual bool ReapplyEffectOnRestart() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) = 0;

  // Extra availability preconditions (TMM: client mode can transition; TAM: none).
  virtual bool ExtraPreconditions() = 0;

  // The top-level SNTConfigurator state-dict key for this feature (TMM: @"TMM";
  // TAM: @"TempAdmin").
  virtual NSString* StateKey() = 0;

  // Policy questions (answered by the subclass using its own policy object).
  virtual bool HasOnDemandPolicy() = 0;
  virtual uint32_t ClampDuration(NSNumber* requested) = 0;
  virtual bool PolicyRequiresAuth() = 0;
  virtual bool PolicyRequiresJustification() = 0;
  virtual void WriteRevokePolicy() = 0;

  // Authenticate the user; reply with success + (TAM) a reason string. The base
  // wraps this with a fail-closed timeout, but implementations MUST invoke `reply`
  // exactly once, including on transport failure (e.g. an absent or dead GUI XPC
  // connection). Otherwise the timeout becomes the only exit and the grant stalls
  // for its full duration instead of failing fast.
  virtual void RequestAuthorization(void (^reply)(BOOL authenticated, NSString* reason)) = 0;

  // Persisted extra state (TAM: TargetUID/Username). Restore returns false if
  // invalid. Restore runs BEFORE any RevertEffect/audit. Clear runs AFTER the
  // leave audit is built (the audit and RevertEffect read the extra state).
  virtual NSDictionary* ExtraStateToPersist() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) = 0;
  virtual bool RestoreAndValidateExtraState(NSDictionary* state)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) = 0;
  virtual void ClearExtraState() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) = 0;

  // Audit-event builders (return an object the subclass's audit sink accepts).
  virtual id BuildEnterAuditEvent(NSString* session_uuid, uint32_t seconds, NSInteger enter_reason,
                                  NSString* user_justification) = 0;
  virtual id BuildLeaveAuditEvent(NSString* session_uuid, NSInteger leave_reason) = 0;

  // Enter-reason / leave-reason values, as the subclass's enum.
  virtual NSInteger EnterReasonOnDemand() = 0;
  virtual NSInteger EnterReasonRefresh() = 0;
  virtual NSInteger EnterReasonRestart() = 0;
  virtual NSInteger LeaveReasonCancelled() = 0;
  virtual NSInteger LeaveReasonSessionExpired() = 0;
  virtual NSInteger LeaveReasonReboot() = 0;
  virtual NSInteger LeaveReasonSyncServerChanged() = 0;
  // Reason for a still-valid session whose effect the subclass declined to
  // re-apply at daemon restart (not a reboot; the reboot case is handled by the
  // boot-UUID check). Reported upstream as REASON_UNSPECIFIED.
  virtual NSInteger LeaveReasonUnspecified() = 0;

  // Deliver the audit event + GUI notifications.
  virtual void EmitAudit(id audit_event) = 0;
  virtual void NotifyEnter(NSDate* expiration) = 0;
  virtual void NotifyLeave() = 0;

  // Require at least this many seconds remaining to resume a session on restart.
  static constexpr uint64_t kMinAllowedStateRemainingSeconds = 5;

  mutable absl::Mutex grant_mutex_;
  mutable absl::Mutex lock_;
  SNTConfigurator* configurator_;
  SNTNotificationQueue* notification_queue_;
  uint64_t deadline_ ABSL_GUARDED_BY(lock_);
  NSUUID* current_uuid_ ABSL_GUARDED_BY(lock_);
  bool active_ ABSL_GUARDED_BY(lock_);
  NSArray<SNTKVOManager*>* kvo_;

 private:
  // Persist the common session state (merged with ExtraStateToPersist), start the
  // timer, notify the GUI, set `active_`. Returns whether a NEW timer was started
  // (false on a refresh of an already-running session).
  bool BeginSessionLocked(uint32_t seconds, bool gen_uuid_on_start)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);
  // Stop the timer, clear the persisted state, notify the GUI, clear `active_`.
  // Returns whether a genuinely-active session was ended. Does NOT clear the
  // subclass extra state (the leave audit/RevertEffect read it).
  bool EndSessionLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);
  bool RevokeLocked(NSInteger leave_reason) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  // Whether the sync-server gate is satisfied (`configurator_.isSyncV2Enabled`).
  bool SyncServerGateSatisfied();

  // hide the base class Start/Stop methods
  bool StartTimer();
  bool StopTimer();
  bool StartTimerWithInterval(uint32_t interval_seconds);
};

}  // namespace santa

#endif  // SANTA_SANTAD_TIMEDSYNCSESSION_H
