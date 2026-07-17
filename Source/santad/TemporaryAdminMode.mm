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

#include "Source/santad/TemporaryAdminMode.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCNotifierInterface.h"

namespace santa {

static NSString* const kTAMTargetUsernameKey = @"TargetUsername";
static NSString* const kTAMTargetUUIDKey = @"TargetUUID";
static NSString* const kTAMTargetLocalKey = @"TargetLocal";
static NSString* const kTAMRetryCountKey = @"TargetRetryCount";

// An expired session whose revert failed is retried once per daemon start. For
// an unresolvable DIRECTORY account -- indistinguishable from a deleted one
// through this seam -- give up after this many attempts and consume the record,
// so a permanently-deleted account cannot wedge every future grant on the
// machine. See docs/2026-07-18-tam-bounded-revert-retry-design.md.
static constexpr uint32_t kMaxRevertRetries = 5;

std::shared_ptr<TemporaryAdminMode> TemporaryAdminMode::Create(
    SNTConfigurator* configurator, SNTNotificationQueue* notification_queue,
    std::unique_ptr<AdminGroupMembership> membership,
    HandleAuditEventBlock handle_audit_event_block) {
  auto tam = std::make_shared<TemporaryAdminMode>(PassKey(), configurator, notification_queue,
                                                  std::move(membership), handle_audit_event_block);
  // NB: SetupFromState is split out of the constructor since it could start the
  // timer, which takes a weak reference that must not be taken before construction
  // is complete.
  tam->SetupFromState();
  return tam;
}

TemporaryAdminMode::TemporaryAdminMode(PassKey, SNTConfigurator* configurator,
                                       SNTNotificationQueue* notification_queue,
                                       std::unique_ptr<AdminGroupMembership> membership,
                                       HandleAuditEventBlock handle_audit_event_block)
    : TimedSyncSession(kMinTemporaryAdminMinutes, kMaxTemporaryAdminMinutes, "Temporary Admin Mode",
                       configurator, notification_queue),
      membership_(std::move(membership)),
      handle_audit_event_block_([handle_audit_event_block copy]),
      target_uid_(0),
      target_is_local_(false),
      revert_retries_(0) {}

bool TemporaryAdminMode::IsCurrentlyAdmin(uid_t uid) {
  return membership_->IsMember(uid);
}

uint32_t TemporaryAdminMode::RequestMinutes(NSNumber* requested_duration, uid_t uid,
                                            NSString* username, NSError** err) {
  // Serialize the whole grant (pre-checks + auth + apply) against other grants so
  // two concurrent requests cannot both pass the single-session / already-admin
  // checks and leave an untracked, never-reverting elevation. grant_mutex_ does not
  // block the fast readers (SecondsRemaining / Available use lock_ only).
  absl::MutexLock grant_lock(grant_mutex_);

  // uid 0 is already fully privileged, and RevertEffect / RestoreAndValidateExtraState
  // treat a target_uid_ of 0 as "no session" -- so a session must never be stored for it
  // (it could never be reverted). Reject before any state is touched.
  if (uid == 0) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTAMAlreadyAdmin
                     format:@"This user is already an administrator."];
    EmitDenied(username, SNTTemporaryAdminModeDeniedReasonAlreadyAdmin);
    return 0;
  }

  if (!Available()) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTAMNoPolicy
                     format:@"This machine does not currently allow admin elevation."];
    EmitDenied(username, SNTTemporaryAdminModeDeniedReasonNoPolicy);
    return 0;
  }

  // TAM-specific pre-checks (single session / natural admin). Atomic with the grant
  // below because grant_mutex_ is held across the whole method.
  bool is_refresh = false;
  {
    absl::MutexLock lock(lock_);
    if (IsStartedLocked()) {
      if (target_uid_ != uid) {
        [SNTError populateError:err
                       withCode:SNTErrorCodeTAMSessionAlreadyActive
                         format:@"A temporary admin session is already active for another user."];
        EmitDenied(username, SNTTemporaryAdminModeDeniedReasonSessionAlreadyActive);
        return 0;
      }
      // Same uid with an active session -> refresh (target already set).
      is_refresh = true;
    } else if (membership_->IsMember(uid)) {
      // Natural admin with no active session -> never record a session for them.
      [SNTError populateError:err
                     withCode:SNTErrorCodeTAMAlreadyAdmin
                       format:@"This user is already an administrator."];
      EmitDenied(username, SNTTemporaryAdminModeDeniedReasonAlreadyAdmin);
      return 0;
    } else {
      target_uid_ = uid;
      target_username_ = username;
    }
  }

  uint32_t minutes = 0;
  GrantOutcome outcome = BeginGrant(requested_duration, &minutes);
  if (outcome == GrantOutcome::kGranted) {
    return minutes;
  }

  // Failure. Defense-in-depth (review H4): clear the freshly-stashed target so no
  // leave path can later act on it. A refresh leaves the original active session's
  // target intact (it is still elevated).
  if (!is_refresh) {
    absl::MutexLock lock(lock_);
    ClearExtraState();
  }

  switch (outcome) {
    case GrantOutcome::kAuthFailed:
      [SNTError populateError:err
                     withCode:SNTErrorCodeTAMAuthFailed
                       format:@"Authorization failed."];
      EmitDenied(username, SNTTemporaryAdminModeDeniedReasonAuthFailed);
      return 0;
    case GrantOutcome::kJustificationRequired:
      [SNTError populateError:err
                     withCode:SNTErrorCodeTAMJustificationRequired
                       format:@"A justification is required to elevate."];
      EmitDenied(username, SNTTemporaryAdminModeDeniedReasonJustificationRequired);
      return 0;
    case GrantOutcome::kApplyFailed:
      [SNTError populateError:err
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"Failed to change admin group membership."];
      EmitDenied(username, SNTTemporaryAdminModeDeniedReasonMembershipChangeFailed);
      return 0;
    default:  // kNoPolicy / kInvalidSyncServer / kNotEligible (raced with Available)
      [SNTError populateError:err withCode:SNTErrorCodeTAMNoPolicy format:@"Not eligible."];
      EmitDenied(username, SNTTemporaryAdminModeDeniedReasonNotEligible);
      return 0;
  }
}

bool TemporaryAdminMode::EndForUserEvent(uid_t uid, NSString* username,
                                         SNTTemporaryAdminModeLeaveReason reason) {
  absl::MutexLock lock(lock_);
  if (!IsStartedLocked()) {
    return false;
  }
  // Match on either key. Each trigger has one trustworthy identifier and one derived one: the ES
  // lock/logout path has the login username but a getpwnam-derived (fallible) uid, while the
  // fast-user-switch path has the audit-token uid but no username. Accepting either lets a session
  // be ended even when the derived key is missing (uid 0) or collides (local vs directory account).
  // The length guards must precede the compare: -[nil caseInsensitiveCompare:] returns
  // NSOrderedSame and would otherwise false-match.
  bool uid_match = (uid != 0 && uid == target_uid_);
  bool name_match = (username.length > 0 && target_username_.length > 0 &&
                     [username caseInsensitiveCompare:target_username_] == NSOrderedSame);
  if (!uid_match && !name_match) {
    return false;
  }
  return EndForReasonLocked((NSInteger)reason);
}

void TemporaryAdminMode::NewPolicyReceived(SNTTemporaryAdminPolicy* policy) {
  if (policy.type == SNTTemporaryAdminPolicyTypeRevoke) {
    if (Revoke(SNTTemporaryAdminModeLeaveReasonRevoked)) {
      LOGI(@"Temporary Admin Mode session revoked due to policy change.");
    }
  }
  [[notification_queue_.notifierConnection remoteObjectProxy]
      temporaryAdminModeAvailable:Available()];
}

#pragma mark Hooks

// Effect hooks run UNDER lock_ (the base invokes them while holding lock_).
// Annotated here (unlike the sibling hooks) because the body calls the
// lock_-guarded PersistExpiredForRetryLocked(); the annotation matches the base
// pure-virtual and lets thread-safety analysis see the lock is already held.
bool TemporaryAdminMode::ApplyEffect(NSError** err) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_) {
  // The pre-checked target can vanish while BeginGrant's authorization window
  // runs off lock_: an expiry, screen lock, or revoke ends the session and
  // zeroes target_uid_. uid 0 is never a valid session target (RevertEffect
  // treats it as "no session"), so refuse the grant rather than elevating
  // root under a record that could never be reverted.
  if (target_uid_ == 0) {
    [SNTError populateError:err
                   withCode:SNTErrorCodeTAMMembershipChangeFailed
                     format:@"The session ended during authorization."];
    return false;
  }
  // Persist-before-flip: name the target on disk before the elevation, so a
  // crash between the two leaves a deadline-0 record the next daemon start
  // reverts — never an elevated user with no on-disk state. It also
  // guarantees AdminUserState's capture exclusion sees the target: capture
  // reads membership first and TAM state second, so member-visible implies
  // state-visible. BeginSessionLocked overwrites this record immediately
  // after a successful add.
  //
  // A refresh already has all of that: the live session's record is on disk,
  // and the elevation it tracks stays owed even if the refresh fails. Leave
  // it alone — overwriting it and then clearing it on failure would leave an
  // elevated user with no record, which a daemon restart would turn into a
  // permanent untracked admin.
  bool is_refresh = IsStartedLocked();
  if (!is_refresh) {
    // Capture the account's stable identity BEFORE the provisional record is
    // written: the UUID is the rename-proof key the revert paths use to detect
    // uid reuse, and the Local bit is what lets the revert of a deleted LOCAL
    // account terminate instead of retrying forever. Best-effort — if the
    // identity does not resolve here, the record carries no UUID and the
    // revert paths fall back to always attempting the demotion.
    target_uuid_ = membership_->UUIDForUID(target_uid_);
    target_is_local_ = membership_->IsLocalAccount(target_uid_);
    PersistExpiredForRetryLocked();
  }
  if (!membership_->AddMember(target_uid_, err)) {
    if (!is_refresh) {
      // The elevation never happened; nothing is owed. Clear the provisional
      // record so it cannot refuse future grants as a stale residue.
      [configurator_ persistTimedSessionState:nil forKey:StateKey()];
    }
    return false;
  }
  return true;
}

bool TemporaryAdminMode::RevertEffect() {
  if (target_uid_ == 0) {
    // No session target -> nothing to revert.
    return true;
  }
  // Single up-front resolution probe. Both the uid-reuse guard and the
  // deleted-local consume below key off this one piece of evidence, so the
  // consume can never fire for an account this same pass proved to exist.
  NSString* current_uuid = membership_->UUIDForUID(target_uid_);
  // uid-reuse guard: if the uid now resolves to a DIFFERENT account than was
  // elevated (unique identifiers differ), the elevated account was deleted
  // and its uid reallocated. There is no elevation left to revert, and the
  // new holder of the uid must never be demoted by this record. Matching on
  // the GeneratedUID rather than the username makes this rename-resistant: a
  // rename preserves the UUID, and rewriting a GeneratedUID requires root —
  // an actor who could equally re-add themselves after any demotion.
  if (target_uuid_.length && current_uuid.length && ![current_uuid isEqualToString:target_uuid_]) {
    LOGW(@"Temporary Admin Mode: uid %u now resolves to a different account "
         @"(recorded UUID %@, current UUID %@); treating the recorded "
         @"elevation as already removed.",
         target_uid_, target_uuid_, current_uuid);
    return true;
  }
  NSError* err = nil;
  if (!membership_->RemoveMember(target_uid_, &err)) {
    if (err.code == SNTErrorCodeTAMNoConsoleUser && current_uuid == nil) {
      // RemoveMember reports group-resolution failures as
      // MembershipChangeFailed, so NoConsoleUser means the admin group
      // resolved but this account did not. The probe above agreeing (nil)
      // rules out a flap inside RemoveMember's own resolution.
      if (target_is_local_) {
        // A LOCAL account that no longer resolves was deleted: nothing left to
        // demote. Consume the record so it cannot block future grants forever.
        //
        // Deleting the user does not scrub group records (they hold members by
        // name and UUID), so a stale name entry can persist past this consume;
        // that artifact is not reachable through this seam.
        LOGW(@"Temporary Admin Mode: local uid %u (recorded UUID %@) no longer "
             @"resolves; treating the recorded elevation as already removed.",
             target_uid_, target_uuid_);
        return true;
      }
      // A DIRECTORY account that does not resolve is ambiguous: deleted, or
      // merely off-network. Retry a bounded number of daemon starts so a
      // genuinely-deleted account cannot wedge future grants forever, but give
      // an off-network account several starts to return. Abandoning an account
      // that was only unreachable leaves it an untracked admin until it
      // resolves again -- an accepted, narrow trade against a permanent wedge.
      if (++revert_retries_ >= kMaxRevertRetries) {
        LOGW(@"Temporary Admin Mode: abandoning demotion of uid %u after %u "
             @"attempts; if this account is only unreachable it will retain "
             @"admin until it resolves again.",
             target_uid_, revert_retries_);
        return true;
      }
      LOGE(@"Temporary Admin Mode: uid %u did not resolve; will retry demotion "
           @"(attempt %u of %u).",
           target_uid_, revert_retries_, kMaxRevertRetries);
      return false;
    }
    // A systemic group-resolution failure or any other error: keep the expired
    // record and retry on the next daemon start rather than clearing state and
    // leaving the user elevated. A still-present admin is never abandoned
    // during a directory-wide outage.
    LOGE(@"Temporary Admin Mode failed to demote uid %u: %@", target_uid_,
         err.localizedDescription);
    return false;
  }
  return true;
}

bool TemporaryAdminMode::ReapplyEffectOnRestart() {
  // IsMember() cannot distinguish "resolved and not a member" from "identity
  // did not resolve" (directory outage / off-network directory account), and
  // only the former proves an out-of-band revocation. Probe resolution first:
  // an unresolvable identity resumes the session so the elevation stays
  // tracked, and the timer (or the next daemon start) reverts it once the
  // directory answers.
  NSString* current_uuid = membership_->UUIDForUID(target_uid_);
  if (current_uuid == nil) {
    LOGW(@"Temporary Admin Mode: uid %u did not resolve at restart; resuming the "
         @"session without membership verification.",
         target_uid_);
    return true;
  }
  if (target_uuid_.length && ![current_uuid isEqualToString:target_uuid_]) {
    // The uid was reallocated to a different account: the elevated account no
    // longer exists, so there is nothing to track — and the new holder must
    // not inherit (or be demoted out of) this session. Declining routes
    // through the base's no-revert teardown.
    LOGI(@"Temporary Admin Mode: uid %u now resolves to a different account "
         @"(recorded UUID %@, current UUID %@); ending the persisted session.",
         target_uid_, target_uuid_, current_uuid);
    return false;
  }
  // If the user is no longer a member, the elevation was revoked out of band
  // (admin/MDM/another tool). Do not re-add — end the session instead.
  if (!membership_->IsMember(target_uid_)) {
    // IsMember resolves the identity again, and it has no error channel: a
    // directory flap between the probe above and this query also reads as
    // "not a member". Only trust the negative while the identity still
    // resolves; otherwise resume so the elevation stays tracked.
    if (membership_->UUIDForUID(target_uid_) == nil) {
      LOGW(@"Temporary Admin Mode: uid %u stopped resolving during restart "
           @"verification; resuming the session without membership verification.",
           target_uid_);
      return true;
    }
    LOGI(@"Temporary Admin Mode: persisted session for uid %u is no longer a group member; "
         @"treating as revoked out of band and ending the session.",
         target_uid_);
    return false;
  }
  // Still a member: AddMember is idempotent. A failure here is logged and ignored —
  // membership persists and the timer still resumes.
  NSError* err = nil;
  if (!membership_->AddMember(target_uid_, &err)) {
    LOGW(@"Temporary Admin Mode: restart re-apply for uid %u failed: %@", target_uid_,
         err.localizedDescription);
  }
  return true;
}

bool TemporaryAdminMode::ExtraPreconditions() {
  return true;
}

NSString* TemporaryAdminMode::StateKey() {
  return kStateTempAdminModeKey;
}

bool TemporaryAdminMode::HasOnDemandPolicy() {
  return [configurator_ temporaryAdminPolicy].type == SNTTemporaryAdminPolicyTypeOnDemand;
}

uint32_t TemporaryAdminMode::ClampDuration(NSNumber* requested) {
  return [[configurator_ temporaryAdminPolicy] getDurationMinutes:requested];
}

bool TemporaryAdminMode::PolicyRequiresAuth() {
  // Authentication is always required to elevate; it is not server-configurable.
  return true;
}

bool TemporaryAdminMode::PolicyRequiresJustification() {
  SNTTemporaryAdminPolicy* p = [configurator_ temporaryAdminPolicy];
  return p ? p.requireJustification : YES;
}

void TemporaryAdminMode::WriteRevokePolicy() {
  [configurator_
      setSyncServerTemporaryAdminPolicy:[[SNTTemporaryAdminPolicy alloc] initRevocation]];
}

void TemporaryAdminMode::RequestAuthorization(void (^reply)(BOOL, NSString*)) {
  // Tell the GUI whether the policy requires a free-text reason so it only prompts
  // when configured to. The daemon still enforces the requirement (an empty reason
  // is rejected with kJustificationRequired when PolicyRequiresJustification() is true).
  [notification_queue_
      authorizeTemporaryAdminModeRequiringJustification:PolicyRequiresJustification()
                                                  reply:^(BOOL ok, NSString* reason) {
                                                    reply(ok, reason);
                                                  }];
}

NSDictionary* TemporaryAdminMode::ExtraStateToPersist() {
  return @{
    kStateTempAdminTargetUIDKey : @(target_uid_),
    kTAMTargetUsernameKey : target_username_ ?: @"",
    kTAMTargetUUIDKey : target_uuid_ ?: @"",
    kTAMTargetLocalKey : @(target_is_local_),
    kTAMRetryCountKey : @(revert_retries_),
  };
}

bool TemporaryAdminMode::RestoreAndValidateExtraState(NSDictionary* state) {
  if (![state[kStateTempAdminTargetUIDKey] isKindOfClass:[NSNumber class]] ||
      ![state[kTAMTargetUsernameKey] isKindOfClass:[NSString class]]) {
    return false;
  }
  uid_t uid = [state[kStateTempAdminTargetUIDKey] unsignedIntValue];
  // Reject only uid 0 (never a valid session target; RevertEffect treats it
  // as "no session"). Deliberately NO account-existence probe here: a Darwin
  // passwd lookup has no error channel — a directory outage and a deleted
  // account both surface as "no such account" — so any probe that drops the
  // session on "not found" turns a boot-time outage into a permanently
  // stranded admin. Deleted-vs-unreachable is instead resolved where an error
  // channel exists: RevertEffect / ReapplyEffectOnRestart, through the
  // AdminGroupMembership seam.
  if (uid == 0) {
    return false;
  }
  target_uid_ = uid;
  target_username_ = state[kTAMTargetUsernameKey];
  // Records written before the UUID/Local keys existed restore without them:
  // an empty UUID skips the uid-reuse guard, and Local defaults to NO so an
  // unresolvable account stays retryable. (Deliberately the opposite default
  // from AdminUserState's EntryIsLocal: a missing key there is tampering;
  // here it is also the upgrade path, and defaulting to local would let an
  // off-network directory account's revert be consumed as "deleted".)
  NSString* uuid =
      [state[kTAMTargetUUIDKey] isKindOfClass:[NSString class]] ? state[kTAMTargetUUIDKey] : nil;
  target_uuid_ = uuid.length ? uuid : nil;
  NSNumber* local = state[kTAMTargetLocalKey];
  target_is_local_ = [local isKindOfClass:[NSNumber class]] && local.boolValue;
  // A record written before this change has no count key; restore it as 0, a
  // clean upgrade that simply starts the retry budget fresh.
  NSNumber* retries = state[kTAMRetryCountKey];
  revert_retries_ = [retries isKindOfClass:[NSNumber class]] ? retries.unsignedIntValue : 0;
  return true;
}

void TemporaryAdminMode::ClearExtraState() {
  target_uid_ = 0;
  target_username_ = nil;
  target_uuid_ = nil;
  target_is_local_ = false;
  revert_retries_ = 0;
}

id TemporaryAdminMode::BuildEnterAuditEvent(NSString* session_uuid, uint32_t seconds,
                                            NSInteger enter_reason, NSString* user_justification) {
  return [[SNTStoredTemporaryAdminModeEnterAuditEvent alloc]
           initWithUUID:session_uuid
               username:target_username_ ?: @""
                seconds:seconds
                 reason:(SNTTemporaryAdminModeEnterReason)enter_reason
      userJustification:user_justification ?: @""];
}

id TemporaryAdminMode::BuildLeaveAuditEvent(NSString* session_uuid, NSInteger leave_reason) {
  return [[SNTStoredTemporaryAdminModeLeaveAuditEvent alloc]
      initWithUUID:session_uuid
          username:target_username_ ?: @""
            reason:(SNTTemporaryAdminModeLeaveReason)leave_reason];
}

NSInteger TemporaryAdminMode::EnterReasonOnDemand() {
  return SNTTemporaryAdminModeEnterReasonOnDemand;
}
NSInteger TemporaryAdminMode::EnterReasonRefresh() {
  return SNTTemporaryAdminModeEnterReasonOnDemandRefresh;
}
NSInteger TemporaryAdminMode::EnterReasonRestart() {
  return SNTTemporaryAdminModeEnterReasonRestart;
}
NSInteger TemporaryAdminMode::LeaveReasonCancelled() {
  return SNTTemporaryAdminModeLeaveReasonCancelled;
}
NSInteger TemporaryAdminMode::LeaveReasonSessionExpired() {
  return SNTTemporaryAdminModeLeaveReasonSessionExpired;
}
NSInteger TemporaryAdminMode::LeaveReasonReboot() {
  return SNTTemporaryAdminModeLeaveReasonReboot;
}
NSInteger TemporaryAdminMode::LeaveReasonSyncServerChanged() {
  return SNTTemporaryAdminModeLeaveReasonSyncServerChanged;
}
NSInteger TemporaryAdminMode::LeaveReasonUnspecified() {
  return SNTTemporaryAdminModeLeaveReasonUnspecified;
}

void TemporaryAdminMode::EmitAudit(id audit_event) {
  handle_audit_event_block_((SNTStoredTemporaryAdminModeAuditEvent*)audit_event);
}

void TemporaryAdminMode::NotifyEnter(NSDate* expiration) {
  [[notification_queue_.notifierConnection remoteObjectProxy] enterTemporaryAdminMode:expiration];
}

void TemporaryAdminMode::NotifyLeave() {
  [[notification_queue_.notifierConnection remoteObjectProxy] leaveTemporaryAdminMode];
}

void TemporaryAdminMode::EmitDenied(NSString* username, SNTTemporaryAdminModeDeniedReason reason) {
  handle_audit_event_block_([[SNTStoredTemporaryAdminModeDeniedAuditEvent alloc]
      initWithUUID:[[NSUUID UUID] UUIDString]
          username:username ?: @""
            reason:reason]);
}

}  // namespace santa
