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

#include <pwd.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCNotifierInterface.h"

namespace santa {

static NSString* const kTAMTargetUsernameKey = @"TargetUsername";

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
      target_uid_(0) {}

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
  NSError* err = nil;
  if (!membership_->RemoveMember(target_uid_, &err)) {
    // Report the failure so the base keeps an expired session record and retries the
    // demotion on the next daemon start, rather than clearing state and leaving the
    // user elevated past the intended window.
    LOGE(@"Temporary Admin Mode failed to demote uid %u: %@", target_uid_,
         err.localizedDescription);
    return false;
  }
  return true;
}

bool TemporaryAdminMode::ReapplyEffectOnRestart() {
  // If the user is no longer a member, the elevation was revoked out of band
  // (admin/MDM/another tool). Do not re-add — end the session instead.
  if (!membership_->IsMember(target_uid_)) {
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
    kTAMTargetUsernameKey : target_username_ ?: @""
  };
}

bool TemporaryAdminMode::RestoreAndValidateExtraState(NSDictionary* state) {
  if (![state[kStateTempAdminTargetUIDKey] isKindOfClass:[NSNumber class]] ||
      ![state[kTAMTargetUsernameKey] isKindOfClass:[NSString class]]) {
    return false;
  }
  uid_t uid = [state[kStateTempAdminTargetUIDKey] unsignedIntValue];
  // Reject uid 0 and any uid that no longer resolves to a user (deleted account).
  if (uid == 0 || getpwuid(uid) == NULL) {
    return false;
  }
  target_uid_ = uid;
  target_username_ = state[kTAMTargetUsernameKey];
  return true;
}

void TemporaryAdminMode::ClearExtraState() {
  target_uid_ = 0;
  target_username_ = nil;
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
