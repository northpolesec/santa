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

static NSString* const kTAMTargetUIDKey = @"TargetUID";
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

bool TemporaryAdminMode::EndForUserEvent(uid_t uid, SNTTemporaryAdminModeLeaveReason reason) {
  absl::MutexLock lock(lock_);
  if (!IsStartedLocked() || target_uid_ != uid) {
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
bool TemporaryAdminMode::ApplyEffect(NSError** err) {
  return membership_->AddMember(target_uid_, err);
}

void TemporaryAdminMode::RevertEffect() {
  if (target_uid_ == 0) {
    return;
  }
  NSError* err = nil;
  if (!membership_->RemoveMember(target_uid_, &err)) {
    LOGE(@"Temporary Admin Mode failed to demote uid %u: %@", target_uid_,
         err.localizedDescription);
  }
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
  return @"TempAdmin";
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
  return @{kTAMTargetUIDKey : @(target_uid_), kTAMTargetUsernameKey : target_username_ ?: @""};
}

bool TemporaryAdminMode::RestoreAndValidateExtraState(NSDictionary* state) {
  if (![state[kTAMTargetUIDKey] isKindOfClass:[NSNumber class]] ||
      ![state[kTAMTargetUsernameKey] isKindOfClass:[NSString class]]) {
    return false;
  }
  uid_t uid = [state[kTAMTargetUIDKey] unsignedIntValue];
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
