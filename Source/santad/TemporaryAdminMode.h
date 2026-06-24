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

#ifndef SANTA_SANTAD_TEMPORARYADMINMODE_H
#define SANTA_SANTAD_TEMPORARYADMINMODE_H

#include <sys/types.h>

#include <memory>

#include "Source/common/PassKey.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredTemporaryAdminModeAuditEvent.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#include "Source/santad/AdminGroupMembership.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "Source/santad/TimedSyncSession.h"

namespace santa {

// Temporary Admin Mode: a sync-blessed, timer-bounded grant of admin-group
// (GID 80) membership to a single user. A thin subclass of TimedSyncSession; the
// effect is real OS state (group membership) mutated through AdminGroupMembership.
//
// target_uid_ / target_username_ identify the elevated user. They are accessed
// only under the base's lock_ (set in RequestMinutes / RestoreAndValidateExtraState,
// read by the effect/audit/persist hooks, all of which the base invokes under
// lock_), so they are not separately annotated.
class TemporaryAdminMode : public TimedSyncSession, public PassKey<TemporaryAdminMode> {
 public:
  using HandleAuditEventBlock = void (^)(SNTStoredTemporaryAdminModeAuditEvent*);

  static std::shared_ptr<TemporaryAdminMode> Create(
      SNTConfigurator* configurator, SNTNotificationQueue* notification_queue,
      std::unique_ptr<AdminGroupMembership> membership,
      HandleAuditEventBlock handle_audit_event_block);

  TemporaryAdminMode(PassKey, SNTConfigurator* configurator,
                     SNTNotificationQueue* notification_queue,
                     std::unique_ptr<AdminGroupMembership> membership,
                     HandleAuditEventBlock handle_audit_event_block);

  // Public entry. The target uid/username are resolved by the daemon controller
  // from the XPC peer's audit token; they are never trusted from the GUI. Returns
  // the granted minutes, or 0 on error (with `err` populated and a Denied audit
  // event emitted).
  uint32_t RequestMinutes(NSNumber* requested_duration, uid_t uid, NSString* username,
                          NSError** err);

  // Whether `uid` is currently a member of the admin group.
  bool IsCurrentlyAdmin(uid_t uid);

  // On a Revoke policy, cancel any active session; always re-notify GUI availability.
  void NewPolicyReceived(SNTTemporaryAdminPolicy* policy);

  // End the active session iff it belongs to `uid`, with the given leave reason and no revoke
  // policy. No-op (returns false) if no session is active or the uid does not match. Used by
  // the session-presence triggers (screen lock / logout / fast-user-switch).
  bool EndForUserEvent(uid_t uid, SNTTemporaryAdminModeLeaveReason reason);

  friend class TemporaryAdminModePeer;

 protected:
  bool ApplyEffect(NSError** err) override;
  void RevertEffect() override;
  bool ReapplyEffectOnRestart() override;
  bool ExtraPreconditions() override;
  NSString* StateKey() override;
  bool HasOnDemandPolicy() override;
  uint32_t ClampDuration(NSNumber* requested) override;
  bool PolicyRequiresAuth() override;
  bool PolicyRequiresJustification() override;
  void WriteRevokePolicy() override;
  void RequestAuthorization(void (^reply)(BOOL authenticated, NSString* reason)) override;
  NSDictionary* ExtraStateToPersist() override;
  bool RestoreAndValidateExtraState(NSDictionary* state) override;
  void ClearExtraState() override;
  id BuildEnterAuditEvent(NSString* session_uuid, uint32_t seconds, NSInteger enter_reason,
                          NSString* user_justification) override;
  id BuildLeaveAuditEvent(NSString* session_uuid, NSInteger leave_reason) override;
  NSInteger EnterReasonOnDemand() override;
  NSInteger EnterReasonRefresh() override;
  NSInteger EnterReasonRestart() override;
  NSInteger LeaveReasonCancelled() override;
  NSInteger LeaveReasonSessionExpired() override;
  NSInteger LeaveReasonReboot() override;
  NSInteger LeaveReasonSyncServerChanged() override;
  void EmitAudit(id audit_event) override;
  void NotifyEnter(NSDate* expiration) override;
  void NotifyLeave() override;

 private:
  void EmitDenied(NSString* username, SNTTemporaryAdminModeDeniedReason reason);

  std::unique_ptr<AdminGroupMembership> membership_;
  HandleAuditEventBlock handle_audit_event_block_;
  uid_t target_uid_;
  NSString* target_username_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_TEMPORARYADMINMODE_H
