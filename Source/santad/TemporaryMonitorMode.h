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

#ifndef SANTA_SANTAD_TEMPORARYMONITORMODE_H
#define SANTA_SANTAD_TEMPORARYMONITORMODE_H

#include <memory>

#include "Source/common/PassKey.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "Source/santad/TimedSyncSession.h"

namespace santa {

// Temporary Monitor Mode: a sync-blessed, timer-bounded override that puts the
// client into Monitor mode for a requested duration. A thin subclass of
// TimedSyncSession; the effect is an in-memory flag that the clientMode getter
// reads.
class TemporaryMonitorMode : public TimedSyncSession, public PassKey<TemporaryMonitorMode> {
 public:
  using HandleAuditEventBlock = void (^)(SNTStoredTemporaryMonitorModeAuditEvent*);

  // Factory
  static std::shared_ptr<TemporaryMonitorMode> Create(
      SNTConfigurator* configurator, SNTNotificationQueue* notification_queue,
      HandleAuditEventBlock handle_audit_event_block);

  // Construction requires a PassKey, can only be used internally / by tests.
  TemporaryMonitorMode(PassKey, SNTConfigurator* configurator,
                       SNTNotificationQueue* notification_queue,
                       HandleAuditEventBlock handle_audit_event_block);

  // Enter Monitor Mode temporarily for the requested duration. Returns the actual
  // number of minutes allowed, or 0 on error (with `err` populated).
  uint32_t RequestMinutes(NSNumber* requested_duration, NSError** err);

  // If the mode transition authorization was revoked, immediately cancel any
  // existing session; always re-notify the GUI of availability.
  void NewModeTransitionReceived(SNTModeTransition* mode_transition);

  friend class TemporaryMonitorModePeer;

 protected:
  bool ApplyEffect(NSError** err) override;
  bool RevertEffect() override;
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
  NSInteger LeaveReasonUnspecified() override;
  void EmitAudit(id audit_event) override;
  void NotifyEnter(NSDate* expiration) override;
  void NotifyLeave() override;

 private:
  HandleAuditEventBlock handle_audit_event_block_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_TEMPORARYMONITORMODE_H
