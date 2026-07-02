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

#include "Source/santad/TemporaryMonitorMode.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"

namespace santa {

std::shared_ptr<TemporaryMonitorMode> TemporaryMonitorMode::Create(
    SNTConfigurator* configurator, SNTNotificationQueue* notification_queue,
    HandleAuditEventBlock handle_audit_event_block) {
  auto tmm = std::make_shared<TemporaryMonitorMode>(PassKey(), configurator, notification_queue,
                                                    handle_audit_event_block);

  // NB: SetupFromState is split out of the constructor since it could start the
  // timer, which takes a weak reference that must not be taken before construction
  // is complete.
  tmm->SetupFromState();

  return tmm;
}

TemporaryMonitorMode::TemporaryMonitorMode(PassKey, SNTConfigurator* configurator,
                                           SNTNotificationQueue* notification_queue,
                                           HandleAuditEventBlock handle_audit_event_block)
    : TimedSyncSession(kMinTemporaryMonitorModeMinutes, kMaxTemporaryMonitorModeMinutes,
                       "Temporary Monitor Mode", configurator, notification_queue),
      handle_audit_event_block_([handle_audit_event_block copy]) {}

uint32_t TemporaryMonitorMode::RequestMinutes(NSNumber* requested_duration, NSError** err) {
  // Serialize the whole grant (pre-checks + auth + apply) against other grants.
  absl::MutexLock grant_lock(grant_mutex_);

  uint32_t minutes = 0;
  switch (BeginGrant(requested_duration, &minutes)) {
    case GrantOutcome::kGranted: return minutes;
    case GrantOutcome::kNoPolicy:
      [SNTError populateError:err
                     withCode:SNTErrorCodeTMMNoPolicy
                       format:@"This machine does not currently have a "
                              @"policy allowing temporary Monitor Mode."];
      return 0;
    case GrantOutcome::kNotEligible:
      [SNTError populateError:err
                     withCode:SNTErrorCodeTMMNotInLockdown
                       format:@"Machine must be in Lockdown Mode in order to "
                              @"transition to temporary Monitor Mode."];
      return 0;
    case GrantOutcome::kInvalidSyncServer:
      [SNTError populateError:err
                     withCode:SNTErrorCodeTMMInvalidSyncServer
                       format:@"This machine is not configured with a sync "
                              @"server that supports temporary Monitor Mode."];
      return 0;
    case GrantOutcome::kAuthFailed:
    case GrantOutcome::kJustificationRequired:  // TMM never requires a reason
    case GrantOutcome::kApplyFailed:            // TMM's effect (the in-memory flag) cannot fail
      [SNTError populateError:err
                     withCode:SNTErrorCodeTMMAuthFailed
                       format:@"User authorization failed."];
      return 0;
  }
}

void TemporaryMonitorMode::NewModeTransitionReceived(SNTModeTransition* mode_transition) {
  // Persistence of the received mode_transition is the caller's responsibility
  // (the daemon controller writes it inside a sync-state batch so that all
  // sync-derived state lands in a single commit). This method handles enforcement
  // side effects for Revoke and the GUI availability notification.
  if (mode_transition.type == SNTModeTransitionTypeRevoke) {
    if (Revoke(SNTTemporaryMonitorModeLeaveReasonRevoked)) {
      LOGI(@"Temporary Monitor Mode session revoked due to policy change.");
    }
  }

  [[notification_queue_.notifierConnection remoteObjectProxy]
      temporaryMonitorModePolicyAvailable:Available()];
}

#pragma mark Hooks

bool TemporaryMonitorMode::ApplyEffect(NSError** err) {
  [configurator_ setInTemporaryMonitorMode:YES];
  return true;
}

bool TemporaryMonitorMode::RevertEffect() {
  // Clearing an in-memory flag cannot fail, so the revert always succeeds.
  [configurator_ setInTemporaryMonitorMode:NO];
  return true;
}

bool TemporaryMonitorMode::ReapplyEffectOnRestart() {
  // The in-memory flag is lost across a daemon restart; re-applying is required so
  // Monitor mode keeps being enforced. Santa is the sole authority for this flag,
  // so re-applying is always correct.
  [configurator_ setInTemporaryMonitorMode:YES];
  return true;
}

bool TemporaryMonitorMode::ExtraPreconditions() {
  SNTClientMode clientMode = [configurator_ clientMode];
  return clientMode == SNTClientModeLockdown ||
         (clientMode == SNTClientModeMonitor && [configurator_ inTemporaryMonitorMode]);
}

NSString* TemporaryMonitorMode::StateKey() {
  return @"TMM";
}

bool TemporaryMonitorMode::HasOnDemandPolicy() {
  return [configurator_ modeTransition].type == SNTModeTransitionTypeOnDemand;
}

uint32_t TemporaryMonitorMode::ClampDuration(NSNumber* requested) {
  return [[configurator_ modeTransition] getDurationMinutes:requested];
}

bool TemporaryMonitorMode::PolicyRequiresAuth() {
  return YES;
}

bool TemporaryMonitorMode::PolicyRequiresJustification() {
  return NO;
}

void TemporaryMonitorMode::WriteRevokePolicy() {
  // Skip the write if the current effective transition is already a revoke, to
  // avoid a second syncState KVO fire on the sync-update path (where the daemon
  // controller writes the revoke inside its batch).
  if ([configurator_ modeTransition].type != SNTModeTransitionTypeRevoke) {
    [configurator_ setSyncServerModeTransition:[[SNTModeTransition alloc] initRevocation]];
  }
}

void TemporaryMonitorMode::RequestAuthorization(void (^reply)(BOOL, NSString*)) {
  [notification_queue_ authorizeTemporaryMonitorMode:^(BOOL authenticated) {
    reply(authenticated, nil);
  }];
}

NSDictionary* TemporaryMonitorMode::ExtraStateToPersist() {
  return @{};
}

bool TemporaryMonitorMode::RestoreAndValidateExtraState(NSDictionary* state) {
  return true;
}

void TemporaryMonitorMode::ClearExtraState() {}

id TemporaryMonitorMode::BuildEnterAuditEvent(NSString* session_uuid, uint32_t seconds,
                                              NSInteger enter_reason,
                                              NSString* user_justification) {
  return [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
      initWithUUID:session_uuid
           seconds:seconds
            reason:(SNTTemporaryMonitorModeEnterReason)enter_reason];
}

id TemporaryMonitorMode::BuildLeaveAuditEvent(NSString* session_uuid, NSInteger leave_reason) {
  return [[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
      initWithUUID:session_uuid
            reason:(SNTTemporaryMonitorModeLeaveReason)leave_reason];
}

NSInteger TemporaryMonitorMode::EnterReasonOnDemand() {
  return SNTTemporaryMonitorModeEnterReasonOnDemand;
}
NSInteger TemporaryMonitorMode::EnterReasonRefresh() {
  return SNTTemporaryMonitorModeEnterReasonOnDemandRefresh;
}
NSInteger TemporaryMonitorMode::EnterReasonRestart() {
  return SNTTemporaryMonitorModeEnterReasonRestart;
}
NSInteger TemporaryMonitorMode::LeaveReasonCancelled() {
  return SNTTemporaryMonitorModeLeaveReasonCancelled;
}
NSInteger TemporaryMonitorMode::LeaveReasonSessionExpired() {
  return SNTTemporaryMonitorModeLeaveReasonSessionExpired;
}
NSInteger TemporaryMonitorMode::LeaveReasonReboot() {
  return SNTTemporaryMonitorModeLeaveReasonReboot;
}
NSInteger TemporaryMonitorMode::LeaveReasonSyncServerChanged() {
  return SNTTemporaryMonitorModeLeaveReasonSyncServerChanged;
}

void TemporaryMonitorMode::EmitAudit(id audit_event) {
  handle_audit_event_block_((SNTStoredTemporaryMonitorModeAuditEvent*)audit_event);
}

void TemporaryMonitorMode::NotifyEnter(NSDate* expiration) {
  [[notification_queue_.notifierConnection remoteObjectProxy] enterTemporaryMonitorMode:expiration];
}

void TemporaryMonitorMode::NotifyLeave() {
  [[notification_queue_.notifierConnection remoteObjectProxy] leaveTemporaryMonitorMode];
}

}  // namespace santa
