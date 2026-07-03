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

#import <Foundation/Foundation.h>

#import "Source/common/SNTTimedSessionAuditEvent.h"

// Reason for entering Temporary Admin Mode.
typedef NS_ENUM(NSInteger, SNTTemporaryAdminModeEnterReason) {
  // On demand request by the user for a new Temporary Admin Mode session.
  SNTTemporaryAdminModeEnterReasonOnDemand,

  // On demand request by the user, changing the timing parameters
  // of an existing Temporary Admin Mode session.
  SNTTemporaryAdminModeEnterReasonOnDemandRefresh,

  // The Santa daemon was restarted but a previously existing Temporary
  // Admin Mode session was still active.
  SNTTemporaryAdminModeEnterReasonRestart,
};

// Reason for leaving Temporary Admin Mode.
typedef NS_ENUM(NSInteger, SNTTemporaryAdminModeLeaveReason) {
  // The requested duration expired.
  SNTTemporaryAdminModeLeaveReasonSessionExpired,

  // The user manually ended the session.
  SNTTemporaryAdminModeLeaveReasonCancelled,

  // The server revoked the machine's eligibility for Temporary Admin Mode
  // and an existing session was terminated.
  SNTTemporaryAdminModeLeaveReasonRevoked,

  // The machine's SyncBaseURL configuration changed which cancelled
  // an active session.
  SNTTemporaryAdminModeLeaveReasonSyncServerChanged,

  // The machine rebooted and the previous session is no longer applicable.
  SNTTemporaryAdminModeLeaveReasonReboot,

  // The user's screen was locked.
  SNTTemporaryAdminModeLeaveReasonScreenLocked,

  // The user's login session ended.
  SNTTemporaryAdminModeLeaveReasonSessionEnded,

  // A still-valid session's elevation could not be re-applied at daemon
  // restart because the user was no longer a member of the admin group --
  // membership was removed out of band (an administrator, MDM, or another
  // tool). Santa cannot attribute the cause and it is not a sync-server
  // revocation, so it is reported as REASON_UNSPECIFIED upstream.
  SNTTemporaryAdminModeLeaveReasonUnspecified,
};

// Reason a Temporary Admin Mode request was denied.
typedef NS_ENUM(NSInteger, SNTTemporaryAdminModeDeniedReason) {
  // No on-demand admin policy is configured.
  SNTTemporaryAdminModeDeniedReasonNoPolicy,

  // The requesting user is not eligible (e.g. not in Lockdown mode).
  SNTTemporaryAdminModeDeniedReasonNotEligible,

  // Authentication was required but failed.
  SNTTemporaryAdminModeDeniedReasonAuthFailed,

  // A justification was required but not provided.
  SNTTemporaryAdminModeDeniedReasonJustificationRequired,

  // The requesting user is already an administrator.
  SNTTemporaryAdminModeDeniedReasonAlreadyAdmin,

  // A Temporary Admin Mode session is already active for a different user.
  SNTTemporaryAdminModeDeniedReasonSessionAlreadyActive,

  // The group membership change could not be applied.
  SNTTemporaryAdminModeDeniedReasonMembershipChangeFailed,
};

// Base class for Temporary Admin Mode audit events. Not instantiated directly;
// use the Enter / Leave / Denied subclasses. Inherits uuid / uniqueID /
// unactionableEvent from SNTTimedSessionAuditEvent.
@interface SNTStoredTemporaryAdminModeAuditEvent : SNTTimedSessionAuditEvent <NSSecureCoding>
@property(readonly) NSString* username;
- (instancetype)initWithUUID:(NSString*)uuid username:(NSString*)username;
- (instancetype)init NS_UNAVAILABLE;
@end

//
// Enter audit event
//
@interface SNTStoredTemporaryAdminModeEnterAuditEvent
    : SNTStoredTemporaryAdminModeAuditEvent <NSSecureCoding>
@property(readonly) uint32_t seconds;
@property(readonly) SNTTemporaryAdminModeEnterReason reason;
@property(readonly) NSString* userJustification;
- (instancetype)initWithUUID:(NSString*)uuid
                    username:(NSString*)username
                     seconds:(uint32_t)seconds
                      reason:(SNTTemporaryAdminModeEnterReason)reason
           userJustification:(NSString*)userJustification;
- (instancetype)init NS_UNAVAILABLE;
@end

//
// Leave audit event
//
@interface SNTStoredTemporaryAdminModeLeaveAuditEvent
    : SNTStoredTemporaryAdminModeAuditEvent <NSSecureCoding>
@property(readonly) SNTTemporaryAdminModeLeaveReason reason;
- (instancetype)initWithUUID:(NSString*)uuid
                    username:(NSString*)username
                      reason:(SNTTemporaryAdminModeLeaveReason)reason;
- (instancetype)init NS_UNAVAILABLE;
@end

//
// Denied audit event
//
@interface SNTStoredTemporaryAdminModeDeniedAuditEvent
    : SNTStoredTemporaryAdminModeAuditEvent <NSSecureCoding>
@property(readonly) SNTTemporaryAdminModeDeniedReason reason;
- (instancetype)initWithUUID:(NSString*)uuid
                    username:(NSString*)username
                      reason:(SNTTemporaryAdminModeDeniedReason)reason;
- (instancetype)init NS_UNAVAILABLE;
@end
