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

#import <Foundation/Foundation.h>

#import "src/common/SNTStoredEvent.h"

// Reason for entering temporary Monitor Mode.
typedef NS_ENUM(NSInteger, SNTTemporaryMonitorModeEnterReason) {
  // On demand request by the user for a new temporary Monitor Mode session.
  SNTTemporaryMonitorModeEnterReasonOnDemand,

  // On demand request by the user, changing the timing parameters
  // of the existing temporary Monitor Mode session.
  SNTTemporaryMonitorModeEnterReasonOnDemandRefresh,

  // The Santa daemon was restarted but a previously existing temporary
  // Monitor Mode session was still active.
  SNTTemporaryMonitorModeEnterReasonRestart,
};

// Reason for leaving temporary Monitor Mode.
typedef NS_ENUM(NSInteger, SNTTemporaryMonitorModeLeaveReason) {
  // The requested duration expired.
  SNTTemporaryMonitorModeLeaveReasonSessionExpired,

  // The user manually ended the session.
  SNTTemporaryMonitorModeLeaveReasonCancelled,

  // The server revoked the machine's eligibility for temporary Monitor
  // Mode and an existing session was terminated.
  SNTTemporaryMonitorModeLeaveReasonRevoked,

  // The machine's SyncBaseURL configuration changed which cancelled
  // an active session.
  SNTTemporaryMonitorModeLeaveReasonSyncServerChanged,

  // The machine rebooted and the previous session is no longer applicable
  SNTTemporaryMonitorModeLeaveReasonReboot,
};

// Represents a temporary Monitor Mode audit event stored in the events database.
// This class is not meant to be directly instantiated. Use derived classes instead.
@interface SNTStoredTemporaryMonitorModeAuditEvent : SNTStoredEvent <NSSecureCoding>

@property(readonly) NSString *uuid;

- (instancetype)initWithUUID:(NSString *)uuid;
- (instancetype)init NS_UNAVAILABLE;

@end

//
// Enter Audit event
//
@interface SNTStoredTemporaryMonitorModeEnterAuditEvent
    : SNTStoredTemporaryMonitorModeAuditEvent <NSSecureCoding>

@property(readonly) uint32_t seconds;
@property(readonly) SNTTemporaryMonitorModeEnterReason reason;

- (instancetype)initWithUUID:(NSString *)uuid
                     seconds:(uint32_t)seconds
                      reason:(SNTTemporaryMonitorModeEnterReason)reason;
- (instancetype)init NS_UNAVAILABLE;

@end

//
// Leave audit event
//
@interface SNTStoredTemporaryMonitorModeLeaveAuditEvent
    : SNTStoredTemporaryMonitorModeAuditEvent <NSSecureCoding>

@property(readonly) SNTTemporaryMonitorModeLeaveReason reason;

- (instancetype)initWithUUID:(NSString *)uuid reason:(SNTTemporaryMonitorModeLeaveReason)reason;
- (instancetype)init NS_UNAVAILABLE;

@end
