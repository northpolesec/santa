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

#import "Source/common/SNTStoredEvent.h"

// Reason for entering temporary Monitor Mode.
typedef NS_ENUM(NSInteger, SNTTemporaryMonitorModeEnterReason) {
  // On deamnd request by the user for a new temporary Monitor Mode session.
  SNTTemporaryMonitorModeEnterReasonOnDemand,

  // On deamnd request by the user, changing the timing parameters
  // of the existing temporary Monitor Mode session.
  SNTTemporaryMonitorModeEnterReasonOnDemandRefresh,

  // The Santa daemon was restarted but a reviously existing temporary
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
};

// Indicates the type (enter/leave) contained within a SNTStoredTemporaryMonitorModeEnterAuditEvent.
typedef NS_ENUM(NSInteger, SNTStoredTemporaryMonitorModeAuditEventType) {
  SNTStoredTemporaryMonitorModeAuditEventTypeUnknown = 0,
  SNTStoredTemporaryMonitorModeAuditEventTypeEnter,
  SNTStoredTemporaryMonitorModeAuditEventTypeLeave,
};

// Empty protocol to constrain types that can be contained within a
// SNTStoredTemporaryMonitorModeEnterAuditEvent.
@protocol SNTStoredTemporaryMonitorModeAuditProtocol <NSObject, NSSecureCoding>
@end

// Enter Audit event
@interface SNTStoredTemporaryMonitorModeEnterAuditEvent
    : NSObject <SNTStoredTemporaryMonitorModeAuditProtocol>
@property(readonly) SNTTemporaryMonitorModeEnterReason reason;
@property(readonly) uint32_t seconds;

- (instancetype)initWithSeconds:(uint32_t)seconds reason:(SNTTemporaryMonitorModeEnterReason)reason;
@end

// Leave audit event
@interface SNTStoredTemporaryMonitorModeLeaveAuditEvent
    : NSObject <SNTStoredTemporaryMonitorModeAuditProtocol>
@property(readonly) SNTTemporaryMonitorModeLeaveReason reason;

- (instancetype)initWithReason:(SNTTemporaryMonitorModeLeaveReason)reason;
@end

// Represents a temporary Monitor Mode audit event stored in the events database.
@interface SNTStoredTemporaryMonitorModeAuditEvent : SNTStoredEvent <NSSecureCoding>

@property NSString *uuid;

@property(readonly) SNTStoredTemporaryMonitorModeAuditEventType type;
@property(readonly) id<SNTStoredTemporaryMonitorModeAuditProtocol> auditEvent;

// Creates a new session with a generated UUID.
- (instancetype)initEnterWithSeconds:(uint32_t)seconds
                              reason:(SNTTemporaryMonitorModeEnterReason)reason;

// Creates an enter event for an existing session (refresh or restart).
- (instancetype)initEnterWithUUID:(NSString *)uuid
                          seconds:(uint32_t)seconds
                           reason:(SNTTemporaryMonitorModeEnterReason)reason;

// Creates a leave event for an existing session.
- (instancetype)initLeaveWithUUID:(NSString *)uuid
                           reason:(SNTTemporaryMonitorModeLeaveReason)reason;

@end
