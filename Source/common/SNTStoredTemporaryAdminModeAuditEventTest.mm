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
#import <XCTest/XCTest.h>

#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredTemporaryAdminModeAuditEvent.h"

// Helper: archive an object using NSKeyedArchiver with secure coding.
static NSData* Archive(id<NSSecureCoding> obj) {
  NSError* err = nil;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:obj
                                       requiringSecureCoding:YES
                                                       error:&err];
  return err ? nil : data;
}

// Helper: unarchive from data, allowing the full TAM class hierarchy.
static id Unarchive(NSData* data) {
  NSSet* allowed = [NSSet setWithObjects:[SNTStoredTemporaryAdminModeAuditEvent class],
                                         [SNTStoredTemporaryAdminModeEnterAuditEvent class],
                                         [SNTStoredTemporaryAdminModeLeaveAuditEvent class],
                                         [SNTStoredTemporaryAdminModeDeniedAuditEvent class], nil];
  NSError* err = nil;
  return [NSKeyedUnarchiver unarchivedObjectOfClasses:allowed fromData:data error:&err];
}

@interface SNTStoredTemporaryAdminModeAuditEventTest : XCTestCase
@end

@implementation SNTStoredTemporaryAdminModeAuditEventTest

#pragma mark - Enter event

- (void)testEnterRoundTrip {
  SNTStoredTemporaryAdminModeEnterAuditEvent* orig =
      [[SNTStoredTemporaryAdminModeEnterAuditEvent alloc]
               initWithUUID:@"session-uuid-1"
                   username:@"alice"
                    seconds:300
                     reason:SNTTemporaryAdminModeEnterReasonOnDemand
          userJustification:@"need to install software"];

  NSData* data = Archive(orig);
  XCTAssertNotNil(data, @"archiving Enter event should succeed");

  SNTStoredTemporaryAdminModeEnterAuditEvent* decoded =
      (SNTStoredTemporaryAdminModeEnterAuditEvent*)Unarchive(data);
  XCTAssertNotNil(decoded);
  XCTAssertTrue([decoded isKindOfClass:[SNTStoredTemporaryAdminModeEnterAuditEvent class]]);

  XCTAssertEqualObjects(decoded.uuid, @"session-uuid-1");
  XCTAssertEqualObjects(decoded.username, @"alice");
  XCTAssertEqual(decoded.seconds, 300u);
  XCTAssertEqual(decoded.reason, SNTTemporaryAdminModeEnterReasonOnDemand);
  XCTAssertEqualObjects(decoded.userJustification, @"need to install software");

  // Inherited from SNTStoredEvent via SNTTimedSessionAuditEvent.
  XCTAssertNotNil(decoded.occurrenceDate);

  // uniqueID is based on a per-instance UUID and must be a UUID-length string.
  XCTAssertNotNil([decoded uniqueID]);
  XCTAssertEqual([[decoded uniqueID] length], [[NSUUID UUID] UUIDString].length);

  // The uniqueID is stable across the same instance (the encoded uniqueUuid round-trips).
  XCTAssertEqualObjects([decoded uniqueID], [orig uniqueID]);

  // Must never be dropped from the event database.
  XCTAssertFalse([decoded unactionableEvent]);
}

- (void)testEnterRefreshReasonRoundTrip {
  SNTStoredTemporaryAdminModeEnterAuditEvent* orig =
      [[SNTStoredTemporaryAdminModeEnterAuditEvent alloc]
               initWithUUID:@"session-uuid-refresh"
                   username:@"bob"
                    seconds:600
                     reason:SNTTemporaryAdminModeEnterReasonOnDemandRefresh
          userJustification:@""];

  SNTStoredTemporaryAdminModeEnterAuditEvent* decoded =
      (SNTStoredTemporaryAdminModeEnterAuditEvent*)Unarchive(Archive(orig));
  XCTAssertEqual(decoded.reason, SNTTemporaryAdminModeEnterReasonOnDemandRefresh);
  XCTAssertEqual(decoded.seconds, 600u);
  XCTAssertEqualObjects(decoded.username, @"bob");
}

- (void)testEnterRestartReasonRoundTrip {
  SNTStoredTemporaryAdminModeEnterAuditEvent* orig =
      [[SNTStoredTemporaryAdminModeEnterAuditEvent alloc]
               initWithUUID:@"session-uuid-restart"
                   username:@"carol"
                    seconds:120
                     reason:SNTTemporaryAdminModeEnterReasonRestart
          userJustification:@""];

  SNTStoredTemporaryAdminModeEnterAuditEvent* decoded =
      (SNTStoredTemporaryAdminModeEnterAuditEvent*)Unarchive(Archive(orig));
  XCTAssertEqual(decoded.reason, SNTTemporaryAdminModeEnterReasonRestart);
  XCTAssertEqualObjects(decoded.uuid, @"session-uuid-restart");
  XCTAssertFalse([decoded unactionableEvent]);
  XCTAssertNotNil([decoded uniqueID]);
}

#pragma mark - Leave event

- (void)testLeaveRoundTrip {
  SNTStoredTemporaryAdminModeLeaveAuditEvent* orig =
      [[SNTStoredTemporaryAdminModeLeaveAuditEvent alloc]
          initWithUUID:@"session-uuid-2"
              username:@"alice"
                reason:SNTTemporaryAdminModeLeaveReasonCancelled];

  NSData* data = Archive(orig);
  XCTAssertNotNil(data, @"archiving Leave event should succeed");

  SNTStoredTemporaryAdminModeLeaveAuditEvent* decoded =
      (SNTStoredTemporaryAdminModeLeaveAuditEvent*)Unarchive(data);
  XCTAssertNotNil(decoded);
  XCTAssertTrue([decoded isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);

  XCTAssertEqualObjects(decoded.uuid, @"session-uuid-2");
  XCTAssertEqualObjects(decoded.username, @"alice");
  XCTAssertEqual(decoded.reason, SNTTemporaryAdminModeLeaveReasonCancelled);

  XCTAssertNotNil(decoded.occurrenceDate);
  XCTAssertNotNil([decoded uniqueID]);
  XCTAssertEqual([[decoded uniqueID] length], [[NSUUID UUID] UUIDString].length);
  XCTAssertEqualObjects([decoded uniqueID], [orig uniqueID]);
  XCTAssertFalse([decoded unactionableEvent]);
}

- (void)testLeaveAllReasonsRoundTrip {
  SNTTemporaryAdminModeLeaveReason reasons[] = {
      SNTTemporaryAdminModeLeaveReasonSessionExpired,
      SNTTemporaryAdminModeLeaveReasonCancelled,
      SNTTemporaryAdminModeLeaveReasonRevoked,
      SNTTemporaryAdminModeLeaveReasonSyncServerChanged,
      SNTTemporaryAdminModeLeaveReasonReboot,
      SNTTemporaryAdminModeLeaveReasonScreenLocked,
      SNTTemporaryAdminModeLeaveReasonSessionEnded,
  };
  for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
    SNTStoredTemporaryAdminModeLeaveAuditEvent* orig =
        [[SNTStoredTemporaryAdminModeLeaveAuditEvent alloc] initWithUUID:@"uuid"
                                                                username:@"dave"
                                                                  reason:reasons[i]];
    SNTStoredTemporaryAdminModeLeaveAuditEvent* decoded =
        (SNTStoredTemporaryAdminModeLeaveAuditEvent*)Unarchive(Archive(orig));
    XCTAssertEqual(decoded.reason, reasons[i], @"leave reason %zu should round-trip", i);
  }
}

#pragma mark - Denied event

- (void)testDeniedRoundTrip {
  SNTStoredTemporaryAdminModeDeniedAuditEvent* orig =
      [[SNTStoredTemporaryAdminModeDeniedAuditEvent alloc]
          initWithUUID:@"session-uuid-3"
              username:@"eve"
                reason:SNTTemporaryAdminModeDeniedReasonAuthFailed];

  NSData* data = Archive(orig);
  XCTAssertNotNil(data, @"archiving Denied event should succeed");

  SNTStoredTemporaryAdminModeDeniedAuditEvent* decoded =
      (SNTStoredTemporaryAdminModeDeniedAuditEvent*)Unarchive(data);
  XCTAssertNotNil(decoded);
  XCTAssertTrue([decoded isKindOfClass:[SNTStoredTemporaryAdminModeDeniedAuditEvent class]]);

  XCTAssertEqualObjects(decoded.uuid, @"session-uuid-3");
  XCTAssertEqualObjects(decoded.username, @"eve");
  XCTAssertEqual(decoded.reason, SNTTemporaryAdminModeDeniedReasonAuthFailed);

  XCTAssertNotNil(decoded.occurrenceDate);
  XCTAssertNotNil([decoded uniqueID]);
  XCTAssertEqual([[decoded uniqueID] length], [[NSUUID UUID] UUIDString].length);
  XCTAssertEqualObjects([decoded uniqueID], [orig uniqueID]);
  XCTAssertFalse([decoded unactionableEvent]);
}

- (void)testDeniedAllReasonsRoundTrip {
  SNTTemporaryAdminModeDeniedReason reasons[] = {
      SNTTemporaryAdminModeDeniedReasonNoPolicy,
      SNTTemporaryAdminModeDeniedReasonNotEligible,
      SNTTemporaryAdminModeDeniedReasonAuthFailed,
      SNTTemporaryAdminModeDeniedReasonJustificationRequired,
      SNTTemporaryAdminModeDeniedReasonAlreadyAdmin,
      SNTTemporaryAdminModeDeniedReasonSessionAlreadyActive,
      SNTTemporaryAdminModeDeniedReasonMembershipChangeFailed,
  };
  for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
    SNTStoredTemporaryAdminModeDeniedAuditEvent* orig =
        [[SNTStoredTemporaryAdminModeDeniedAuditEvent alloc] initWithUUID:@"uuid"
                                                                 username:@"frank"
                                                                   reason:reasons[i]];
    SNTStoredTemporaryAdminModeDeniedAuditEvent* decoded =
        (SNTStoredTemporaryAdminModeDeniedAuditEvent*)Unarchive(Archive(orig));
    XCTAssertEqual(decoded.reason, reasons[i], @"denied reason %zu should round-trip", i);
  }
}

#pragma mark - uniqueID distinctness

- (void)testUniqueIDsAreDistinctAcrossInstances {
  // Two independently created events must have different uniqueIDs even with the
  // same session UUID — this prevents de-duplication of refresh events.
  SNTStoredTemporaryAdminModeEnterAuditEvent* e1 =
      [[SNTStoredTemporaryAdminModeEnterAuditEvent alloc]
               initWithUUID:@"same-uuid"
                   username:@"gina"
                    seconds:60
                     reason:SNTTemporaryAdminModeEnterReasonOnDemand
          userJustification:@""];
  SNTStoredTemporaryAdminModeEnterAuditEvent* e2 =
      [[SNTStoredTemporaryAdminModeEnterAuditEvent alloc]
               initWithUUID:@"same-uuid"
                   username:@"gina"
                    seconds:60
                     reason:SNTTemporaryAdminModeEnterReasonOnDemandRefresh
          userJustification:@""];

  XCTAssertNotEqualObjects([e1 uniqueID], [e2 uniqueID],
                           @"distinct instances must produce distinct uniqueIDs");
}

@end
