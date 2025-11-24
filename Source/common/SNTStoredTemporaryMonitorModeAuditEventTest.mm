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

#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface StoredEventTest : XCTestCase
@end

@implementation StoredEventTest

- (void)testUniqueID {
  // Ensure some UUID-length string is returned.It should be random and not match
  // what the object was initialized with.
  SNTStoredTemporaryMonitorModeEnterAuditEvent *tmmAuditEnter =
      [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
          initWithUUID:@"abc"
               seconds:123
                reason:SNTTemporaryMonitorModeEnterReasonRestart];
  XCTAssertEqual([[tmmAuditEnter uniqueID] length], [[NSUUID UUID] UUIDString].length);

  SNTStoredTemporaryMonitorModeLeaveAuditEvent *tmmAuditLeave =
      [[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
          initWithUUID:@"xyz"
                reason:SNTTemporaryMonitorModeLeaveReasonSessionExpired];
  XCTAssertEqual([[tmmAuditLeave uniqueID] length], [[NSUUID UUID] UUIDString].length);
}

- (void)testUnactionableEvent {
  // Spot check temporary Monitor Mode audit events
  SNTStoredTemporaryMonitorModeEnterAuditEvent *tmmAuditEnter =
      [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
          initWithUUID:@"abc"
               seconds:123
                reason:SNTTemporaryMonitorModeEnterReasonOnDemand];
  XCTAssertFalse([tmmAuditEnter unactionableEvent]);

  SNTStoredTemporaryMonitorModeLeaveAuditEvent *tmmAuditLeave =
      [[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
          initWithUUID:@"xyz"
                reason:SNTTemporaryMonitorModeLeaveReasonCancelled];
  XCTAssertFalse([tmmAuditLeave unactionableEvent]);
}

- (void)testEncodeDecode {
  SNTStoredTemporaryMonitorModeEnterAuditEvent *tmmAuditEnter =
      [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
          initWithUUID:@"abc"
               seconds:123
                reason:SNTTemporaryMonitorModeEnterReasonOnDemandRefresh];

  SNTStoredTemporaryMonitorModeLeaveAuditEvent *tmmAuditLeave =
      [[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
          initWithUUID:@"xyz"
                reason:SNTTemporaryMonitorModeLeaveReasonSyncServerChanged];

  NSData *archivedTmmEnterEvent = [NSKeyedArchiver archivedDataWithRootObject:tmmAuditEnter
                                                        requiringSecureCoding:YES
                                                                        error:nil];

  NSData *archivedTmmLeaveEvent = [NSKeyedArchiver archivedDataWithRootObject:tmmAuditLeave
                                                        requiringSecureCoding:YES
                                                                        error:nil];

  XCTAssertNotNil(archivedTmmEnterEvent);
  XCTAssertNotNil(archivedTmmLeaveEvent);

  NSSet *allowedClasses =
      [NSSet setWithObjects:[SNTStoredTemporaryMonitorModeAuditEvent class],
                            [SNTStoredTemporaryMonitorModeEnterAuditEvent class],
                            [SNTStoredTemporaryMonitorModeLeaveAuditEvent class], nil];

  SNTStoredEvent *unarchivedTmmEnterEvent =
      [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                          fromData:archivedTmmEnterEvent
                                             error:nil];
  XCTAssertNotNil(unarchivedTmmEnterEvent);
  XCTAssertTrue(
      [unarchivedTmmEnterEvent isKindOfClass:[SNTStoredTemporaryMonitorModeEnterAuditEvent class]]);
  SNTStoredTemporaryMonitorModeEnterAuditEvent *tmmEnterAuditEvent =
      (SNTStoredTemporaryMonitorModeEnterAuditEvent *)unarchivedTmmEnterEvent;
  XCTAssertEqualObjects([tmmEnterAuditEvent uniqueID], [tmmAuditEnter uniqueID]);
  XCTAssertEqual(tmmEnterAuditEvent.seconds, 123);
  XCTAssertEqual(tmmEnterAuditEvent.reason, SNTTemporaryMonitorModeEnterReasonOnDemandRefresh);

  SNTStoredEvent *unarchivedTmmLeaveEvent =
      [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                          fromData:archivedTmmLeaveEvent
                                             error:nil];
  XCTAssertNotNil(unarchivedTmmLeaveEvent);
  XCTAssertTrue(
      [unarchivedTmmLeaveEvent isKindOfClass:[SNTStoredTemporaryMonitorModeLeaveAuditEvent class]]);
  SNTStoredTemporaryMonitorModeLeaveAuditEvent *tmmLeaveAuditEvent =
      (SNTStoredTemporaryMonitorModeLeaveAuditEvent *)unarchivedTmmLeaveEvent;
  XCTAssertEqualObjects([tmmLeaveAuditEvent uniqueID], [tmmAuditLeave uniqueID]);
  XCTAssertEqual(tmmLeaveAuditEvent.reason, SNTTemporaryMonitorModeLeaveReasonSyncServerChanged);
}

@end
