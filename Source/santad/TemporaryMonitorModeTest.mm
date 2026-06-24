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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <mach/mach_time.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTModeTransition.h"
#include "Source/common/SystemResources.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "Source/santad/TimedSyncSession.h"

namespace santa {
class TemporaryMonitorModePeer : public TemporaryMonitorMode {
 public:
  TemporaryMonitorModePeer(SNTConfigurator* configurator, SNTNotificationQueue* notQueue,
                           HandleAuditEventBlock block)
      : santa::TemporaryMonitorMode(MakeKey(), configurator, notQueue, block) {}

  using santa::TimedSyncSession::GetSecondsRemainingFromStateLocked;
};
}  // namespace santa

using santa::TemporaryMonitorModePeer;

// Return a mach continuous time that is at least the given seconds in the future.
// Checks should use `XCTAssertGreaterThan(..., want)` to account for timing delays.
uint64_t MakeDeadline(uint64_t want) {
  return MachTimeToNanos(
      AddNanosecondsToMachTime((want + 5) * NSEC_PER_SEC, mach_continuous_time()));
}

@interface TemporaryMonitorModeTest : XCTestCase
@property id mockConfigurator;
@property id mockNotQueue;
@end

@implementation TemporaryMonitorModeTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // Use the class mock directly as the notification-queue instance. (The previous
  // alloc / initWithRingBuffer: dance did not reliably yield a usable mock: the
  // designated initializer takes a C++ std::unique_ptr that OCMock cannot match, so
  // instance-method stubs such as authorizeTemporaryMonitorMode: could not be
  // recorded. The peer never calls the initializer, so a class mock stands in fine.)
  self.mockNotQueue = OCMClassMock([SNTNotificationQueue class]);
}

- (void)testGetSecondsRemainingFromInitialState {
  NSURL* unpinnedURL = [NSURL URLWithString:@"https://my.sync.server"];
  NSURL* pinnedURL = [NSURL URLWithString:@"https://foo.workshop.cloud"];
  NSURL* pinnedURL2 = [NSURL URLWithString:@"https://bar.workshop.cloud"];
  NSString* testBootUUID = @"my.boot.uuid";
  NSString* testSessionUUID = [[NSUUID UUID] UUIDString];
  uint64_t wantAtLeastSeconds = 100;

  TemporaryMonitorModePeer tmm([SNTConfigurator configurator], self.mockNotQueue,
                               ^(id){
                                   // This space intentionally left blank.
                               });

  NSDictionary* goodTestState = @{
    kTimedSessionBootUUIDKey : testBootUUID,
    kTimedSessionDeadlineKey : @(MakeDeadline(wantAtLeastSeconds)),
    kTimedSessionSyncURLKey : pinnedURL.host,
    kTimedSessionSessionUUIDKey : testSessionUUID,
  };

  __block BOOL syncV2Enabled = YES;
  OCMStub([self.mockConfigurator isSyncV2Enabled]).andDo(^(NSInvocation* inv) {
    [inv setReturnValue:&syncV2Enabled];
  });

  NSMutableDictionary* testState = [goodTestState copy];
  XCTAssertGreaterThan(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL),
                       wantAtLeastSeconds);

  // Bad Boot Session UUID type
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionBootUUIDKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL), 0);

  // Bad Deadline type
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionDeadlineKey] = @"123";
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL), 0);

  // Bad Session UUID type
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionSessionUUIDKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL), 0);

  // Invalid Session UUID
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionSessionUUIDKey] = @"ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ";
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL), 0);

  // Bad Sync URL type type
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionSyncURLKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL), 0);

  // Mismatched boot session UUID
  testState = [goodTestState mutableCopy];
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, @"xyz", pinnedURL), 0);

  // Sync V2 not enabled
  syncV2Enabled = NO;
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionSyncURLKey] = unpinnedURL.host;
  OCMExpect([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition* mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, unpinnedURL), 0);

  // Mismatched sync URL
  testState = [goodTestState mutableCopy];
  testState[kTimedSessionSyncURLKey] = pinnedURL2.host;
  OCMExpect([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition* mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  XCTAssertEqual(tmm.GetSecondsRemainingFromStateLocked(testState, testBootUUID, pinnedURL), 0);

  XCTAssertTrue(OCMVerifyAll(self.mockConfigurator));
}

// Characterization tests: lock in the grant / refresh / cancel / revoke / OnTimer
// behavior of the CURRENT TemporaryMonitorMode before it is refactored onto the
// shared TimedSyncSession base. They must pass against today's TMM unchanged.
//
// These construct the peer via std::make_shared so the Timer mixin's
// shared_from_this() works when the timer starts (a stack-allocated peer would
// throw bad_weak_ptr the moment RequestMinutes starts the timer). make_shared on
// the peer also skips SetupFromState, so no KVO is registered on the mock.

// Stub the configurator/notification-queue so Available() passes and the GUI auth
// callback returns YES. Durations are minutes; the live timer (>= 1 minute) never
// fires during a unit test, so expiry is driven explicitly via OnTimer().
- (void)stubOnDemandAvailableMaxMinutes:(uint32_t)maxMinutes defaultDuration:(uint32_t)def {
  OCMStub([self.mockConfigurator modeTransition])
      .andReturn([[SNTModeTransition alloc] initOnDemandMinutes:maxMinutes defaultDuration:def]);
  OCMStub([self.mockConfigurator isSyncV2Enabled]).andReturn(YES);
  OCMStub([self.mockConfigurator clientMode]).andReturn(SNTClientModeLockdown);
  OCMStub([self.mockConfigurator syncBaseURL])
      .andReturn([NSURL URLWithString:@"https://foo.workshop.cloud"]);
  OCMStub([self.mockNotQueue
      authorizeTemporaryMonitorMode:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(YES), nil])]);
}

- (void)testGrantEntersAndEmitsOnDemandEnter {
  [self stubOnDemandAvailableMaxMinutes:60 defaultDuration:5];
  NSMutableArray<SNTStoredTemporaryMonitorModeAuditEvent*>* events = [NSMutableArray array];
  auto tmm = std::make_shared<TemporaryMonitorModePeer>(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      ^(SNTStoredTemporaryMonitorModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tmm->RequestMinutes(@5, &err), 5u);
  XCTAssertNil(err);

  OCMVerify([self.mockConfigurator setInTemporaryMonitorMode:YES]);

  std::optional<uint64_t> remaining = tmm->SecondsRemaining();
  XCTAssertTrue(remaining.has_value());
  XCTAssertGreaterThan(*remaining, 0u);

  XCTAssertEqual(events.count, 1u);
  XCTAssertTrue([events[0] isKindOfClass:[SNTStoredTemporaryMonitorModeEnterAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryMonitorModeEnterAuditEvent*)events[0]).reason,
                 SNTTemporaryMonitorModeEnterReasonOnDemand);
}

- (void)testSecondRequestIsRefresh {
  [self stubOnDemandAvailableMaxMinutes:60 defaultDuration:5];
  NSMutableArray<SNTStoredTemporaryMonitorModeAuditEvent*>* events = [NSMutableArray array];
  auto tmm = std::make_shared<TemporaryMonitorModePeer>(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      ^(SNTStoredTemporaryMonitorModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tmm->RequestMinutes(@5, &err), 5u);
  XCTAssertEqual(tmm->RequestMinutes(@5, &err), 5u);

  XCTAssertTrue(tmm->SecondsRemaining().has_value());
  XCTAssertEqual(events.count, 2u);
  XCTAssertEqual(((SNTStoredTemporaryMonitorModeEnterAuditEvent*)events[0]).reason,
                 SNTTemporaryMonitorModeEnterReasonOnDemand);
  XCTAssertTrue([events[1] isKindOfClass:[SNTStoredTemporaryMonitorModeEnterAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryMonitorModeEnterAuditEvent*)events[1]).reason,
                 SNTTemporaryMonitorModeEnterReasonOnDemandRefresh);
}

- (void)testCancelEmitsCancelledLeave {
  [self stubOnDemandAvailableMaxMinutes:60 defaultDuration:5];
  NSMutableArray<SNTStoredTemporaryMonitorModeAuditEvent*>* events = [NSMutableArray array];
  auto tmm = std::make_shared<TemporaryMonitorModePeer>(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      ^(SNTStoredTemporaryMonitorModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tmm->RequestMinutes(@5, &err), 5u);
  XCTAssertTrue(tmm->Cancel());

  OCMVerify([self.mockConfigurator setInTemporaryMonitorMode:NO]);
  XCTAssertFalse(tmm->SecondsRemaining().has_value());

  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryMonitorModeLeaveAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryMonitorModeLeaveAuditEvent*)events.lastObject).reason,
                 SNTTemporaryMonitorModeLeaveReasonCancelled);
}

- (void)testRevokeWritesRevocationAndEmitsRevokedLeave {
  [self stubOnDemandAvailableMaxMinutes:60 defaultDuration:5];
  NSMutableArray<SNTStoredTemporaryMonitorModeAuditEvent*>* events = [NSMutableArray array];
  auto tmm = std::make_shared<TemporaryMonitorModePeer>(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      ^(SNTStoredTemporaryMonitorModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tmm->RequestMinutes(@5, &err), 5u);
  XCTAssertTrue(tmm->Revoke(SNTTemporaryMonitorModeLeaveReasonRevoked));

  OCMVerify([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition* mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  OCMVerify([self.mockConfigurator setInTemporaryMonitorMode:NO]);
  XCTAssertFalse(tmm->SecondsRemaining().has_value());

  XCTAssertEqual(((SNTStoredTemporaryMonitorModeLeaveAuditEvent*)events.lastObject).reason,
                 SNTTemporaryMonitorModeLeaveReasonRevoked);
}

- (void)testOnTimerEmitsSessionExpiredLeave {
  [self stubOnDemandAvailableMaxMinutes:60 defaultDuration:5];
  NSMutableArray<SNTStoredTemporaryMonitorModeAuditEvent*>* events = [NSMutableArray array];
  auto tmm = std::make_shared<TemporaryMonitorModePeer>(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      ^(SNTStoredTemporaryMonitorModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tmm->RequestMinutes(@5, &err), 5u);

  // OnTimer returns false: the session expired, do not reschedule.
  XCTAssertFalse(tmm->OnTimer());

  OCMVerify([self.mockConfigurator setInTemporaryMonitorMode:NO]);
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryMonitorModeLeaveAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryMonitorModeLeaveAuditEvent*)events.lastObject).reason,
                 SNTTemporaryMonitorModeLeaveReasonSessionExpired);
}

@end
