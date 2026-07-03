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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <mach/mach_time.h>
#include <unistd.h>

#include <set>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTStoredTemporaryAdminModeAuditEvent.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#include "Source/common/SystemResources.h"
#include "Source/santad/AdminGroupMembership.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "Source/santad/TimedSyncSession.h"

namespace santa {

// In-memory fake admin-group membership for tests. Never touches the real group 80.
class FakeAdminGroupMembership : public AdminGroupMembership {
 public:
  bool IsMember(uid_t uid) override { return members_.count(uid) > 0; }

  bool AddMember(uid_t uid, NSError** error) override {
    if (fail_add_) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"fake add"];
      return false;
    }
    members_.insert(uid);
    return true;
  }

  bool RemoveMember(uid_t uid, NSError** error) override {
    if (fail_remove_) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"fake remove"];
      return false;
    }
    members_.erase(uid);
    return true;
  }

  std::set<uid_t> members_;
  bool fail_add_ = false;
  bool fail_remove_ = false;
};

}  // namespace santa

using santa::FakeAdminGroupMembership;

// A mach continuous time at least the given seconds in the future.
static uint64_t MakeDeadline(uint64_t want) {
  return MachTimeToNanos(
      AddNanosecondsToMachTime((want + 5) * NSEC_PER_SEC, mach_continuous_time()));
}

@interface TemporaryAdminModeTest : XCTestCase
@property id mockConfigurator;
@property id mockNotQueue;
@end

@implementation TemporaryAdminModeTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  self.mockNotQueue = OCMClassMock([SNTNotificationQueue class]);
}

// Stub an available on-demand policy that requires a justification.
- (void)stubPolicyAvailable {
  OCMStub([self.mockConfigurator temporaryAdminPolicy])
      .andReturn([[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                                      defaultDuration:5
                                                 requireJustification:YES]);
  OCMStub([self.mockConfigurator isSyncV2Enabled]).andReturn(YES);
  OCMStub([self.mockConfigurator syncBaseURL])
      .andReturn([NSURL URLWithString:@"https://foo.workshop.cloud"]);
}

- (void)stubAuthReply:(BOOL)authed reason:(NSString*)reason {
  // setUp configures a policy with requireJustification:YES, so RequestAuthorization passes YES.
  OCMStub([self.mockNotQueue
      authorizeTemporaryAdminModeRequiringJustification:YES
                                                  reply:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(
                                                                                         authed),
                                                                                     reason,
                                                                                     nil])]);
}

// Builds a persisted TAM session-state dict for reconciliation tests.
- (NSDictionary*)stateWithBootUUID:(NSString*)bootUUID
                          deadline:(uint64_t)deadline
                          syncHost:(NSString*)syncHost
                               uid:(uid_t)uid {
  return @{
    kTimedSessionBootUUIDKey : bootUUID,
    kTimedSessionDeadlineKey : @(deadline),
    kTimedSessionSyncURLKey : syncHost,
    kTimedSessionSessionUUIDKey : [[NSUUID UUID] UUIDString],
    @"TargetUID" : @(uid),
    @"TargetUsername" : @"reconcile-user",
  };
}

#pragma mark Grant-path tests

- (void)testGrantAddsMemberAndEmitsEnter {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need to install"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  XCTAssertNil(err);
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(tam->SecondsRemaining().has_value());
  XCTAssertEqual(events.count, 1u);
  XCTAssertTrue([events[0] isKindOfClass:[SNTStoredTemporaryAdminModeEnterAuditEvent class]]);
  SNTStoredTemporaryAdminModeEnterAuditEvent* enter =
      (SNTStoredTemporaryAdminModeEnterAuditEvent*)events[0];
  XCTAssertEqual(enter.reason, SNTTemporaryAdminModeEnterReasonOnDemand);
  XCTAssertEqualObjects(enter.username, @"alice");
}

- (void)testNaturalAdminRefused {
  [self stubPolicyAvailable];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->members_.insert(501);  // already an admin
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 0u);
  XCTAssertEqual(err.code, SNTErrorCodeTAMAlreadyAdmin);
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  XCTAssertTrue(fake->IsMember(501));  // unchanged: never stripped
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeDeniedAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryAdminModeDeniedAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeDeniedReasonAlreadyAdmin);
}

- (void)testSecondUserRefused {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"reason"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);  // first user grants

  err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 502, @"bob", &err), 0u);  // second user refused
  XCTAssertEqual(err.code, SNTErrorCodeTAMSessionAlreadyActive);
  XCTAssertEqual(((SNTStoredTemporaryAdminModeDeniedAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeDeniedReasonSessionAlreadyActive);
}

- (void)testAuthFailEmitsDenied {
  [self stubPolicyAvailable];
  [self stubAuthReply:NO reason:@""];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 0u);
  XCTAssertEqual(err.code, SNTErrorCodeTAMAuthFailed);
  XCTAssertFalse(fake->IsMember(501));  // never elevated
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  XCTAssertEqual(((SNTStoredTemporaryAdminModeDeniedAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeDeniedReasonAuthFailed);
}

// Review M3: an unresolvable / AD account fails cleanly via AddMember -> kApplyFailed.
- (void)testApplyFailedFailsClean {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"reason"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->fail_add_ = true;  // simulate a directory user that cannot be committed locally
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 0u);
  XCTAssertEqual(err.code, SNTErrorCodeTAMMembershipChangeFailed);
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  XCTAssertEqual(((SNTStoredTemporaryAdminModeDeniedAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeDeniedReasonMembershipChangeFailed);
}

#pragma mark Reconciliation tests

- (void)testReconcileRebootRemovesMember {
  [self stubPolicyAvailable];
  uid_t uid = getuid();  // a uid getpwuid resolves
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:@"a-previous-boot"
                                deadline:MakeDeadline(100)
                                syncHost:@"foo.workshop.cloud"
                                     uid:uid]);
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->members_.insert(uid);  // membership persisted across the (simulated) reboot
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  XCTAssertFalse(fake->IsMember(uid));  // actively demoted
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryAdminModeLeaveAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeLeaveReasonReboot);
}

- (void)testReconcileExpiredRemovesMember {
  [self stubPolicyAvailable];
  uid_t uid = getuid();
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1  // already in the past
                                syncHost:@"foo.workshop.cloud"
                                     uid:uid]);
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->members_.insert(uid);
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  XCTAssertFalse(fake->IsMember(uid));
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  XCTAssertEqual(((SNTStoredTemporaryAdminModeLeaveAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeLeaveReasonSessionExpired);
}

// Review M1: a still-valid session whose user is no longer a member must NOT be
// re-added — the elevation was revoked out of band. End the session instead.
- (void)testReconcileValidButNotMemberEndsSession {
  [self stubPolicyAvailable];
  uid_t uid = getuid();
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:MakeDeadline(100)
                                syncHost:@"foo.workshop.cloud"
                                     uid:uid]);
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  // NOT a member: removed out of band while the session was still within its deadline.
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  XCTAssertFalse(fake->IsMember(uid));                  // not re-added
  XCTAssertFalse(tam->SecondsRemaining().has_value());  // session ended, not resumed
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
}

// If the demotion fails during reconciliation of an expired session, the session state
// must NOT be cleared: the base keeps an already-expired record (deadline 0) so the next
// daemon start retries the revert, rather than leaving the user elevated with nothing
// tracking it. (The success case is covered by testReconcileExpiredRemovesMember; together
// they exercise the retry loop.)
- (void)testReconcileRevertFailureRetainsExpiredStateForRetry {
  [self stubPolicyAvailable];
  uid_t uid = getuid();
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1  // already in the past
                                syncHost:@"foo.workshop.cloud"
                                     uid:uid]);
  __block NSDictionary* lastPersisted = nil;
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        lastPersisted = s;
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->members_.insert(uid);
  fake->fail_remove_ = true;  // the demotion cannot be committed
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  // Still elevated (removal failed) ...
  XCTAssertTrue(fake->IsMember(uid));
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  // ... and the state was NOT cleared: an already-expired record was persisted for retry.
  XCTAssertNotNil(lastPersisted);
  XCTAssertEqualObjects(lastPersisted[kTimedSessionDeadlineKey], @0);
  XCTAssertEqualObjects(lastPersisted[@"TargetUID"], @(uid));
}

#pragma mark EndForUserEvent tests

// After a successful grant, EndForUserEvent for the granted uid returns true, removes the uid
// from the admin group, and emits a Leave audit with the specified reason.
- (void)testEndForUserEventEndsMatchingSession {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"install something"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  XCTAssertNil(err);
  XCTAssertTrue(fake->IsMember(501));

  // EndForUserEvent with the matching uid must return true.
  XCTAssertTrue(tam->EndForUserEvent(501, SNTTemporaryAdminModeLeaveReasonScreenLocked));

  // The user must be removed from the admin group.
  XCTAssertFalse(fake->IsMember(501));

  // A Leave audit must have been emitted with the correct reason.
  XCTAssertEqual(events.count, 2u);
  XCTAssertTrue([events[1] isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
  SNTStoredTemporaryAdminModeLeaveAuditEvent* leave =
      (SNTStoredTemporaryAdminModeLeaveAuditEvent*)events[1];
  XCTAssertEqual(leave.reason, SNTTemporaryAdminModeLeaveReasonScreenLocked);
}

// After EndForUserEvent the feature must remain available (no revoke policy written).
- (void)testEndForUserEventDoesNotWriteRevokePolicy {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"install something"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  XCTAssertNil(err);
  // Available() must be true before and after; EndForUserEvent must not call WriteRevokePolicy.
  XCTAssertTrue(tam->Available());

  XCTAssertTrue(tam->EndForUserEvent(501, SNTTemporaryAdminModeLeaveReasonScreenLocked));

  // The feature must still be available — no revoke policy was written.
  XCTAssertTrue(tam->Available());
}

// With an active session for uid 501, EndForUserEvent for a different uid is a no-op.
- (void)testEndForUserEventWrongUidIsNoOp {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"reason"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  XCTAssertNil(err);
  XCTAssertTrue(fake->IsMember(501));

  // A different uid must be rejected.
  XCTAssertFalse(tam->EndForUserEvent(502, SNTTemporaryAdminModeLeaveReasonScreenLocked));

  // Session for 501 must remain intact.
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(tam->SecondsRemaining().has_value());

  // No additional audit event should have been emitted (only the Enter from the grant).
  XCTAssertEqual(events.count, 1u);
}

// With no active session, EndForUserEvent is a no-op.
- (void)testEndForUserEventNoActiveSession {
  [self stubPolicyAvailable];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  // No session was started.
  XCTAssertFalse(tam->SecondsRemaining().has_value());

  XCTAssertFalse(tam->EndForUserEvent(501, SNTTemporaryAdminModeLeaveReasonScreenLocked));

  // No audit events must have been emitted.
  XCTAssertEqual(events.count, 0u);
}

// A second EndForUserEvent after the first returns false and does not emit a second Leave audit.
- (void)testEndForUserEventIdempotent {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"reason"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  XCTAssertNil(err);

  // First call succeeds.
  XCTAssertTrue(tam->EndForUserEvent(501, SNTTemporaryAdminModeLeaveReasonScreenLocked));
  NSUInteger countAfterFirst = events.count;

  // Second call must return false and must not emit another audit event.
  XCTAssertFalse(tam->EndForUserEvent(501, SNTTemporaryAdminModeLeaveReasonScreenLocked));
  XCTAssertEqual(events.count, countAfterFirst);
}

// EndForUserEvent with SNTTemporaryAdminModeLeaveReasonSessionEnded flows the reason through.
- (void)testEndForUserEventSessionEndedReason {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"logout test"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  XCTAssertNil(err);

  XCTAssertTrue(tam->EndForUserEvent(501, SNTTemporaryAdminModeLeaveReasonSessionEnded));

  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
  SNTStoredTemporaryAdminModeLeaveAuditEvent* leave =
      (SNTStoredTemporaryAdminModeLeaveAuditEvent*)events.lastObject;
  XCTAssertEqual(leave.reason, SNTTemporaryAdminModeLeaveReasonSessionEnded);
}

@end
