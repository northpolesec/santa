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

#include <map>
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

// In-memory fake admin-group membership for tests. Never touches the real
// group 80. Models the seam's resolution behavior: `directory_down_` makes
// every identity unresolvable (systemic outage), `deleted_uids_` makes
// individual accounts unresolvable (deleted), `uuids_` overrides the per-uid
// unique identifier (uid-reuse scenarios), `uuid_calls_until_outage_`
// sequences a directory flap between two calls within the same reconcile
// pass, and `remove_fails_no_console_user_` models RemoveMember's own
// internal resolution flapping independently of Resolves().
class FakeAdminGroupMembership : public AdminGroupMembership {
 public:
  bool IsMember(uid_t uid) override { return Resolves(uid) && members_.count(uid) > 0; }

  bool AddMember(uid_t uid, NSError** error) override {
    if (directory_down_ || fail_add_) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"fake add"];
      return false;
    }
    if (deleted_uids_.count(uid)) {
      [SNTError populateError:error withCode:SNTErrorCodeTAMNoConsoleUser format:@"fake add"];
      return false;
    }
    members_.insert(uid);
    return true;
  }

  bool RemoveMember(uid_t uid, NSError** error) override {
    if (remove_fails_no_console_user_) {
      // The account resolves everywhere else (Resolves() is untouched) --
      // only RemoveMember's own internal resolution flaps to "not found".
      [SNTError populateError:error withCode:SNTErrorCodeTAMNoConsoleUser format:@"fake remove"];
      return false;
    }
    if (directory_down_ || fail_remove_) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"fake remove"];
      return false;
    }
    if (deleted_uids_.count(uid)) {
      [SNTError populateError:error withCode:SNTErrorCodeTAMNoConsoleUser format:@"fake remove"];
      return false;
    }
    members_.erase(uid);
    return true;
  }

  std::optional<std::vector<AdminGroupMember>> ListDirectUserMembers() override {
    // Unused by these tests.
    return std::nullopt;
  }

  NSString* UsernameForUID(uid_t uid) override {
    // Unused by TAM.
    return nil;
  }

  NSString* UUIDForUID(uid_t uid) override {
    if (!Resolves(uid)) {
      return nil;
    }
    auto it = uuids_.find(uid);
    NSString* result = it != uuids_.end() ? it->second : [NSString stringWithFormat:@"uuid-%u", uid];
    // Sequencing knob: this call still resolves, then the directory goes
    // down before the NEXT call -- modeling a flap between two resolutions
    // in the same reconcile pass rather than an outage present from the start.
    if (uuid_calls_until_outage_ > 0 && --uuid_calls_until_outage_ == 0) {
      directory_down_ = true;
    }
    return result;
  }

  bool IsLocalAccount(uid_t uid) override { return Resolves(uid) && local_uids_.count(uid) > 0; }

  std::set<uid_t> members_;
  std::set<uid_t> deleted_uids_;
  std::set<uid_t> local_uids_;
  std::map<uid_t, NSString*> uuids_;
  bool directory_down_ = false;
  bool fail_add_ = false;
  bool fail_remove_ = false;
  bool remove_fails_no_console_user_ = false;
  int uuid_calls_until_outage_ = -1;

 private:
  bool Resolves(uid_t uid) { return !directory_down_ && deleted_uids_.count(uid) == 0; }
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
                               uid:(uid_t)uid
                              uuid:(NSString*)uuid
                             local:(BOOL)local {
  return @{
    kTimedSessionBootUUIDKey : bootUUID,
    kTimedSessionDeadlineKey : @(deadline),
    kTimedSessionSyncURLKey : syncHost,
    kTimedSessionSessionUUIDKey : [[NSUUID UUID] UUIDString],
    @"TargetUID" : @(uid),
    @"TargetUsername" : @"reconcile-user",
    @"TargetUUID" : uuid ?: @"",
    @"TargetLocal" : @(local),
  };
}

// Legacy-shaped record (written before the TargetUUID/TargetLocal keys
// existed): restore must tolerate both shapes.
- (NSDictionary*)stateWithBootUUID:(NSString*)bootUUID
                          deadline:(uint64_t)deadline
                          syncHost:(NSString*)syncHost
                               uid:(uid_t)uid {
  NSMutableDictionary* state = [[self stateWithBootUUID:bootUUID
                                               deadline:deadline
                                               syncHost:syncHost
                                                    uid:uid
                                                   uuid:nil
                                                  local:NO] mutableCopy];
  [state removeObjectsForKeys:@[ @"TargetUUID", @"TargetLocal" ]];
  return state;
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

// A failed refresh must not destroy the live session's on-disk record: the
// original elevation is still applied and still owed a revert, and clearing
// the record would leave the user permanently elevated across a daemon restart.
- (void)testFailedRefreshKeepsLiveSessionRecord {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"reason"];
  __block NSDictionary* lastPersisted = nil;
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        lastPersisted = s;
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);
  NSDictionary* liveRecord = lastPersisted;
  XCTAssertNotNil(liveRecord);

  fake->fail_add_ = true;  // directory unreachable at refresh time
  err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 0u);
  XCTAssertEqual(err.code, SNTErrorCodeTAMMembershipChangeFailed);

  XCTAssertEqualObjects(lastPersisted, liveRecord);    // record never touched
  XCTAssertTrue(fake->IsMember(501));                  // still elevated
  XCTAssertTrue(tam->SecondsRemaining().has_value());  // original session still live
}

- (void)testGrantRefusedWhileTeardownRetryPending {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need to install"];
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  // A deadline-0 record left by a failed teardown, owed to the next daemon
  // start. Stubbed after Create so startup reconciliation does not consume it.
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:@"boot"
                                deadline:0
                                syncHost:@"foo.workshop.cloud"
                                     uid:501]);

  // Granting now would overwrite the residue and orphan uid 501's stuck
  // elevation forever; the grant must be refused instead.
  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 502, @"bob", &err), 0u);
  XCTAssertNotNil(err);
  XCTAssertFalse(fake->IsMember(502));
}

// I3: RequestMinutes validates a refresh under lock_, then BeginGrant runs the
// authorization window OFF lock_ (Touch ID + GUI, up to ~90s). If the session
// ends during that window -- here, simulated as a screen lock via
// EndForUserEvent -- target_uid_ is zeroed before ApplyEffect runs. ApplyEffect
// must refuse rather than persist/elevate uid 0.
//
// Does not use stubAuthReply: -- OCMock matches the first-added stub, so this
// test needs its own single stub that behaves differently on the 1st (initial
// grant) and 2nd (raced refresh) invocation.
- (void)testApplyEffectRefusesGrantWhenSessionEndsMidAuth {
  [self stubPolicyAvailable];
  __block std::shared_ptr<santa::TemporaryAdminMode> tam;
  __block int call = 0;
  OCMStub([self.mockNotQueue authorizeTemporaryAdminModeRequiringJustification:YES
                                                                         reply:[OCMArg any]])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained void (^reply)(BOOL, NSString*) = nil;
        [inv getArgument:&reply atIndex:3];
        call++;
        if (call == 2) {
          // Same thread; safe. lock_ is not held during the auth window and
          // EndForUserEvent does not take grant_mutex_ (held by the in-flight
          // RequestMinutes call on this same thread).
          tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked);
        }
        reply(YES, @"reason");
      });
  __block NSDictionary* lastPersisted = nil;
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        lastPersisted = s;
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                          (SNTNotificationQueue*)self.mockNotQueue,
                                          std::move(fakeOwned),
                                          ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                          });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);  // initial grant
  XCTAssertNil(err);

  err = nil;
  // The refresh's auth window is where the stub ends the session mid-auth.
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 0u);
  XCTAssertEqual(err.code, SNTErrorCodeTAMMembershipChangeFailed);
  XCTAssertEqual(fake->members_.count(0), 0u);  // root was never added
  XCTAssertNil(lastPersisted);                  // no TargetUID=0 record persisted
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

// The headline stranding bug: at daemon start during a directory outage the
// target does not resolve, which is byte-identical to a deleted account on
// Darwin. The session record must be KEPT for retry (the user is still
// elevated), not dropped as "no such account" — dropping it makes the user a
// permanent untracked admin. The uid deliberately does not exist on the test
// machine: the old StatusForUID gate reads it as kNotFound and drops the
// record.
- (void)testReconcileExpiredDuringOutageRetainsRecordForRetry {
  [self stubPolicyAvailable];
  constexpr uid_t kUnresolvableUID = 4000000000;
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1  // already in the past
                                syncHost:@"foo.workshop.cloud"
                                     uid:kUnresolvableUID
                                    uuid:@"uuid-alice"
                                   local:YES]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->members_.insert(kUnresolvableUID);  // elevated before the restart
  fake->directory_down_ = true;             // nothing resolves at startup
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  XCTAssertEqual(fake->members_.count(kUnresolvableUID), 1u);  // still elevated (remove failed)
  XCTAssertFalse(tam->SecondsRemaining().has_value());
  // The record was re-persisted as an expired retry residue, NOT cleared.
  XCTAssertTrue(writes.count > 0);
  NSDictionary* last = writes.lastObject;
  XCTAssertTrue([last isKindOfClass:[NSDictionary class]]);
  XCTAssertEqualObjects(last[kTimedSessionDeadlineKey], @0);
  XCTAssertEqualObjects(last[@"TargetUID"], @(kUnresolvableUID));
}

// A record naming uid 0 is malformed (grants for uid 0 are refused up front):
// it is dropped without any revert attempt and the persisted state is cleared.
- (void)testRestoreRejectsUidZeroRecord {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1
                                syncHost:@"foo.workshop.cloud"
                                     uid:0
                                    uuid:@"uuid-root"
                                   local:YES]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  XCTAssertFalse(tam->SecondsRemaining().has_value());
  XCTAssertEqualObjects(writes.lastObject, [NSNull null]);  // cleared, not retried
}

// The uid was reallocated to a different account (UUID differs from the
// record). The new holder must not be demoted — it may legitimately hold
// admin — and the record is consumed: the elevated account no longer exists.
- (void)testReconcileExpiredUidReusedConsumesWithoutDemoting {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->uuids_[501] = @"uuid-mallory";  // a different account now holds uid 501
  fake->members_.insert(501);           // and it happens to be an admin
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  XCTAssertEqual(fake->members_.count(501), 1u);            // never demoted
  XCTAssertEqualObjects(writes.lastObject, [NSNull null]);  // record consumed
}

// Same UUID means same account, whatever its name is now: a TAM user can
// rename their own account while elevated, and the demotion must still land
// (the guard keys on the GeneratedUID precisely so a rename is not an
// escape hatch).
- (void)testReconcileExpiredSameAccountStillDemoted {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->uuids_[501] = @"uuid-alice";  // same account (renamed or not)
  fake->members_.insert(501);
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  XCTAssertEqual(fake->members_.count(501), 0u);            // demoted
  XCTAssertEqualObjects(writes.lastObject, [NSNull null]);  // record cleared
}

// A LOCAL account that fails user-resolution against a healthy local node
// (RemoveMember -> SNTErrorCodeTAMNoConsoleUser) was deleted: there is
// nothing left to demote, and the record must be consumed rather than left
// as a residue that blocks every future grant on the machine.
- (void)testReconcileExpiredDeletedLocalConsumesRecord {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->deleted_uids_.insert(501);
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  XCTAssertEqualObjects(writes.lastObject, [NSNull null]);  // consumed, no residue
}

// An unresolvable DIRECTORY account is ambiguous: deleted or merely
// off-network. Consuming on an outage would strand a real admin, so the
// record is retried instead.
- (void)testReconcileExpiredDeletedDirectoryAccountRetries {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:NO]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->deleted_uids_.insert(501);
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  NSDictionary* last = writes.lastObject;
  XCTAssertTrue([last isKindOfClass:[NSDictionary class]]);  // residue kept
  XCTAssertEqualObjects(last[kTimedSessionDeadlineKey], @0);
  XCTAssertEqualObjects(last[@"TargetUID"], @501);
}

// I2: the uid-reuse guard can resolve the account (same UUID -- it provably
// exists this pass), and then RemoveMember's OWN internal resolution flaps to
// SNTErrorCodeTAMNoConsoleUser. That must not be read as "deleted" -- the
// probe that ran moments earlier proved otherwise -- so the record must stay
// retryable rather than being consumed out from under a still-existing user.
- (void)testReconcileExpiredLocalRemoveMemberFlapRetainsRecordForRetry {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:1  // already in the past
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* s = nil;
        [inv getArgument:&s atIndex:2];
        [writes addObject:s ? (id)[s copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->uuids_[501] = @"uuid-alice";  // same account -- the probe proves it exists
  fake->members_.insert(501);
  fake->remove_fails_no_console_user_ = true;  // RemoveMember's own resolution flaps
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  XCTAssertEqual(fake->members_.count(501), 1u);  // never demoted
  NSDictionary* last = writes.lastObject;
  XCTAssertTrue([last isKindOfClass:[NSDictionary class]]);  // residue kept, not consumed
  XCTAssertEqualObjects(last[kTimedSessionDeadlineKey], @0);
  XCTAssertEqualObjects(last[@"TargetUID"], @501);
}

// A still-time-valid session at daemon start during a directory outage:
// IsMember reads false only because nothing resolves. That must NOT be
// treated as an out-of-band revocation (which ends the session without
// reverting and strands the still-elevated user) — the session resumes, and
// the timer or the next reconcile reverts once the directory answers.
- (void)testReconcileValidDuringOutageResumesSession {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:MakeDeadline(100)
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->members_.insert(501);  // still a member; resolution merely fails
  fake->directory_down_ = true;
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  XCTAssertTrue(tam->SecondsRemaining().has_value());  // resumed, still tracked
  XCTAssertEqual(fake->members_.count(501), 1u);       // membership untouched
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeEnterAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryAdminModeEnterAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeEnterReasonRestart);
}

// I1: the resolution probe (UUIDForUID) and IsMember are two separate
// directory resolutions, not one atomic read. A flap BETWEEN them (the probe
// resolves, then the directory goes down before IsMember runs) must not be
// read as an out-of-band revocation: re-probe before trusting the negative,
// and resume when the identity has stopped resolving.
- (void)testReconcileValidDirectoryFlapBetweenProbeAndIsMemberResumesSession {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:MakeDeadline(100)
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->uuids_[501] = @"uuid-alice";
  fake->members_.insert(501);          // still a member ...
  fake->uuid_calls_until_outage_ = 1;  // ... until the directory drops after the first probe
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  XCTAssertTrue(tam->SecondsRemaining().has_value());  // resumed, still tracked
  XCTAssertEqual(fake->members_.count(501), 1u);       // membership untouched
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeEnterAuditEvent class]]);
  XCTAssertEqual(((SNTStoredTemporaryAdminModeEnterAuditEvent*)events.lastObject).reason,
                 SNTTemporaryAdminModeEnterReasonRestart);
}

// A still-time-valid session whose uid now resolves to a DIFFERENT account:
// the elevated account is gone, so the session ends — but through the
// no-revert decline path, so the uid's new holder is never demoted.
- (void)testReconcileValidUidReusedEndsSessionWithoutDemoting {
  [self stubPolicyAvailable];
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:@"TempAdmin"])
      .andReturn([self stateWithBootUUID:[SNTSystemInfo bootSessionUUID]
                                deadline:MakeDeadline(100)
                                syncHost:@"foo.workshop.cloud"
                                     uid:501
                                    uuid:@"uuid-alice"
                                   local:YES]);
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->uuids_[501] = @"uuid-mallory";  // a different account now holds uid 501
  fake->members_.insert(501);           // and it happens to be an admin
  NSMutableArray* events = [NSMutableArray array];
  auto tam = santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });

  XCTAssertFalse(tam->SecondsRemaining().has_value());  // session ended
  XCTAssertEqual(fake->members_.count(501), 1u);        // new holder never demoted
  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
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
  XCTAssertTrue(tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked));

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

  XCTAssertTrue(tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked));

  // The feature must still be available — no revoke policy was written.
  XCTAssertTrue(tam->Available());
}

// With an active session for uid 501 / "alice", EndForUserEvent for a different uid AND a
// different username is a no-op.
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

  // A different uid and a different username must be rejected.
  XCTAssertFalse(tam->EndForUserEvent(502, @"bob", SNTTemporaryAdminModeLeaveReasonScreenLocked));

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

  XCTAssertFalse(tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked));

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
  XCTAssertTrue(tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked));
  NSUInteger countAfterFirst = events.count;

  // Second call must return false and must not emit another audit event.
  XCTAssertFalse(tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked));
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

  XCTAssertTrue(tam->EndForUserEvent(501, @"alice", SNTTemporaryAdminModeLeaveReasonSessionEnded));

  XCTAssertTrue(
      [events.lastObject isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
  SNTStoredTemporaryAdminModeLeaveAuditEvent* leave =
      (SNTStoredTemporaryAdminModeLeaveAuditEvent*)events.lastObject;
  XCTAssertEqual(leave.reason, SNTTemporaryAdminModeLeaveReasonSessionEnded);
}

// uid unresolved (0) but the username matches the stored target -> revokes via the name. This is
// the transient-directory-failure case where getpwnam yields no uid.
- (void)testEndForUserEventNameMatchWhenUidUnresolved {
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

  XCTAssertTrue(tam->EndForUserEvent(0, @"alice", SNTTemporaryAdminModeLeaveReasonScreenLocked));
  XCTAssertFalse(fake->IsMember(501));
}

// uid does not match but the username does (local-vs-directory uid collision) -> revokes.
- (void)testEndForUserEventNameMatchWhenUidDiffers {
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

  XCTAssertTrue(tam->EndForUserEvent(999, @"alice", SNTTemporaryAdminModeLeaveReasonSessionEnded));
  XCTAssertFalse(fake->IsMember(501));
}

// The username match is case-insensitive (login name vs canonical pw_name can differ in case).
- (void)testEndForUserEventNameMatchIsCaseInsensitive {
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

  XCTAssertTrue(tam->EndForUserEvent(0, @"ALICE", SNTTemporaryAdminModeLeaveReasonScreenLocked));
  XCTAssertFalse(fake->IsMember(501));
}

// Neither key resolvable/matching (uid 0, empty username) -> no-op even with an active session.
- (void)testEndForUserEventNoKeyIsNoOp {
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

  XCTAssertFalse(tam->EndForUserEvent(0, @"", SNTTemporaryAdminModeLeaveReasonScreenLocked));
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(tam->SecondsRemaining().has_value());
}

- (void)testGrantPersistsTargetBeforeElevation {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need to install"];
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* state = nil;
        [inv getArgument:&state atIndex:2];
        [writes addObject:state ? (id)[state copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);

  // Persist-before-flip: a provisional deadline-0 record names the target on
  // disk BEFORE the elevation; the real session state follows.
  XCTAssertEqual(writes.count, 2u);
  NSDictionary* provisional = writes[0];
  NSDictionary* session = writes[1];
  XCTAssertEqualObjects(provisional[@"TargetUID"], @501);
  XCTAssertEqualObjects(provisional[kTimedSessionDeadlineKey], @0);
  XCTAssertEqualObjects(session[@"TargetUID"], @501);
  XCTAssertTrue([session[kTimedSessionDeadlineKey] unsignedLongLongValue] > 0);
}

// Grant-time identity capture: both the provisional (persist-before-flip)
// record and the session record carry the account's UUID and Local bit, so
// the revert paths can distinguish uid reuse and deleted-local after a
// daemon restart.
- (void)testGrantCapturesAccountIdentity {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need to install"];
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* state = nil;
        [inv getArgument:&state atIndex:2];
        [writes addObject:state ? (id)[state copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->uuids_[501] = @"uuid-alice";
  fake->local_uids_.insert(501);
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 5u);

  XCTAssertEqual(writes.count, 2u);
  for (NSDictionary* record in writes) {
    XCTAssertEqualObjects(record[@"TargetUUID"], @"uuid-alice");
    XCTAssertEqualObjects(record[@"TargetLocal"], @YES);
  }
}

- (void)testFailedElevationClearsProvisionalState {
  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need to install"];
  NSMutableArray* writes = [NSMutableArray array];
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:@"TempAdmin"])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* state = nil;
        [inv getArgument:&state atIndex:2];
        [writes addObject:state ? (id)[state copy] : (id)[NSNull null]];
      });
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  FakeAdminGroupMembership* fake = fakeOwned.get();
  fake->fail_add_ = true;
  auto tam = santa::TemporaryAdminMode::Create((SNTConfigurator*)self.mockConfigurator,
                                               (SNTNotificationQueue*)self.mockNotQueue,
                                               std::move(fakeOwned),
                                               ^(SNTStoredTemporaryAdminModeAuditEvent* e){
                                               });

  NSError* err = nil;
  XCTAssertEqual(tam->RequestMinutes(@5, 501, @"alice", &err), 0u);
  XCTAssertFalse(fake->IsMember(501));

  // The elevation never happened, so nothing is owed: the provisional record
  // is written, then cleared — it must not linger as a fake residue (which
  // would block future grants via the Task 1 guard).
  XCTAssertEqual(writes.count, 2u);
  NSDictionary* provisional = writes[0];
  XCTAssertEqualObjects(provisional[@"TargetUID"], @501);
  XCTAssertEqualObjects(provisional[kTimedSessionDeadlineKey], @0);
  XCTAssertEqualObjects(writes[1], [NSNull null]);
}

@end
