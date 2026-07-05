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

#include "Source/santad/AdminUserState.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <map>
#include <memory>
#include <set>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#include "Source/santad/AdminGroupMembership.h"

namespace santa {

// In-memory fake admin-group membership for tests. Never touches the real group 80.
class FakeAdminGroupMembership : public AdminGroupMembership {
 public:
  bool IsMember(uid_t uid) override { return members_.count(uid) > 0; }

  bool AddMember(uid_t uid, NSError** error) override {
    if (gone_uids_.count(uid)) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMNoConsoleUser
                       format:@"fake unresolvable uid"];
      return false;
    }
    if (fail_add_uids_.count(uid)) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"fake add"];
      return false;
    }
    members_.insert(uid);
    return true;
  }

  bool RemoveMember(uid_t uid, NSError** error) override {
    if (fail_remove_uids_.count(uid)) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"fake remove"];
      return false;
    }
    members_.erase(uid);
    return true;
  }

  std::optional<std::vector<AdminGroupMember>> ListDirectUserMembers() override {
    if (fail_list_) {
      return std::nullopt;
    }
    std::vector<AdminGroupMember> out;
    for (uid_t uid : members_) {
      out.push_back({uid, names_.count(uid) ? names_[uid] : @"", !network_uids_.count(uid)});
    }
    return out;
  }

  NSString* UsernameForUID(uid_t uid) override {
    if (gone_uids_.count(uid)) return nil;
    return names_.count(uid) ? names_[uid] : nil;
  }

  std::set<uid_t> members_;           // current group-80 members (sorted => deterministic order)
  std::map<uid_t, NSString*> names_;  // uid -> username reported by enumeration
  std::set<uid_t> fail_add_uids_;     // AddMember fails (transient commit failure)
  std::set<uid_t> fail_remove_uids_;  // RemoveMember fails
  std::set<uid_t> gone_uids_;         // AddMember fails as unresolvable (account deleted)
  std::set<uid_t> network_uids_;      // enumerated as non-local (directory) accounts
  bool fail_list_ = false;
};

}  // namespace santa

using santa::AdminUserState;
using santa::FakeAdminGroupMembership;

static SNTTemporaryAdminPolicy* OnDemandPolicy() {
  return [[SNTTemporaryAdminPolicy alloc] initOnDemandMinutes:60
                                              defaultDuration:5
                                         requireJustification:NO];
}

static SNTTemporaryAdminPolicy* RevokePolicy() {
  return [[SNTTemporaryAdminPolicy alloc] initRevocation];
}

@interface AdminUserStateTest : XCTestCase
@property id mockConfigurator;
// In-memory stand-in for the persisted DemotedAdmins record: nil means no
// record, mirroring persistDemotedAdmins:/savedDemotedAdmins semantics.
@property(copy) NSArray<NSDictionary*>* storedRecord;
// When YES, persistDemotedAdmins: reports failure and leaves storedRecord
// unchanged, mirroring the production rollback semantics.
@property BOOL persistFails;
// In-memory stand-in for TAM's persisted session state under the TempAdmin
// key: nil means no session/residue.
@property(copy) NSDictionary* tamSessionState;
@end

@implementation AdminUserStateTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  self.storedRecord = nil;

  OCMStub([self.mockConfigurator persistDemotedAdmins:[OCMArg any]]).andDo(^(NSInvocation* inv) {
    BOOL ok = !self.persistFails;
    if (ok) {
      __unsafe_unretained NSArray* record = nil;
      [inv getArgument:&record atIndex:2];
      self.storedRecord = record;
    }
    [inv setReturnValue:&ok];
  });
  OCMStub([self.mockConfigurator savedDemotedAdmins]).andDo(^(NSInvocation* inv) {
    __unsafe_unretained NSArray* record = self.storedRecord;
    [inv setReturnValue:&record];
  });
  OCMStub([self.mockConfigurator savedTimedSessionStateForKey:[OCMArg any]])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* ret = self.tamSessionState;
        [inv setReturnValue:&ret];
      });
  OCMStub([self.mockConfigurator persistTimedSessionState:[OCMArg any] forKey:[OCMArg any]])
      .andDo(^(NSInvocation* inv) {
        __unsafe_unretained NSDictionary* state = nil;
        [inv getArgument:&state atIndex:2];
        self.tamSessionState = state;
      });
}

- (std::unique_ptr<AdminUserState>)makeStateWithFake:(FakeAdminGroupMembership**)fakeOut {
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  *fakeOut = fakeOwned.get();
  return std::make_unique<AdminUserState>((SNTConfigurator*)self.mockConfigurator,
                                          std::move(fakeOwned));
}

#pragma mark Capture + demote

- (void)testPolicyOnCapturesAndDemotesOnlyRealUsers {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {0, 200, 501, 503};
  fake->names_ = {{0, @"root"}, {200, @"_swupdate"}, {501, @"jane"}, {503, @"itadmin"}};

  state->HandlePolicy(OnDemandPolicy());

  NSArray* expected = @[
    @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES},
    @{@"Username" : @"itadmin", @"UID" : @503, @"Local" : @YES},
  ];
  XCTAssertEqualObjects(self.storedRecord, expected);
  XCTAssertFalse(fake->IsMember(501));
  XCTAssertFalse(fake->IsMember(503));
  // System accounts are neither demoted nor recorded.
  XCTAssertTrue(fake->IsMember(0));
  XCTAssertTrue(fake->IsMember(200));
}

- (void)testFailedDemoteStaysRecordedAndRestoreIsIdempotent {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501, 503};
  fake->names_ = {{501, @"jane"}, {503, @"itadmin"}};
  fake->fail_remove_uids_ = {503};

  state->HandlePolicy(OnDemandPolicy());

  // Persist-before-flip: the failed remove leaves itadmin recorded AND admin.
  NSArray* expected = @[
    @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES},
    @{@"Username" : @"itadmin", @"UID" : @503, @"Local" : @YES},
  ];
  XCTAssertEqualObjects(self.storedRecord, expected);
  XCTAssertFalse(fake->IsMember(501));
  XCTAssertTrue(fake->IsMember(503));

  // Restore: AddMember on the still-admin itadmin is an idempotent no-op.
  state->HandlePolicy(RevokePolicy());
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(fake->IsMember(503));
  XCTAssertNil(self.storedRecord);
}

- (void)testEnumerationFailureWritesNoRecord {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501};
  fake->names_ = {{501, @"jane"}};
  fake->fail_list_ = true;

  state->HandlePolicy(OnDemandPolicy());

  XCTAssertNil(self.storedRecord);     // no record written
  XCTAssertTrue(fake->IsMember(501));  // no flip applied
}

- (void)testZeroAdminsWritesEmptyRecordAsEdgeDetector {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {0};  // only root
  fake->names_ = {{0, @"root"}};

  state->HandlePolicy(OnDemandPolicy());

  // The empty record still marks the flip as applied ...
  XCTAssertNotNil(self.storedRecord);
  XCTAssertEqual(self.storedRecord.count, 0u);

  // ... so a user promoted later is not demoted by the repeated on-policy.
  fake->members_.insert(501);
  fake->names_[501] = @"jane";
  state->HandlePolicy(OnDemandPolicy());
  XCTAssertTrue(fake->IsMember(501));

  // Turning off deletes the record.
  state->HandlePolicy(RevokePolicy());
  XCTAssertNil(self.storedRecord);
}

- (void)testPersistFailureAbortsDemote {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501};
  fake->names_ = {{501, @"jane"}};
  self.persistFails = YES;

  state->HandlePolicy(OnDemandPolicy());

  // No durable record means no flip: nobody is demoted, nothing is recorded.
  XCTAssertNil(self.storedRecord);
  XCTAssertTrue(fake->IsMember(501));

  // The write path recovers; the next delivery performs the full edge.
  self.persistFails = NO;
  state->HandlePolicy(OnDemandPolicy());
  XCTAssertEqualObjects(self.storedRecord, (@[ @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES} ]));
  XCTAssertFalse(fake->IsMember(501));
}

#pragma mark Restore + delete

- (void)testPolicyOffRestoresAndDeletesRecord {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  self.storedRecord = @[
    @{@"Username" : @"jane", @"UID" : @501},
    @{@"Username" : @"itadmin", @"UID" : @503},
  ];

  state->HandlePolicy(RevokePolicy());

  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(fake->IsMember(503));
  XCTAssertNil(self.storedRecord);
}

- (void)testPartialRestoreKeepsRecordUntilComplete {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  NSArray* record = @[
    @{@"Username" : @"jane", @"UID" : @501},
    @{@"Username" : @"itadmin", @"UID" : @503},
  ];
  self.storedRecord = record;
  fake->fail_add_uids_ = {503};

  state->HandlePolicy(RevokePolicy());

  // jane restored, itadmin failed: the record survives in full for the retry
  // at the next sync (Workshop re-sends revoke every preflight).
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertFalse(fake->IsMember(503));
  XCTAssertEqualObjects(self.storedRecord, record);

  // The failure clears; the next delivery completes the restore.
  fake->fail_add_uids_.clear();
  state->HandlePolicy(RevokePolicy());
  XCTAssertTrue(fake->IsMember(503));
  XCTAssertNil(self.storedRecord);
}

- (void)testRestoreWithDeletedAccountCompletes {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  self.storedRecord = @[
    @{@"Username" : @"jane", @"UID" : @501},
    @{@"Username" : @"deleted", @"UID" : @503},
  ];
  fake->gone_uids_ = {503};

  state->HandlePolicy(RevokePolicy());

  XCTAssertTrue(fake->IsMember(501));
  XCTAssertFalse(fake->IsMember(503));  // nothing to restore
  XCTAssertNil(self.storedRecord);      // treated as done; record deleted
}

- (void)testMalformedRecordEntrySkippedAndRecordDeleted {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  self.storedRecord = @[
    @{@"Username" : @"jane", @"UID" : @501},
    @{@"Username" : @"no-uid"},
  ];

  state->HandlePolicy(RevokePolicy());

  // The parsable entry restores; the malformed one can never be restored, so
  // the record is deleted rather than retried forever.
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);
}

- (void)testRecordEntryBelowMinUIDIsNeverRestored {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  // Capture never records system accounts; a uid-0 entry means the record was
  // tampered with or corrupted. It must not be promoted.
  self.storedRecord = @[
    @{@"Username" : @"root", @"UID" : @0},
    @{@"Username" : @"jane", @"UID" : @501},
  ];

  state->HandlePolicy(RevokePolicy());

  XCTAssertFalse(fake->IsMember(0));
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);
}

#pragma mark TAM cross-check

- (void)testCaptureExcludesTAMSessionTargetUnlessStateIsMalformed {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501, 503};
  fake->names_ = {{501, @"jane"}, {503, @"tamuser"}};
  // 503 is in group 80 only because of TAM (active grant or failed-teardown
  // residue) — not a natural admin.
  self.tamSessionState = @{@"TargetUID" : @503};

  state->HandlePolicy(OnDemandPolicy());

  XCTAssertEqualObjects(self.storedRecord, (@[ @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES} ]));
  XCTAssertFalse(fake->IsMember(501));
  XCTAssertTrue(fake->IsMember(503));  // left to TAM's own teardown/retry

  // Same capture with malformed TAM state (no TargetUID): nobody is excluded,
  // so the uid the well-formed state protected above is now captured normally.
  self.storedRecord = nil;
  fake->members_ = {501, 503};
  self.tamSessionState = @{@"TargetUsername" : @"tamuser"};

  state->HandlePolicy(OnDemandPolicy());

  XCTAssertEqualObjects(self.storedRecord, (@[
    @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES},
    @{@"Username" : @"tamuser", @"UID" : @503, @"Local" : @YES},
  ]));
  XCTAssertFalse(fake->IsMember(501));
  XCTAssertFalse(fake->IsMember(503));
}

- (void)testRestoreClearsMatchingTAMRetryResidue {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  self.storedRecord = @[ @{@"Username" : @"jane", @"UID" : @501} ];
  // TAM still owes a demotion for jane from a failed teardown; executing it at
  // the next daemon start would strand her after this deliberate restore.
  self.tamSessionState = @{@"TargetUID" : @501};

  state->HandlePolicy(RevokePolicy());

  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);
  XCTAssertNil(self.tamSessionState);  // the restore supersedes the owed demotion
}

- (void)testRestoreLeavesUnrelatedTAMStateAlone {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  self.storedRecord = @[ @{@"Username" : @"jane", @"UID" : @501} ];
  self.tamSessionState = @{@"TargetUID" : @999};

  state->HandlePolicy(RevokePolicy());

  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);
  XCTAssertEqualObjects(self.tamSessionState, @{@"TargetUID" : @999});
}

#pragma mark Directory accounts + uid reuse

- (void)testUnresolvableDirectoryAccountAtRestoreRetries {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501, 503};
  fake->names_ = {{501, @"jane"}, {503, @"adadmin"}};
  fake->network_uids_ = {503};

  state->HandlePolicy(OnDemandPolicy());

  NSArray* expected = @[
    @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES},
    @{@"Username" : @"adadmin", @"UID" : @503, @"Local" : @NO},
  ];
  XCTAssertEqualObjects(self.storedRecord, expected);
  XCTAssertFalse(fake->IsMember(501));
  XCTAssertFalse(fake->IsMember(503));

  // The directory is unreachable at revoke time: the account resolves to
  // nothing, which for a directory account must NOT be read as deleted.
  fake->gone_uids_ = {503};

  state->HandlePolicy(RevokePolicy());

  XCTAssertTrue(fake->IsMember(501));
  XCTAssertFalse(fake->IsMember(503));
  XCTAssertNotNil(self.storedRecord);  // retained for retry

  // Back on the network: the next delivery completes and deletes the record.
  fake->gone_uids_.clear();
  state->HandlePolicy(RevokePolicy());
  XCTAssertTrue(fake->IsMember(503));
  XCTAssertNil(self.storedRecord);
}

- (void)testReusedUIDIsNeverPromoted {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  self.storedRecord = @[ @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES} ];
  // jane's account was deleted during the window and uid 501 was reassigned
  // to a new account. The new account must not inherit jane's admin.
  fake->names_ = {{501, @"newhire"}};

  state->HandlePolicy(RevokePolicy());

  XCTAssertFalse(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);  // entry is complete, not retried
}

#pragma mark Idempotency across the full cycle

- (void)testRepeatedDeliveryIsIdempotent {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501};
  fake->names_ = {{501, @"jane"}};

  // Revoke before any capture (fleet where the policy was never on): no-op.
  state->HandlePolicy(RevokePolicy());
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);

  state->HandlePolicy(OnDemandPolicy());
  XCTAssertFalse(fake->IsMember(501));

  // During the enabled window jane is re-promoted and 505 newly promoted, out
  // of band (e.g. by other management software). The repeated on-policy at the
  // next sync must demote neither — no fighting — and must not re-capture the
  // record.
  fake->members_ = {501, 505};
  fake->names_[505] = @"newadmin";
  state->HandlePolicy(OnDemandPolicy());
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(fake->IsMember(505));
  XCTAssertEqualObjects(self.storedRecord, (@[ @{@"Username" : @"jane", @"UID" : @501, @"Local" : @YES} ]));

  state->HandlePolicy(RevokePolicy());
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertTrue(fake->IsMember(505));  // untouched: not in the record
  XCTAssertNil(self.storedRecord);

  // Repeated revoke with no record: no-op.
  state->HandlePolicy(RevokePolicy());
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);
}

- (void)testNilOrUnspecifiedPolicyIsNoOp {
  FakeAdminGroupMembership* fake = nullptr;
  auto state = [self makeStateWithFake:&fake];
  fake->members_ = {501};
  fake->names_ = {{501, @"jane"}};

  // No record: neither branch fires. (A nil policy reads as type 0/Unspecified.)
  state->HandlePolicy(nil);
  XCTAssertTrue(fake->IsMember(501));
  XCTAssertNil(self.storedRecord);

  // Record present: still neither branch fires.
  self.storedRecord = @[ @{@"Username" : @"gone", @"UID" : @504} ];
  state->HandlePolicy(nil);
  XCTAssertFalse(fake->IsMember(504));
  XCTAssertEqualObjects(self.storedRecord, (@[ @{@"Username" : @"gone", @"UID" : @504} ]));
}

@end
