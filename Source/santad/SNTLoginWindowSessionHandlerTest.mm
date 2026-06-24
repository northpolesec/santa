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
#include <pwd.h>
#include <unistd.h>

#include <memory>
#include <set>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTStoredTemporaryAdminModeAuditEvent.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#include "Source/santad/AdminGroupMembership.h"
#import "Source/santad/SNTLoginWindowSessionHandler.h"
#import "Source/santad/SNTNotificationQueue.h"

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

@interface SNTLoginWindowSessionHandlerTest : XCTestCase
@property id mockConfigurator;
@property id mockNotQueue;
@end

@implementation SNTLoginWindowSessionHandlerTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  self.mockNotQueue = OCMClassMock([SNTNotificationQueue class]);
}

// Stub an available on-demand policy.
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
  OCMStub([self.mockNotQueue
      authorizeTemporaryAdminModeRequiringJustification:YES
                                                  reply:([OCMArg invokeBlockWithArgs:OCMOCK_VALUE(
                                                                                         authed),
                                                                                     reason,
                                                                                     nil])]);
}

// Build a real TemporaryAdminMode backed by a FakeAdminGroupMembership.
// Returns the TAM; sets *fakeOut and populates eventsOut on each audit event.
- (std::shared_ptr<santa::TemporaryAdminMode>)
    buildTAMWithFake:(FakeAdminGroupMembership**)fakeOut
              events:(NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>*)events {
  auto fakeOwned = std::make_unique<FakeAdminGroupMembership>();
  *fakeOut = fakeOwned.get();
  return santa::TemporaryAdminMode::Create(
      (SNTConfigurator*)self.mockConfigurator, (SNTNotificationQueue*)self.mockNotQueue,
      std::move(fakeOwned), ^(SNTStoredTemporaryAdminModeAuditEvent* e) {
        [events addObject:e];
      });
}

// Helper: grant a session for uid / username, asserting success.
- (void)grantTAM:(std::shared_ptr<santa::TemporaryAdminMode>&)tam
             uid:(uid_t)uid
        username:(NSString*)username {
  NSError* err = nil;
  XCTAssertGreaterThan(tam->RequestMinutes(@5, uid, username, &err), 0u);
  XCTAssertNil(err);
}

#pragma mark - Test cases

// Case 1: LW_SESSION_LOCK with matching username → uid removed, Leave audit with ScreenLocked.
- (void)testLockRevokesSession {
  if (getuid() == 0) {
    XCTSkip(@"handler ignores uid 0; skip when running as root");
  }

  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need admin"];

  uid_t uid = getuid();
  struct passwd* pw = getpwuid(uid);
  NSString* username = @(pw->pw_name);

  FakeAdminGroupMembership* fake = nullptr;
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = [self buildTAMWithFake:&fake events:events];

  [self grantTAM:tam uid:uid username:username];
  XCTAssertTrue(fake->IsMember(uid));

  dispatch_queue_t q =
      dispatch_queue_create("com.test.lwsession", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  SNTLoginWindowSessionHandler* handler =
      [[SNTLoginWindowSessionHandler alloc] initWithTemporaryAdminMode:tam queue:q];

  [handler handleLoginWindowSessionEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK username:username];
  // Drain the serial queue to let the async block complete.
  dispatch_sync(q, ^{
                });

  XCTAssertFalse(fake->IsMember(uid), @"uid should have been removed from admin group");
  SNTStoredTemporaryAdminModeLeaveAuditEvent* leave =
      (SNTStoredTemporaryAdminModeLeaveAuditEvent*)events.lastObject;
  XCTAssertTrue([leave isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
  XCTAssertEqual(leave.reason, SNTTemporaryAdminModeLeaveReasonScreenLocked);
}

// Case 2: LW_SESSION_LOGOUT with matching username → uid removed, Leave audit with SessionEnded.
- (void)testLogoutRevokesSession {
  if (getuid() == 0) {
    XCTSkip(@"handler ignores uid 0; skip when running as root");
  }

  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need admin"];

  uid_t uid = getuid();
  struct passwd* pw = getpwuid(uid);
  NSString* username = @(pw->pw_name);

  FakeAdminGroupMembership* fake = nullptr;
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = [self buildTAMWithFake:&fake events:events];

  [self grantTAM:tam uid:uid username:username];
  XCTAssertTrue(fake->IsMember(uid));

  dispatch_queue_t q =
      dispatch_queue_create("com.test.lwsession", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  SNTLoginWindowSessionHandler* handler =
      [[SNTLoginWindowSessionHandler alloc] initWithTemporaryAdminMode:tam queue:q];

  [handler handleLoginWindowSessionEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT username:username];
  dispatch_sync(q, ^{
                });

  XCTAssertFalse(fake->IsMember(uid));
  SNTStoredTemporaryAdminModeLeaveAuditEvent* leave =
      (SNTStoredTemporaryAdminModeLeaveAuditEvent*)events.lastObject;
  XCTAssertTrue([leave isKindOfClass:[SNTStoredTemporaryAdminModeLeaveAuditEvent class]]);
  XCTAssertEqual(leave.reason, SNTTemporaryAdminModeLeaveReasonSessionEnded);
}

// Case 3: LW_SESSION_LOCK with empty username → early synchronous return; session remains active.
- (void)testLockWithEmptyUsernameIsNoOp {
  if (getuid() == 0) {
    XCTSkip(@"handler ignores uid 0; skip when running as root");
  }

  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need admin"];

  uid_t uid = getuid();
  struct passwd* pw = getpwuid(uid);
  NSString* username = @(pw->pw_name);

  FakeAdminGroupMembership* fake = nullptr;
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = [self buildTAMWithFake:&fake events:events];

  [self grantTAM:tam uid:uid username:username];
  NSUInteger eventsAfterGrant = events.count;

  dispatch_queue_t q =
      dispatch_queue_create("com.test.lwsession", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  SNTLoginWindowSessionHandler* handler =
      [[SNTLoginWindowSessionHandler alloc] initWithTemporaryAdminMode:tam queue:q];

  // Empty username → synchronous early return, no dispatch_async.
  [handler handleLoginWindowSessionEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK username:@""];

  // Session must still be active, no additional audit events.
  XCTAssertTrue(fake->IsMember(uid), @"session should still be active");
  XCTAssertTrue(tam->SecondsRemaining().has_value());
  XCTAssertEqual(events.count, eventsAfterGrant, @"no Leave audit should have been emitted");
}

// Case 4: LW_SESSION_LOCK with a non-resolvable username → session remains active.
- (void)testLockWithUnresolvableUsernameIsNoOp {
  if (getuid() == 0) {
    XCTSkip(@"handler ignores uid 0; skip when running as root");
  }

  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need admin"];

  uid_t uid = getuid();
  struct passwd* pw = getpwuid(uid);
  NSString* username = @(pw->pw_name);

  FakeAdminGroupMembership* fake = nullptr;
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = [self buildTAMWithFake:&fake events:events];

  [self grantTAM:tam uid:uid username:username];
  NSUInteger eventsAfterGrant = events.count;

  dispatch_queue_t q =
      dispatch_queue_create("com.test.lwsession", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  SNTLoginWindowSessionHandler* handler =
      [[SNTLoginWindowSessionHandler alloc] initWithTemporaryAdminMode:tam queue:q];

  [handler handleLoginWindowSessionEvent:ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
                                username:@"no_such_user_zzqq"];
  dispatch_sync(q, ^{
                });

  XCTAssertTrue(fake->IsMember(uid), @"session should still be active for original uid");
  XCTAssertTrue(tam->SecondsRemaining().has_value());
  XCTAssertEqual(events.count, eventsAfterGrant, @"no Leave audit should have been emitted");
}

// Case 5: A non-LW event type (e.g. ES_EVENT_TYPE_NOTIFY_EXEC) → no removal, session intact.
- (void)testNonLWEventTypeIsNoOp {
  if (getuid() == 0) {
    XCTSkip(@"handler ignores uid 0; skip when running as root");
  }

  [self stubPolicyAvailable];
  [self stubAuthReply:YES reason:@"need admin"];

  uid_t uid = getuid();
  struct passwd* pw = getpwuid(uid);
  NSString* username = @(pw->pw_name);

  FakeAdminGroupMembership* fake = nullptr;
  NSMutableArray<SNTStoredTemporaryAdminModeAuditEvent*>* events = [NSMutableArray array];
  auto tam = [self buildTAMWithFake:&fake events:events];

  [self grantTAM:tam uid:uid username:username];
  NSUInteger eventsAfterGrant = events.count;

  dispatch_queue_t q =
      dispatch_queue_create("com.test.lwsession", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  SNTLoginWindowSessionHandler* handler =
      [[SNTLoginWindowSessionHandler alloc] initWithTemporaryAdminMode:tam queue:q];

  [handler handleLoginWindowSessionEvent:ES_EVENT_TYPE_NOTIFY_EXEC username:username];
  // No async work is dispatched for unrecognized events; no drain needed.

  XCTAssertTrue(fake->IsMember(uid), @"session should still be active");
  XCTAssertTrue(tam->SecondsRemaining().has_value());
  XCTAssertEqual(events.count, eventsAfterGrant, @"no Leave audit should have been emitted");
}

@end
