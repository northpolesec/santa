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

#import "Source/santad/PendingExecCoordinator.h"

#import <XCTest/XCTest.h>

#include <memory>

using santa::PendingExecCoordinator;

static dispatch_time_t TwoSeconds() {
  return dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC);
}

@interface PendingExecCoordinatorTest : XCTestCase
@end

@implementation PendingExecCoordinatorTest

// NotifyRuleCreated wakes a pending waiter with rule_created == true.
- (void)testNotifyWakesWaiter {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = false;
  coord->Wait("aaa", 5000, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  coord->NotifyRuleCreated("aaa");
  XCTAssertEqual(0, dispatch_semaphore_wait(sema, TwoSeconds()));
  XCTAssertTrue(got);
}

// A rule for different content does not wake the waiter, which times out.
- (void)testNotifyForOtherContentDoesNotWake {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = true;
  coord->Wait("aaa", 100 /* ms */, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  coord->NotifyRuleCreated("bbb");
  XCTAssertEqual(0, dispatch_semaphore_wait(sema, TwoSeconds()));
  XCTAssertFalse(got);
}

// A waiter with no matching notification resolves false on timeout.
- (void)testTimeoutResolvesFalse {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = true;
  coord->Wait("ccc", 50 /* ms */, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  XCTAssertEqual(0, dispatch_semaphore_wait(sema, TwoSeconds()));
  XCTAssertFalse(got);
}

// A notification that lands just before the matching Wait still resolves true
// (the recently-created window absorbs the registration race).
- (void)testNotifyBeforeWaitResolvesTrue {
  auto coord = std::make_shared<PendingExecCoordinator>();
  coord->NotifyRuleCreated("ddd");
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = false;
  coord->Wait("ddd", 50 /* ms */, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  XCTAssertEqual(0, dispatch_semaphore_wait(sema, TwoSeconds()));
  XCTAssertTrue(got);
}

// A marked compiler keeps the gate open however long it runs. Once cleared,
// the gate stays open for the window and then closes.
- (void)testCompilerActivityWindow {
  auto coord = std::make_shared<PendingExecCoordinator>(/*window_ms=*/150);
  XCTAssertFalse(coord->CompilerActiveRecently());
  coord->UpdateCompilerMarks(1);
  [NSThread sleepForTimeInterval:0.25];
  XCTAssertTrue(coord->CompilerActiveRecently());
  coord->UpdateCompilerMarks(-1);
  XCTAssertTrue(coord->CompilerActiveRecently());
  [NSThread sleepForTimeInterval:0.25];
  XCTAssertFalse(coord->CompilerActiveRecently());
}

// A waiter resolves exactly once: a NotifyRuleCreated after a timeout must not
// invoke the resolve block a second time.
- (void)testResolveExactlyOnceOnTimeoutThenNotify {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block int calls = 0;
  __block bool firstResult = true;
  coord->Wait("eee", 50 /* ms */, ^(bool ruleCreated) {
    calls++;
    firstResult = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  XCTAssertEqual(0, dispatch_semaphore_wait(sema, TwoSeconds()));
  coord->NotifyRuleCreated("eee");  // already resolved by timeout; must be a no-op

  // Resolves run on one serial queue, so once this later waiter (which takes the
  // recently-created path) has resolved, any stray second resolve of the first
  // waiter would already have run.
  dispatch_semaphore_t barrier = dispatch_semaphore_create(0);
  coord->Wait("eee", 5000, ^(bool) {
    dispatch_semaphore_signal(barrier);
  });
  XCTAssertEqual(0, dispatch_semaphore_wait(barrier, TwoSeconds()));

  XCTAssertEqual(calls, 1);
  XCTAssertFalse(firstResult);
}

// A rule created after a waiter's deadline does not resume it, even when the
// resolution queue is busy and the waiter's timeout has not run yet.
- (void)testNotifyAfterDeadlineResolvesFalseWhileQueueIsBusy {
  auto coord = std::make_shared<PendingExecCoordinator>();

  // Occupy the resolution queue with a resolve that waits on `gate`.
  dispatch_semaphore_t gate = dispatch_semaphore_create(0);
  dispatch_semaphore_t busy = dispatch_semaphore_create(0);
  coord->Wait("busy", 5000, ^(bool) {
    dispatch_semaphore_signal(busy);
    dispatch_semaphore_wait(gate, TwoSeconds());
  });
  coord->NotifyRuleCreated("busy");
  XCTAssertEqual(0, dispatch_semaphore_wait(busy, TwoSeconds()));

  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  __block bool got = true;
  coord->Wait("late", 20 /* ms */, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(done);
  });

  // Past the deadline; the timeout is queued behind the busy resolve.
  [NSThread sleepForTimeInterval:0.1];
  coord->NotifyRuleCreated("late");
  dispatch_semaphore_signal(gate);

  XCTAssertEqual(0, dispatch_semaphore_wait(done, TwoSeconds()));
  XCTAssertFalse(got);
}

@end
