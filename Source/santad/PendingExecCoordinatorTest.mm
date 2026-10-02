#import "Source/santad/PendingExecCoordinator.h"

#import <XCTest/XCTest.h>

#include <memory>

#import "Source/common/SantaVnode.h"

using santa::PendingExecCoordinator;

static SantaVnode V(uint64_t dev, uint64_t ino) {
  return SantaVnode{.fsid = (dev_t)dev, .fileid = (ino_t)ino};
}

@interface PendingExecCoordinatorTest : XCTestCase
@end

@implementation PendingExecCoordinatorTest

// NotifyRuleCreated wakes a pending waiter with rule_created == true.
- (void)testNotifyWakesWaiter {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = false;
  coord->Wait(V(1, 100), 5000, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  coord->NotifyRuleCreated(V(1, 100));
  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)));
  XCTAssertTrue(got);
}

// A waiter with no matching notification resolves false on timeout.
- (void)testTimeoutResolvesFalse {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = true;
  coord->Wait(V(1, 101), 50 /* ms */, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)));
  XCTAssertFalse(got);
}

// A notification that lands just before the matching Wait still resolves true
// (recently-resolved window absorbs the registration race).
- (void)testNotifyBeforeWaitResolvesTrue {
  auto coord = std::make_shared<PendingExecCoordinator>();
  coord->NotifyRuleCreated(V(1, 102));
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block bool got = false;
  coord->Wait(V(1, 102), 50 /* ms */, ^(bool ruleCreated) {
    got = ruleCreated;
    dispatch_semaphore_signal(sema);
  });
  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)));
  XCTAssertTrue(got);
}

// Compiler activity opens the gate and self-heals (lapses) after the window (I5).
- (void)testCompilerActivityWindow {
  auto coord = std::make_shared<PendingExecCoordinator>(/*window_ms=*/150);
  XCTAssertFalse(coord->CompilerActiveRecently());
  coord->RecordCompilerActivity();
  XCTAssertTrue(coord->CompilerActiveRecently());
  [NSThread sleepForTimeInterval:0.25];
  XCTAssertFalse(coord->CompilerActiveRecently());
}

// A waiter resolves exactly once: a NotifyRuleCreated after a timeout must not
// invoke the resolve block a second time (I1/I3).
- (void)testResolveExactlyOnceOnTimeoutThenNotify {
  auto coord = std::make_shared<PendingExecCoordinator>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block int calls = 0;
  __block bool firstResult = true;
  coord->Wait(V(3, 300), 50 /* ms */, ^(bool ruleCreated) {
    @synchronized(self) {
      calls++;
      firstResult = ruleCreated;
    }
    dispatch_semaphore_signal(sema);
  });
  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC)));
  coord->NotifyRuleCreated(V(3, 300));  // already resolved by timeout; must be a no-op
  [NSThread sleepForTimeInterval:0.1];
  @synchronized(self) {
    XCTAssertEqual(calls, 1);
    XCTAssertFalse(firstResult);  // resolved via timeout
  }
}

@end
