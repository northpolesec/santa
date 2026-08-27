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

#import "Source/santad/SNTBelievableClock.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <cmath>

#import "Source/common/SNTConfigurator.h"
#include "Source/common/SystemResources.h"

typedef BOOL (^StateFileAccessAuthorizer)(void);

// The private initializer that lets a test point a configurator at its own
// state file rather than /var/db/santa. Same declaration SNTConfiguratorTest
// uses.
@interface SNTConfigurator (Testing)
- (instancetype)initWithSyncStateFile:(NSString*)syncStateFilePath
                            stateFile:(NSString*)stateFilePath
            syncStateAccessAuthorizer:(StateFileAccessAuthorizer)syncStateAccessAuthorizer
                stateAccessAuthorizer:(StateFileAccessAuthorizer)stateAccessAuthorizer;
@end

// The seam the clock keeps private: its refresh cadence, and the three host
// readings it is built on. Nothing a test runs can move the host's wall clock,
// restart its mach continuous counter or begin a new boot session, and no test
// should wait ten minutes for a tick, so this is the only way to exercise any
// of it.
@interface SNTBelievableClock (Testing)
- (instancetype)initWithConfigurator:(SNTConfigurator*)configurator
                     refreshInterval:(NSTimeInterval)refreshInterval
                           wallClock:(NSDate* (^)(void))wallClock
                      machContinuous:(uint64_t (^)(void))machContinuous
                     bootSessionUUID:(NSString* (^)(void))bootSessionUUID;
@end

// Counts the reading writes, so a test can assert how many hours of clock
// produce how many, and can stand in the middle of one. Everything else about
// the configurator is real, including the state file on disk.
@interface CountingConfigurator : SNTConfigurator
@property NSUInteger clockReadingWrites;
/// Runs at the top of a write, before the real one. The one case that uses it
/// makes a write take long enough to catch a caller waiting on it.
@property(copy) void (^persistBlock)(void);
@end

@implementation CountingConfigurator
- (BOOL)persistClockReading:(NSDictionary*)reading {
  self.clockReadingWrites++;
  if (self.persistBlock) {
    self.persistBlock();
  }
  return [super persistClockReading:reading];
}
@end

/// The host clocks, moved by hand: a wall time in seconds since 1970, a mach
/// continuous tick count, and the boot session those ticks belong to.
@interface FakeHost : NSObject
@property NSTimeInterval wall;
@property uint64_t mach;
@property(copy) NSString* bootUUID;
- (void)advanceMachBySeconds:(NSTimeInterval)seconds;
@end

@implementation FakeHost
- (void)advanceMachBySeconds:(NSTimeInterval)seconds {
  self.mach = AddNanosecondsToMachTime((uint64_t)(seconds * NSEC_PER_SEC), self.mach);
}
@end

// A fixed wall time to measure everything from, and the uptime the first daemon
// start sees. The uptime is not zero so that a reading from before a reboot can
// be given a larger mach value than the one after it, which is what makes the
// reboot test able to tell "not carried forward" from "carried forward by
// nothing".
static const NSTimeInterval kBaseWall = 1780000000;
static const NSTimeInterval kBaseUptime = 60;

static NSString* const kBootUUIDA = @"6A2B4C8E-0000-0000-0000-00000000000A";
static NSString* const kBootUUIDB = @"6A2B4C8E-0000-0000-0000-00000000000B";

// Wall times are compared in seconds; the fake clocks are exact, so this only
// absorbs the double arithmetic.
static const NSTimeInterval kAccuracy = 0.001;

// A cadence an hour out, for the cases that are about answers rather than about
// the tick: no test runs long enough for it to fire.
static const NSTimeInterval kUntickableInterval = 3600;
// A cadence for the one case that is about the tick.
static const NSTimeInterval kTickInterval = 0.1;

@interface SNTBelievableClockTest : XCTestCase
@property NSFileManager* fileMgr;
@property NSString* testDir;
@property NSString* statePath;
@property CountingConfigurator* configurator;
@end

@implementation SNTBelievableClockTest

- (void)setUp {
  [super setUp];

  self.fileMgr = [NSFileManager defaultManager];
  self.testDir = [NSString stringWithFormat:@"%@santa-believable-clock-%d-%@",
                                            NSTemporaryDirectory(), getpid(), [NSUUID UUID]];
  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);
  self.statePath = [NSString stringWithFormat:@"%@/state.plist", self.testDir];
  self.configurator = [self makeConfigurator];
}

- (void)tearDown {
  [self.fileMgr removeItemAtPath:self.testDir error:nil];
  [super tearDown];
}

#pragma mark Helpers

- (CountingConfigurator*)makeConfigurator {
  CountingConfigurator* cfg = [[CountingConfigurator alloc]
      initWithSyncStateFile:[NSString stringWithFormat:@"%@/sync-state.plist", self.testDir]
      stateFile:self.statePath
      syncStateAccessAuthorizer:^BOOL {
        return YES;
      }
      stateAccessAuthorizer:^BOOL {
        return YES;
      }];
  XCTAssertNotNil(cfg);
  return cfg;
}

/// A host at the base wall time, one minute into boot session A.
- (FakeHost*)makeHost {
  FakeHost* host = [[FakeHost alloc] init];
  host.wall = kBaseWall;
  host.mach = NanosToMachTime((uint64_t)(kBaseUptime * NSEC_PER_SEC));
  host.bootUUID = kBootUUIDA;
  return host;
}

/// A daemon start with a cadence no test will sit through, so the only writes
/// are the ones a case asks for. The tick has its own case, which sets its own
/// cadence.
- (SNTBelievableClock*)startClockOnHost:(FakeHost*)host {
  return [self startClockOnHost:host refreshInterval:kUntickableInterval];
}

/// A daemon start: a clock over `host`, reading and then rewriting whatever the
/// state file holds.
- (SNTBelievableClock*)startClockOnHost:(FakeHost*)host
                        refreshInterval:(NSTimeInterval)refreshInterval {
  SNTBelievableClock* clock = [[SNTBelievableClock alloc] initWithConfigurator:self.configurator
      refreshInterval:refreshInterval
      wallClock:^NSDate* {
        return [NSDate dateWithTimeIntervalSince1970:host.wall];
      }
      machContinuous:^uint64_t {
        return host.mach;
      }
      bootSessionUUID:^NSString* {
        return host.bootUUID;
      }];
  XCTAssertNotNil(clock);
  return clock;
}

- (NSTimeInterval)nowOf:(SNTBelievableClock*)clock {
  return [clock now].timeIntervalSince1970;
}

/// Puts a saved reading on disk as a previous daemon would have left it, and
/// points the configurator at it.
- (void)seedReadingWithWall:(NSTimeInterval)wall
                       mach:(NSTimeInterval)uptimeSeconds
                   bootUUID:(NSString*)bootUUID {
  NSDictionary* state = @{
    @"ClockReading" : @{
      @"Wall" : @(wall),
      @"MachContinuous" : @(NanosToMachTime((uint64_t)(uptimeSeconds * NSEC_PER_SEC))),
      @"BootSessionUUID" : bootUUID,
    },
  };
  XCTAssertTrue([state writeToFile:self.statePath atomically:YES]);
  self.configurator = [self makeConfigurator];
}

- (NSDictionary*)rawStateFile {
  return [NSDictionary dictionaryWithContentsOfFile:self.statePath];
}

#pragma mark Tests

// Time that has passed is not a matter of opinion: mach continuous time says a
// minute went by, so the answer is a minute later than the floor, whatever the
// wall clock has been set to.
- (void)testRollbackWithinABootSessionAnswersFromTheProjection {
  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host];

  [host advanceMachBySeconds:60];
  host.wall = kBaseWall - 3600;

  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall + 60, kAccuracy);
}

// The same across a restart: the reading a previous daemon wrote is on disk, so
// the new one picks up where that one had reached rather than believing the
// clock it comes up to. Reading it back is what needs the state file's key
// allowlist to know about ClockReading.
- (void)testRollbackAcrossADaemonRestartAnswersFromTheSavedReading {
  FakeHost* host = [self makeHost];
  // A start is all it takes: the reading is written at daemon start.
  (void)[self startClockOnHost:host];

  [host advanceMachBySeconds:300];
  host.wall = kBaseWall - 3600;

  // A second daemon start, so the reading comes back off disk.
  self.configurator = [self makeConfigurator];
  XCTAssertNotNil([self.configurator savedClockReading]);
  SNTBelievableClock* restarted = [self startClockOnHost:host];

  XCTAssertEqualWithAccuracy([self nowOf:restarted], kBaseWall + 300, kAccuracy);
}

// A reading from an earlier boot session cannot be carried forward at all: its
// mach value belongs to a counter that has since restarted. The only thing it
// still says is that time had reached its wall value, so that is the answer.
- (void)testRollbackPlusARebootAnswersFromTheSavedWallValue {
  FakeHost* host = [self makeHost];
  (void)[self startClockOnHost:host];

  // A reboot: a new boot session, a mach counter that restarted (and has since
  // reached a value well past the saved one, so carrying it forward would show
  // up as two hours), and a wall clock an hour behind.
  host.bootUUID = kBootUUIDB;
  host.mach = NanosToMachTime((uint64_t)(7200 * NSEC_PER_SEC));
  host.wall = kBaseWall - 3600;

  self.configurator = [self makeConfigurator];
  SNTBelievableClock* rebooted = [self startClockOnHost:host];
  XCTAssertEqualWithAccuracy([self nowOf:rebooted], kBaseWall, kAccuracy);

  // The reading that start wrote is this boot session's, so time moves again.
  [host advanceMachBySeconds:60];
  XCTAssertEqualWithAccuracy([self nowOf:rebooted], kBaseWall + 60, kAccuracy);
}

// A wall clock that jumps forward is believed, and the jump sticks: the floor
// rose to it, so moving the clock back afterwards does not undo it. This is the
// max() rule, not a special case, and it is the behavior the design asks for.
- (void)testAForwardCorrectionWinsImmediatelyAndSticks {
  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host];

  host.wall = kBaseWall + 86400;
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall + 86400, kAccuracy);

  host.wall = kBaseWall;
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall + 86400, kAccuracy);
}

// The floor is kept in memory and the reading is the timer's business, so the
// write volume owes nothing to how busy the machine is: six hours of a clock
// asked for the time every minute is still just the write the start made, and
// the floor has tracked every one of those answers.
- (void)testAskingTheTimeNeverWritesTheReading {
  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host];
  XCTAssertEqual(self.configurator.clockReadingWrites, 1u);

  __block NSUInteger refreshes = 0;
  clock.refreshHandler = ^{
    refreshes++;
  };

  for (int minute = 0; minute < 6 * 60; minute++) {
    [host advanceMachBySeconds:60];
    host.wall = kBaseWall + (minute + 1) * 60;
    (void)[self nowOf:clock];
  }

  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall + 6 * 3600, kAccuracy);
  XCTAssertEqual(self.configurator.clockReadingWrites, 1u);
  XCTAssertEqual(refreshes, 0u);
}

// The tick is what puts a bound on how stale the reading, and the handler
// hanging off it, can be. Nothing in this case ever asks the clock for the time:
// an idle machine is exactly the case a traffic-driven refresh would leave
// waiting indefinitely.
- (void)testTheTickRefreshesTheReadingWithNoOtherTraffic {
  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host refreshInterval:kTickInterval];
  XCTAssertEqual(self.configurator.clockReadingWrites, 1u);

  // Moved before there is anything to wait on, so that no tick can land between
  // the wait starting and the value it is meant to observe being in place.
  host.wall = kBaseWall + 3600;

  XCTestExpectation* refreshed = [self expectationWithDescription:@"the refresh handler ran"];
  // The timer keeps ticking for the life of the clock, so more than one is fine.
  refreshed.assertForOverFulfill = NO;
  clock.refreshHandler = ^{
    [refreshed fulfill];
  };

  [self waitForExpectations:@[ refreshed ] timeout:5.0];
  clock.refreshHandler = nil;

  XCTAssertGreaterThanOrEqual(self.configurator.clockReadingWrites, 2u);
  NSDictionary* reading = [self rawStateFile][@"ClockReading"];
  XCTAssertEqualWithAccuracy([reading[@"Wall"] doubleValue], kBaseWall + 3600, kAccuracy);
}

// The reading shares the state file with the timed rule kills and every timed
// session, so writing one must leave the rest exactly as they were.
- (void)testOtherStateFileKeysAreUntouched {
  NSDictionary* existing = @{
    @"TMM" : @{@"Deadline" : @123},
    @"TempAdmin" : @{@"Deadline" : @456},
    @"DemotedAdmins" : @[ @{@"Username" : @"jane"} ],
    @"TimedRuleKills" : @[ @{@"Identifier" : @"ABCDE12345"} ],
  };
  XCTAssertTrue([existing writeToFile:self.statePath atomically:YES]);

  self.configurator = [self makeConfigurator];
  (void)[self startClockOnHost:[self makeHost]];

  NSDictionary* onDisk = [self rawStateFile];
  XCTAssertEqualObjects(onDisk[@"TMM"], existing[@"TMM"]);
  XCTAssertEqualObjects(onDisk[@"TempAdmin"], existing[@"TempAdmin"]);
  XCTAssertEqualObjects(onDisk[@"DemotedAdmins"], existing[@"DemotedAdmins"]);
  XCTAssertEqualObjects(onDisk[@"TimedRuleKills"], existing[@"TimedRuleKills"]);

  NSDictionary* reading = onDisk[@"ClockReading"];
  XCTAssertEqualWithAccuracy([reading[@"Wall"] doubleValue], kBaseWall, kAccuracy);
  XCTAssertNotNil(reading[@"MachContinuous"]);
  XCTAssertEqualObjects(reading[@"BootSessionUUID"], kBootUUIDA);
}

// The state file is on disk, so a reading is validated rather than trusted. One
// that doesn't check out is no reading at all: the clock starts from the wall
// clock it finds, and a rollback from there is believed because nothing says
// otherwise.
- (void)testAnUnreadableReadingIsIgnored {
  NSDictionary* garbage = @{
    @"ClockReading" : @{@"Wall" : @"soon", @"MachContinuous" : @1, @"BootSessionUUID" : kBootUUIDA},
  };
  XCTAssertTrue([garbage writeToFile:self.statePath atomically:YES]);

  self.configurator = [self makeConfigurator];
  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host];
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall, kAccuracy);

  // Nothing was carried over from the unusable reading, so this start's own
  // floor is all there is: a rollback below it still cannot win.
  host.wall = kBaseWall - 3600;
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall, kAccuracy);
}

// A number is not enough: a plist real carries infinities and NaN, and a floor
// that is either of those is a clock that can never be compared with anything
// again. Such a reading loads as absent.
- (void)testANonFiniteWallValueLoadsAsAbsent {
  [self seedReadingWithWall:INFINITY mach:kBaseUptime bootUUID:kBootUUIDA];
  // The fixture has to really carry a non-finite value, or this case would pass
  // for the wrong reason.
  XCTAssertFalse(std::isfinite([[self.configurator savedClockReading][@"Wall"] doubleValue]));

  SNTBelievableClock* clock = [self startClockOnHost:[self makeHost]];
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall, kAccuracy);
}

// A reading from an earlier boot session has nothing but the system clock left to
// be checked against, so one implausibly far ahead of it is discarded (and
// logged, which has no seam to assert here). Otherwise a single boot with a dead
// RTC would leave a floor years ahead that every later reboot inherits through
// this same branch.
- (void)testACrossBootReadingTooFarAheadIsDiscarded {
  [self seedReadingWithWall:kBaseWall + 31 * 86400 mach:kBaseUptime bootUUID:kBootUUIDB];

  SNTBelievableClock* clock = [self startClockOnHost:[self makeHost]];
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall, kAccuracy);
}

// The other side of that ceiling: a lead this machine could plausibly have had
// is still inherited across the reboot, which is what stops a reboot from being
// a way to shake off a floor.
- (void)testACrossBootReadingWithinTheCeilingIsBelieved {
  [self seedReadingWithWall:kBaseWall + 29 * 86400 mach:kBaseUptime bootUUID:kBootUUIDB];

  SNTBelievableClock* clock = [self startClockOnHost:[self makeHost]];
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall + 29 * 86400, kAccuracy);
}

// The ceiling is a rule about inheriting a lead across a reboot, not about how
// large a lead may be. Inside one boot session mach continuous time vouches for
// the distance, so a reading this boot wrote is believed however far ahead of the
// system clock it is: that is the forward-jump stickiness the design asks for,
// surviving a daemon restart the same way it survives an exec.
- (void)testAWithinBootReadingIsBelievedPastTheCeiling {
  [self seedReadingWithWall:kBaseWall + 60 * 86400 mach:kBaseUptime bootUUID:kBootUUIDA];

  SNTBelievableClock* clock = [self startClockOnHost:[self makeHost]];
  XCTAssertEqualWithAccuracy([self nowOf:clock], kBaseWall + 60 * 86400, kAccuracy);
}

// Writing the reading is a whole state file serialized, renamed into place and
// chmodded. It must not be on the path of a thread asking for the time, because
// those threads are answering executions against a deadline.
- (void)testAWritingTickDoesNotBlockCallersAskingForTheTime {
  static const NSTimeInterval kPersistDuration = 1.0;

  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host refreshInterval:kTickInterval];

  // Set after the start's own write, so only the tick's write is slow.
  dispatch_semaphore_t inWrite = dispatch_semaphore_create(0);
  self.configurator.persistBlock = ^{
    dispatch_semaphore_signal(inWrite);
    [NSThread sleepForTimeInterval:kPersistDuration];
  };

  XCTAssertEqual(
      0l, dispatch_semaphore_wait(inWrite, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)));

  // The tick is inside the write now. Asking for the time must not wait for it.
  NSDate* asked = [NSDate date];
  (void)[self nowOf:clock];
  NSTimeInterval waited = -asked.timeIntervalSinceNow;
  self.configurator.persistBlock = nil;

  XCTAssertLessThan(waited, kPersistDuration / 2);
}

// The handler runs with the clock's lock released, so it may ask the clock for
// the time. That is exactly what a handler checking whether a deadline has come
// due does, and doing it under the lock would deadlock any handler that had to
// wait on another thread for the answer.
- (void)testTheRefreshHandlerMayAskTheClockForTheTime {
  FakeHost* host = [self makeHost];
  SNTBelievableClock* clock = [self startClockOnHost:host refreshInterval:kTickInterval];
  host.wall = kBaseWall + 60;

  XCTestExpectation* asked = [self expectationWithDescription:@"the handler asked for the time"];
  asked.assertForOverFulfill = NO;
  __block NSDate* seen = nil;
  // Weakly, so the handler cannot keep the clock it hangs off alive.
  __weak SNTBelievableClock* weakClock = clock;
  clock.refreshHandler = ^{
    seen = [weakClock now];
    [asked fulfill];
  };

  [self waitForExpectations:@[ asked ] timeout:5.0];
  clock.refreshHandler = nil;

  XCTAssertEqualWithAccuracy(seen.timeIntervalSince1970, kBaseWall + 60, kAccuracy);
}

@end
