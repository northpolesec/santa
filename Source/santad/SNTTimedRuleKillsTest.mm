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

#import "Source/santad/SNTTimedRuleKills.h"

#import <Foundation/Foundation.h>
#import <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <arpa/inet.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <unistd.h>

#include <climits>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleTimeWindow.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTTimedRuleKillDetails.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#include "Source/common/SystemResources.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/KillEnvTestSupport.h"
#include "Source/santad/KillingMachine.h"
#import "Source/santad/SNTBelievableClock.h"
#import "Source/santad/SNTNotificationQueue.h"

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

// Making these readwrite is how the other rule tests build a rule without
// going through a full initializer.
@interface SNTRule ()
@property(readwrite) SNTRuleState state;
@property(readwrite) SNTRuleType type;
@property(readwrite) NSString* identifier;
@property(readwrite) NSString* celExpr;
@property(readwrite) int64_t ruleId;
@end

// The seams SNTTimedRuleKills keeps private: the interval the countdown timer
// was last armed for, which is how a test sees a rolled-back clock being
// corrected, the serial queue the component does all of its work on, which a
// test drains to observe the result of a record, and the pass that queue runs,
// so a test can run one as of an instant it chooses rather than as of the clock.
@interface SNTTimedRuleKills (Testing)
@property uint32_t armedTimerSeconds;
@property(readonly) dispatch_queue_t queue;
- (void)processDueEntriesSerializedAsOf:(NSDate*)now;
@end

/// The host clocks a test builds a believable clock over: a system wall clock it
/// moves at will, and a mach continuous reading that tracks the real one plus an
/// offset. Mach continuous time is the reading nothing on the machine can move,
/// so a test only ever adds to it, which is how it says "this much time really
/// did pass" while the wall clock says otherwise.
@interface FakeHost : NSObject
@property NSTimeInterval wall;
@property NSTimeInterval machOffsetSeconds;
@property(readonly) uint64_t mach;
@end

@implementation FakeHost
- (uint64_t)mach {
  return AddNanosecondsToMachTime((uint64_t)(self.machOffsetSeconds * NSEC_PER_SEC),
                                  mach_continuous_time());
}
@end

namespace {

// The fake kill env and its team ID are shared with KillingMachineTest. What
// this suite adds is the rest of the code signing lookups: its rules match on a
// signing ID, a CDHash and the platform bit as well as a team ID.
using santa::testing::kMatchingTeamID;
using santa::testing::SignalDescriptions;

// The rest of the code signing identity the fake csops reports for every matched
// pid. Each rule below is written against one of these criteria.
static NSString* const kMatchingSigningID = @"com.apple.ls";
// The hex form of kMatchingCDHashBytes, which is what a CDHASH rule holds.
static NSString* const kMatchingCDHash = @"deadbeefcafebabe0123456789abcdeffedcba98";
static const uint8_t kMatchingCDHashBytes[CS_CDHASH_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23,
    0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};

struct FakeEnv : santa::testing::FakeKillEnv {
  // Puts one process in the fake world that every rule below matches, in a
  // process group of its own.
  void AddMatching(pid_t pid, pid_t pgid) {
    pids->push_back(pid);
    pidversions[pid] = 1;
    matching.insert(pid);
    pgids[pid] = pgid;
  }
};

// Writes `value` into the blob-wrapped form csops returns for the string ops.
int WriteCSOpsBlob(NSString* value, void* useraddr, size_t usersize) {
  if (usersize < sizeof(santa::csops_blob) + 1 + value.length) {
    return -1;
  }
  santa::csops_blob* blob = (santa::csops_blob*)useraddr;
  blob->type = 0;
  blob->len = htonl(sizeof(santa::csops_blob) + 1 + value.length);
  std::memcpy(blob->data, value.UTF8String, value.length);
  return 0;
}

santa::KillEnv MakeEnv(FakeEnv* fake) {
  santa::KillEnv env = santa::testing::MakeKillEnv(fake);

  // The one seam the shared fake does not cover: it answers a team ID and
  // nothing else, and these rules are matched on four criteria.
  env.csops_func = [fake](pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
    if (!fake->matching.count(pid)) {
      return -1;
    }
    switch (ops) {
      case santa::kCsopTeamID: return WriteCSOpsBlob(kMatchingTeamID, useraddr, usersize);
      case santa::kCsopIdentity: return WriteCSOpsBlob(kMatchingSigningID, useraddr, usersize);
      case santa::kCsopCDHash:
        if (usersize != sizeof(kMatchingCDHashBytes)) {
          return -1;
        }
        std::memcpy(useraddr, kMatchingCDHashBytes, sizeof(kMatchingCDHashBytes));
        return 0;
      case santa::kCsopStatus:
        if (usersize != sizeof(uint32_t)) {
          return -1;
        }
        *(uint32_t*)useraddr = CS_PLATFORM_BINARY;
        return 0;
      default: return -1;
    }
  };

  return env;
}

// Seconds of mach continuous time between two readings, which is how a test
// checks where a persisted mach deadline points without knowing the machine's
// timebase.
NSTimeInterval MachSecondsBetween(uint64_t earlier, uint64_t later) {
  return later <= earlier ? 0 : (NSTimeInterval)MachTimeToNanos(later - earlier) / NSEC_PER_SEC;
}

}  // namespace

// A CEL expression that compiles under CELv2, so the rule table accepts the
// rules these tests insert. The text is never evaluated or hashed here.
static NSString* const kCELExpr = @"euid == 0 ? REQUIRE_TOUCHID : ALLOWLIST";

// The server-assigned id the rules and entries below share, and a second one
// standing for an edited rule.
static const int64_t kRuleID = 48213;
static const int64_t kOtherRuleID = 90001;

// Every day of the week, which is what makes a recurring HH:MM window in these
// tests land the same way whichever day they run on.
static NSArray<NSNumber*>* const kEveryDay = @[ @0, @1, @2, @3, @4, @5, @6 ];

static NSString* const kTimedRuleKillsStateKey = @"TimedRuleKills";
static NSString* const kTMMStateKey = @"TMM";

// Fast enough that a case waiting on a refresh finishes, and long enough that a
// case which must not see one never does.
static const NSTimeInterval kFastRefreshInterval = 0.1;
static const NSTimeInterval kUntickableRefreshInterval = 3600;

// A boot session that is not this machine's, for an entry left by an earlier one.
static NSString* const kOtherBootSessionUUID = @"6A2B4C8E-0000-0000-0000-00000000000B";

@interface SNTTimedRuleKillsTest : XCTestCase
@property NSFileManager* fileMgr;
@property NSString* testDir;
@property NSString* statePath;
@property CountingConfigurator* configurator;
@property SNTRuleTable* ruleTable;
@property FMDatabaseQueue* dbq;
@property id mockConfiguratorClass;
@property id mockNotifierQueue;
@property id mockNotifierConnection;
@property id mockNotifierProxy;
/// The process group the one process in the fake world is in.
@property pid_t matchingPgid;
@end

@implementation SNTTimedRuleKillsTest {
  /// The faked syscalls the component's santa::KillEnv runs against, so the
  /// production match and kill code runs against a world the test describes.
  FakeEnv _fake;
}

- (void)setUp {
  [super setUp];

  // A real pid that isn't ours, because the banner names it with real
  // syscalls; the pgid is arbitrary, since every signal is faked.
  self.matchingPgid = getpgrp() + 1;
  _fake.AddMatching(getppid(), self.matchingPgid);

  self.fileMgr = [NSFileManager defaultManager];
  self.testDir = [NSString stringWithFormat:@"%@santa-timed-rule-kills-%d-%@",
                                            NSTemporaryDirectory(), getpid(), [NSUUID UUID]];
  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);
  self.statePath = [NSString stringWithFormat:@"%@/state.plist", self.testDir];

  // The rule table reads the shared configurator for static rules; keep the
  // host's real configuration out of these tests.
  self.mockConfiguratorClass = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfiguratorClass configurator]).andReturn(self.mockConfiguratorClass);

  self.configurator = [self makeConfigurator];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.ruleTable = [[SNTRuleTable alloc] initWithDatabaseQueue:self.dbq];
}

- (void)tearDown {
  [self.mockConfiguratorClass stopMocking];
  // Class mocks swizzle the class itself, so they have to be undone or they
  // follow the process into the next test.
  [self.mockNotifierQueue stopMocking];
  [self.mockNotifierConnection stopMocking];
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

/// The component under test over `clock`, wired to whatever notifier queue
/// setUpNotifierProxy left behind: nil unless a test asked for one, which is the
/// "no GUI running" case.
- (SNTTimedRuleKills*)makeSUTWithClock:(SNTBelievableClock*)clock {
  XCTAssertNotNil(clock);
  SNTTimedRuleKills* sut = [[SNTTimedRuleKills alloc] initWithNotifierQueue:self.mockNotifierQueue
                                                                  ruleTable:self.ruleTable
                                                               configurator:self.configurator
                                                                      clock:clock
                                                                    killEnv:MakeEnv(&_fake)];
  XCTAssertNotNil(sut);
  return sut;
}

/// A real clock over the test's own state file: nothing here moves the host's
/// clock, so the believable time is the system time, which is what these tests
/// build their deadlines from.
- (SNTTimedRuleKills*)makeSUT {
  return
      [self makeSUTWithClock:[[SNTBelievableClock alloc] initWithConfigurator:self.configurator]];
}

/// A host at the current wall time, with no mach time pretended to have elapsed
/// yet.
- (FakeHost*)makeHost {
  FakeHost* host = [[FakeHost alloc] init];
  host.wall = [NSDate date].timeIntervalSince1970;
  return host;
}

/// The component over a clock built on `host`, so a test can move the wall clock
/// the component's deadlines are measured against and choose how often the
/// refresh due-check runs. The component's own mach and boot session readings
/// are the machine's real ones, which is what an entry's mach deadline is
/// compared against.
- (SNTTimedRuleKills*)makeSUTOnHost:(FakeHost*)host refreshInterval:(NSTimeInterval)interval {
  SNTBelievableClock* clock = [[SNTBelievableClock alloc] initWithConfigurator:self.configurator
      refreshInterval:interval
      wallClock:^NSDate* {
        return [NSDate dateWithTimeIntervalSince1970:host.wall];
      }
      machContinuous:^uint64_t {
        return host.mach;
      }
      bootSessionUUID:^NSString* {
        return [SNTSystemInfo bootSessionUUID];
      }];
  return [self makeSUTWithClock:clock];
}

/// The two deliveries a kill makes to the matching process's group: SIGTERM,
/// then SIGKILL to whatever survived the grace period.
- (NSArray<NSString*>*)termThenKillOfTheProcessGroup {
  return @[
    [NSString stringWithFormat:@"group:%d:%d", self.matchingPgid, SIGTERM],
    [NSString stringWithFormat:@"group:%d:%d", self.matchingPgid, SIGKILL],
  ];
}

/// Wires up a notifier queue whose remote proxy is a protocol mock, the same
/// shape SNTNetworkExtensionQueueTest uses. Call before makeSUT; the strong
/// test references keep the stubs alive for the test's duration.
- (id)setUpNotifierProxy {
  self.mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  self.mockNotifierConnection = OCMClassMock([MOLXPCConnection class]);
  self.mockNotifierProxy = OCMProtocolMock(@protocol(SNTNotifierXPC));
  OCMStub([self.mockNotifierQueue notifierConnection]).andReturn(self.mockNotifierConnection);
  OCMStub([self.mockNotifierConnection remoteObjectProxy]).andReturn(self.mockNotifierProxy);
  return self.mockNotifierProxy;
}

- (void)addRuleOfType:(SNTRuleType)type identifier:(NSString*)identifier ruleId:(int64_t)ruleId {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.identifier = identifier;
  rule.type = type;
  rule.state = SNTRuleStateCELv2;
  rule.celExpr = kCELExpr;
  rule.ruleId = ruleId;

  NSArray<NSError*>* errors;
  XCTAssertTrue([self.ruleTable addExecutionRules:@[ rule ]
                                      ruleCleanup:SNTRuleCleanupNone
                                           errors:&errors]);
  XCTAssertEqual(errors.count, 0u, @"%@", errors);
}

/// Waits for everything already enqueued on the component's serial queue,
/// which is where a record lands.
- (void)drain:(SNTTimedRuleKills*)sut {
  dispatch_sync(sut.queue, ^{
                });
}

/// Runs one pass as of `now`, on the queue every pass runs on. The clock is what
/// arms the timer in production; a test that needs a pass at a particular instant
/// relative to a deadline runs it here instead of waiting for one.
- (void)runPassOn:(SNTTimedRuleKills*)sut asOf:(NSDate*)now {
  dispatch_sync(sut.queue, ^{
    [sut processDueEntriesSerializedAsOf:now];
  });
}

- (NSArray<NSDictionary*>*)savedEntries {
  return [self.configurator savedTimedRuleKills];
}

- (NSDictionary*)rawStateFile {
  return [NSDictionary dictionaryWithContentsOfFile:self.statePath];
}

- (NSDictionary*)savedEntryForIdentifier:(NSString*)identifier {
  for (NSDictionary* entry in self.savedEntries) {
    if ([entry[@"Identifier"] isEqualToString:identifier]) {
      return entry;
    }
  }
  return nil;
}

/// A fixed offset zone ([+-]HH:MM) that reads `instant` as `hour`:00 local, to
/// the whole minute. An entry's window is HH:MM in the zone the entry stored, and
/// nothing a test runs can move this host's clock, so the zone is the part these
/// cases choose: an offset picked from the real instant is how one stands inside
/// or outside a fixed 09:00 to 17:00 window on any host at any time of day.
- (NSString*)zoneReading:(NSDate*)instant asHour:(NSInteger)hour {
  NSInteger minutesIntoDayUTC = (NSInteger)floor(instant.timeIntervalSince1970 / 60) % (24 * 60);
  NSInteger offset = hour * 60 - minutesIntoDayUTC;
  // Whole hours into a 24 hour day, so every offset this can produce is inside
  // the [+-]HH:MM range the zone resolver takes.
  XCTAssertLessThan(ABS(offset), 24 * 60);
  return [NSString stringWithFormat:@"%@%02ld:%02ld", offset < 0 ? @"-" : @"+",
                                    (long)(ABS(offset) / 60), (long)(ABS(offset) % 60)];
}

/// Today at a wall-clock hour and minute in the host's own zone, which is what a
/// case standing a fake host inside a "local" window needs.
- (NSDate*)todayAtHour:(NSInteger)hour minute:(NSInteger)minute {
  NSCalendar* calendar = [NSCalendar currentCalendar];
  NSDateComponents* parts =
      [calendar components:(NSCalendarUnitYear | NSCalendarUnitMonth | NSCalendarUnitDay)
                  fromDate:[NSDate date]];
  parts.hour = hour;
  parts.minute = minute;
  parts.second = 0;
  NSDate* date = [calendar dateFromComponents:parts];
  XCTAssertNotNil(date);
  return date;
}

/// The start of the minute `instant` falls in, which is the instant a zone from
/// -zoneReading:asHour: reads as exactly that hour, and so what the end of an
/// occurrence is measured from.
- (NSDate*)minuteFloor:(NSDate*)instant {
  return [NSDate dateWithTimeIntervalSince1970:floor(instant.timeIntervalSince1970 / 60) * 60];
}

/// Records every banner the component sends, in order, as
/// @{@"details": ..., @"signals": ...}, fulfilling `expectation` for each one.
/// `signals` is how many deliveries the kill pass had already made when the
/// banner went out, which is what an ordering test reads. Pass a nil expectation
/// when the test's point is that no banner arrives.
- (void)recordBannersOn:(id)proxy
                   into:(NSMutableArray<NSDictionary*>*)banners
            expectation:(XCTestExpectation*)expectation {
  FakeEnv* fake = &_fake;
  OCMStub([proxy postTimedRuleKillNotification:OCMOCK_ANY]).andDo(^(NSInvocation* invocation) {
    __unsafe_unretained SNTTimedRuleKillDetails* details;
    [invocation getArgument:&details atIndex:2];
    // Built key by key rather than as a literal: andDo() is a macro, and a
    // comma inside a braced literal would be read as another argument to it.
    NSMutableDictionary* banner = [NSMutableDictionary dictionary];
    banner[@"details"] = details;
    banner[@"signals"] = @(fake->signals.size());
    @synchronized(banners) {
      [banners addObject:banner];
    }
    [expectation fulfill];
  });
}

- (SNTCachedDecision*)decisionForRuleType:(SNTRuleType)type
                               identifier:(NSString*)identifier
                                   ruleId:(int64_t)ruleId
                                 deadline:(NSDate*)deadline
                                 notifyAt:(NSDate*)notifyAt
                               windowDays:(NSArray<NSNumber*>*)windowDays
                              windowStart:(NSString*)windowStart
                                windowEnd:(NSString*)windowEnd
                               windowZone:(NSString*)windowZone {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.ruleId = ruleId;
  cd.timedRuleKillRuleType = type;
  cd.timedRuleKillIdentifier = identifier;
  cd.timedRuleKillDeadline = deadline;
  cd.timedRuleKillNotifyAt = notifyAt;
  cd.timedRuleKillWindowDays = windowDays;
  cd.timedRuleKillWindowStart = windowStart;
  cd.timedRuleKillWindowEnd = windowEnd;
  cd.timedRuleKillWindowZone = windowZone;
  return cd;
}

/// Records one shapeless kill under the shared rule id for the fake world's one
/// process. The three sites that need another id (a different key, an edited
/// rule, and the refused id zero) call the full form below.
- (void)record:(SNTTimedRuleKills*)sut
          type:(SNTRuleType)type
    identifier:(NSString*)identifier
      deadline:(NSDate*)deadline
      notifyAt:(NSDate*)notifyAt {
  [self record:sut
            type:type
      identifier:identifier
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(getppid(), 1)];
}

- (void)record:(SNTTimedRuleKills*)sut
          type:(SNTRuleType)type
    identifier:(NSString*)identifier
        ruleId:(int64_t)ruleId
      deadline:(NSDate*)deadline
      notifyAt:(NSDate*)notifyAt
         token:(audit_token_t)token {
  [sut recordKillForDecision:[self decisionForRuleType:type
                                            identifier:identifier
                                                ruleId:ruleId
                                              deadline:deadline
                                              notifyAt:notifyAt
                                            windowDays:nil
                                           windowStart:nil
                                             windowEnd:nil
                                            windowZone:nil]
                     process:token];
}

- (NSDictionary*)entryDictForRuleType:(SNTRuleType)type
                           identifier:(NSString*)identifier
                               ruleId:(int64_t)ruleId
                             deadline:(NSDate*)deadline {
  return [self entryDictForRuleType:type
                         identifier:identifier
                             ruleId:ruleId
                           deadline:deadline
                        liveProcess:NO];
}

- (NSDictionary*)entryDictForRuleType:(SNTRuleType)type
                           identifier:(NSString*)identifier
                               ruleId:(int64_t)ruleId
                             deadline:(NSDate*)deadline
                          liveProcess:(BOOL)liveProcess {
  NSMutableDictionary* dict = [@{
    @"RuleType" : @(type),
    @"Identifier" : identifier,
    @"RuleID" : @(ruleId),
    @"Deadline" : @(deadline.timeIntervalSince1970),
    @"NotifyAt" : @(deadline.timeIntervalSince1970 - 60),
    @"Notified" : @NO,
  } mutableCopy];
  if (liveProcess) {
    // The fake world's one process under this boot's stamp, so a kill or a
    // warning the entry produces has something to reach.
    dict[@"BootSessionUUID"] = [SNTSystemInfo bootSessionUUID];
    dict[@"Processes"] = @[ @{@"Pid" : @(getppid()), @"Pidversion" : @1} ];
  }
  return dict;
}

#pragma mark Recording

- (void)testEarlierScheduleWinsAndEveryExecutionIsRecorded {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* far = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* near = [NSDate dateWithTimeIntervalSinceNow:1800];
  NSDate* farther = [NSDate dateWithTimeIntervalSinceNow:7200];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:far
        notifyAt:[far dateByAddingTimeInterval:-60]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             far.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 1u);

  // An earlier deadline replaces the schedule, recorded here from a second
  // process so the list below is two distinct pairs.
  _fake.pidversions[4100] = 1;
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:near
        notifyAt:[near dateByAddingTimeInterval:-60]
           token:santa::MakeStubAuditToken(4100, 1)];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             near.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u);
  // The schedule moved but the list did not: the first execution is still
  // tracked under the new deadline, with the second appended to it.
  NSArray<NSDictionary*>* processes = self.savedEntries.firstObject[@"Processes"];
  XCTAssertEqual(processes.count, 2u);
  XCTAssertEqualObjects(processes.lastObject[@"Pid"], @4100);

  // A later deadline for the same key leaves the schedule alone, but the exec
  // under it is recorded, so it writes.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:farther
        notifyAt:[farther dateByAddingTimeInterval:-60]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u, @"a later deadline");
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             near.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 3u, @"a later deadline");

  // Re-recording the deadline that already governs is the common case of a
  // binary executing repeatedly inside its window: the schedule does not move,
  // but each exec is a pair appended and written.
  for (int i = 0; i < 5; i++) {
    [self record:sut
              type:SNTRuleTypeTeamID
        identifier:kMatchingTeamID
          deadline:near
          notifyAt:[near dateByAddingTimeInterval:-60]];
  }
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u, @"the same deadline again");
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 8u, @"the same deadline again");

  // A different rule id is a different key, so it is a second entry rather
  // than an arbitration against the first.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kOtherRuleID
        deadline:farther
        notifyAt:[farther dateByAddingTimeInterval:-60]
           token:santa::MakeStubAuditToken(getppid(), 1)];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 2u, @"a different rule id");
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 9u, @"a different rule id");
}

// The three guards on the recording path: a rule type that is not an execution
// rule type, a rule id with no server behind it, and each field the completeness
// check requires.
- (void)testRecordingIsRefusedForUnsupportedTypeBadRuleIdAndIncompleteFields {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  [self record:sut
            type:SNTRuleTypeUnknown
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:deadline];
  [self record:sut type:SNTRuleTypeTeamID identifier:@"" deadline:deadline notifyAt:deadline];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:0
        deadline:deadline
        notifyAt:deadline
           token:santa::MakeStubAuditToken(getppid(), 1)];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:nil
        notifyAt:deadline];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:nil];
  [self drain:sut];

  XCTAssertNil(self.savedEntries, @"one of: unknown rule type, empty identifier, ruleId 0, "
                                  @"nil deadline, nil notifyAt");
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 0u);
}

- (void)testEachExecutionAppendsAProcessAndWritesEachTime {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];

  _fake.pidversions[4001] = 7;
  _fake.pidversions[4002] = 9;
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(4001, 7)];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(4002, 9)];
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, 1u);
  NSArray<NSDictionary*>* processes = self.savedEntries.firstObject[@"Processes"];
  XCTAssertEqual(processes.count, 2u);
  XCTAssertEqualObjects(processes[0][@"Pid"], @4001);
  XCTAssertEqualObjects(processes[0][@"Pidversion"], @7);
  XCTAssertEqualObjects(processes[1][@"Pid"], @4002);
  XCTAssertEqualObjects(processes[1][@"Pidversion"], @9);
  // Every exec is a new pair, so every record writes.
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u);
}

- (void)testRecordingIsRefusedWhenTheBootSessionIsUnreadable {
  // Built before the mock so the component's own setup reads the real session;
  // only the record under test sees the unreadable one.
  SNTTimedRuleKills* sut = [self makeSUT];
  id mockSystemInfo = OCMClassMock([SNTSystemInfo class]);
  OCMStub([mockSystemInfo bootSessionUUID]).andReturn(@"");

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:3300]];
  [self drain:sut];
  [mockSystemInfo stopMocking];

  XCTAssertNil(self.savedEntries);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 0u);
}

- (void)testADeadPairIsPrunedAtRecord {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];

  // A live pid; a pid the fake has no token for; a pid whose pidversion moved on.
  _fake.pidversions[5001] = 1;
  _fake.pidversions[5002] = 4;
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(5001, 1)];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(5999, 1)];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(5002, 3)];
  [self drain:sut];

  NSArray<NSDictionary*>* processes = self.savedEntries.firstObject[@"Processes"];
  XCTAssertEqual(processes.count, 1u);
  XCTAssertEqualObjects(processes.firstObject[@"Pid"], @5001);
}

#pragma mark Persistence

- (void)testEntryWritesPreserveOtherStateKeys {
  [self.configurator persistTimedSessionState:@{@"Deadline" : @123} forKey:kTMMStateKey];

  SNTTimedRuleKills* sut = [self makeSUT];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:3540]];
  [self drain:sut];

  NSDictionary* onDisk = [self rawStateFile];
  XCTAssertEqualObjects(onDisk[kTMMStateKey], (@{@"Deadline" : @123}));
  XCTAssertEqual([onDisk[kTimedRuleKillsStateKey] count], 1u);
}

- (void)testEntriesSurviveReloadButAWrongTypedValueDoesNot {
  NSDictionary* entry = [self entryDictForRuleType:SNTRuleTypeTeamID
                                        identifier:kMatchingTeamID
                                            ruleId:kRuleID
                                          deadline:[NSDate dateWithTimeIntervalSinceNow:3600]];
  XCTAssertTrue([@{kTimedRuleKillsStateKey : @[ entry ]} writeToFile:self.statePath
                                                          atomically:YES]);
  XCTAssertEqual([[self makeConfigurator] savedTimedRuleKills].count, 1u);

  // A value of the wrong type under the key is stripped by the allowlist.
  NSDictionary* wrongType = @{kTimedRuleKillsStateKey : @"not-an-array"};
  XCTAssertTrue([wrongType writeToFile:self.statePath atomically:YES]);
  XCTAssertNil([[self makeConfigurator] savedTimedRuleKills]);
}

// The window shape is part of the entry: written with it, read back with it and
// written out again unchanged, which is what lets a restart re-check the window
// a deadline came from. A zone this host's loader refuses round-trips like any
// other, because whether a zone resolves is asked at the re-check and not at
// load: a load that dropped it would have the next write put the drop on disk
// permanently. The kills recorded from a timestamp or duration window carry no
// shape, so their entries have no window fields at all.
- (void)testWindowShapePersistsAndSurvivesAReload {
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut recordKillForDecision:[self decisionForRuleType:SNTRuleTypeTeamID
                                            identifier:kMatchingTeamID
                                                ruleId:kRuleID
                                              deadline:deadline
                                              notifyAt:notifyAt
                                            windowDays:@[ @1, @3, @5 ]
                                           windowStart:@"09:00"
                                             windowEnd:@"17:00"
                                            windowZone:@"local"]
                     process:santa::MakeStubAuditToken(getppid(), 1)];
  // A second shape whose zone no loader on this host knows, so the load path has
  // to carry a zone it cannot resolve.
  [sut recordKillForDecision:[self decisionForRuleType:SNTRuleTypeSigningID
                                            identifier:kMatchingSigningID
                                                ruleId:kRuleID
                                              deadline:deadline
                                              notifyAt:notifyAt
                                            windowDays:kEveryDay
                                           windowStart:@"09:00"
                                             windowEnd:@"17:00"
                                            windowZone:@"Mars/Olympus"]
                     process:santa::MakeStubAuditToken(getppid(), 1)];
  [self drain:sut];

  NSDictionary* saved = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqualObjects(saved[@"WindowDays"], (@[ @1, @3, @5 ]));
  XCTAssertEqualObjects(saved[@"WindowStart"], @"09:00");
  XCTAssertEqualObjects(saved[@"WindowEnd"], @"17:00");
  XCTAssertEqualObjects(saved[@"WindowZone"], @"local");

  // A restart: a new configurator reads the state file back from disk and a new
  // component loads the entry out of it.
  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* restarted = [self makeSUT];
  [restarted resumeFromSavedState];
  [self drain:restarted];

  // Recording an unrelated entry rewrites the whole set, so what lands on disk
  // for the first entry is what the reload deserialized.
  [self record:restarted
            type:SNTRuleTypeCDHash
      identifier:kMatchingCDHash
        deadline:deadline
        notifyAt:notifyAt];
  [self drain:restarted];

  NSDictionary* reloaded = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqualObjects(reloaded[@"WindowDays"], (@[ @1, @3, @5 ]));
  XCTAssertEqualObjects(reloaded[@"WindowStart"], @"09:00");
  XCTAssertEqualObjects(reloaded[@"WindowEnd"], @"17:00");
  XCTAssertEqualObjects(reloaded[@"WindowZone"], @"local");

  // The unresolvable zone came back whole too, and is on disk again after the
  // write above.
  NSDictionary* unresolvableZone = [self savedEntryForIdentifier:kMatchingSigningID];
  XCTAssertEqualObjects(unresolvableZone[@"WindowZone"], @"Mars/Olympus");
  XCTAssertEqualObjects(unresolvableZone[@"WindowDays"], kEveryDay);
  XCTAssertEqualObjects(unresolvableZone[@"WindowStart"], @"09:00");
  XCTAssertEqualObjects(unresolvableZone[@"WindowEnd"], @"17:00");

  NSDictionary* shapeless = [self savedEntryForIdentifier:kMatchingCDHash];
  XCTAssertNotNil(shapeless);
  XCTAssertNil(shapeless[@"WindowDays"]);
  XCTAssertNil(shapeless[@"WindowStart"]);
  XCTAssertNil(shapeless[@"WindowEnd"]);
  XCTAssertNil(shapeless[@"WindowZone"]);
}

// A shape a window cannot be rebuilt from reads as no shape at all: wrong types,
// a day outside 0-6, a time that isn't HH:MM, or a shape only half there. The
// entry still loads and still holds its deadline, and nothing on the way in is
// sent a message it doesn't answer.
- (void)testMalformedWindowShapeLoadsAsAbsent {
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  // One unusable shape per entry, keyed by the CDHash identifier its entry gets
  // so they can all be asserted together after the reload.
  NSDictionary<NSString*, NSDictionary*>* shapes = @{
    // A day list holding something that isn't a number.
    @"1111111111111111111111111111111111111111" : @{
      @"WindowDays" : @[ @1, @"Wednesday" ],
      @"WindowStart" : @"09:00",
      @"WindowEnd" : @"17:00",
      @"WindowZone" : @"local"
    },
    // A day outside 0 (Sunday) through 6 (Saturday).
    @"2222222222222222222222222222222222222222" : @{
      @"WindowDays" : @[ @42 ],
      @"WindowStart" : @"09:00",
      @"WindowEnd" : @"17:00",
      @"WindowZone" : @"local"
    },
    // A start time that is not a 24-hour HH:MM.
    @"3333333333333333333333333333333333333333" : @{
      @"WindowDays" : @[ @1, @3, @5 ],
      @"WindowStart" : @"banana",
      @"WindowEnd" : @"17:00",
      @"WindowZone" : @"local"
    },
    // An end time that parses as HH:MM but names no hour of the day.
    @"4444444444444444444444444444444444444444" : @{
      @"WindowDays" : @[ @1, @3, @5 ],
      @"WindowStart" : @"09:00",
      @"WindowEnd" : @"25:00",
      @"WindowZone" : @"local"
    },
    // A shape missing its start time.
    @"5555555555555555555555555555555555555555" :
        @{@"WindowDays" : @[ @1, @3, @5 ], @"WindowEnd" : @"17:00", @"WindowZone" : @"local"},
    // A zone that is not a string, which must never become the entry's zone: the
    // re-check sends that -UTF8String. The other two ways a zone can be unusable,
    // a name the resolver refuses and a shape whole but for the zone, are pinned
    // at the kill seam instead by
    // testUnusablePersistedWindowShapesKillRatherThanRescheduling.
    @"6666666666666666666666666666666666666666" : @{
      @"WindowDays" : @[ @1, @3, @5 ],
      @"WindowStart" : @"09:00",
      @"WindowEnd" : @"17:00",
      @"WindowZone" : @42
    },
  };

  NSMutableArray<NSDictionary*>* saved = [NSMutableArray array];
  for (NSString* identifier in shapes) {
    NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeCDHash
                                                  identifier:identifier
                                                      ruleId:kRuleID
                                                    deadline:deadline] mutableCopy];
    [entry addEntriesFromDictionary:shapes[identifier]];
    [saved addObject:entry];
  }
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  // As above, an unrelated recording rewrites what the reload deserialized.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:deadline];
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, shapes.count + 1);
  for (NSString* identifier in shapes) {
    NSDictionary* entry = [self savedEntryForIdentifier:identifier];
    XCTAssertNotNil(entry, @"%@ should still have loaded", identifier);
    XCTAssertNil(entry[@"WindowDays"], @"%@", identifier);
    XCTAssertNil(entry[@"WindowStart"], @"%@", identifier);
    XCTAssertNil(entry[@"WindowEnd"], @"%@", identifier);
    XCTAssertNil(entry[@"WindowZone"], @"%@", identifier);
  }
}

#pragma mark The kill

// Every execution rule type quits the process group of the execution recorded
// under it: SIGTERM, five seconds, then SIGKILL to whatever is still there. The
// five types take one path; the only per-type code left is the fire-time rule
// lookup through IdentifiersForEntry, which each row exercises by its own
// identifier, the `platform:` SIGNINGID form included.
- (void)testEveryRuleTypeTermsThenKillsTheRecordedProcessGroup {
  NSArray<NSArray*>* rows = @[
    @[ @(SNTRuleTypeTeamID), kMatchingTeamID ],
    @[ @(SNTRuleTypeSigningID), [NSString stringWithFormat:@"platform:%@", kMatchingSigningID] ],
    @[ @(SNTRuleTypeCDHash), kMatchingCDHash ],
    @[ @(SNTRuleTypeBinary), @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670" ],
    @[
      @(SNTRuleTypeCertificate), @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258"
    ],
  ];

  SNTTimedRuleKills* sut = [self makeSUT];
  for (NSArray* row in rows) {
    SNTRuleType type = (SNTRuleType)[row[0] integerValue];
    NSString* identifier = row[1];
    _fake.signals.clear();
    _fake.waits.clear();
    [self addRuleOfType:type identifier:identifier ruleId:kRuleID];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
    [self record:sut type:type identifier:identifier deadline:deadline notifyAt:deadline];
    [self waitForEntriesToClear:sut];
    [self drain:sut];

    XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup],
                          @"%@", identifier);
    XCTAssertEqual(_fake.waits.size(), 1u, @"%@", identifier);
    XCTAssertEqualWithAccuracy(_fake.waits.front(), 5.0, 0.001);
    // The clear reached disk, not just the configurator's in-memory state.
    XCTAssertNil([self rawStateFile][kTimedRuleKillsStateKey], @"%@", identifier);
  }
}

// Two deadlines landing in one pass share one grace period: every due entry
// is collected into a single kill call. Both rules cover the one process, so
// the shared group is also signaled once per pass.
- (void)testDeadlinesInOnePassShareTheGracePeriod {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:kMatchingCDHash ruleId:kRuleID];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut type:SNTRuleTypeTeamID identifier:kMatchingTeamID deadline:due notifyAt:due];
  [self record:sut type:SNTRuleTypeCDHash identifier:kMatchingCDHash deadline:due notifyAt:due];

  [self waitForEntriesToClear:sut];
  [self drain:sut];

  XCTAssertEqual(_fake.waits.size(), 1u);
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

- (void)testFireBuildsOneRequestPerRecordedPairAndSharesOneGrace {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  _fake.pidversions[6001] = 1;
  _fake.pgids[6001] = self.matchingPgid;
  _fake.pidversions[6002] = 1;
  _fake.pgids[6002] = self.matchingPgid + 1;

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:due
        notifyAt:due
           token:santa::MakeStubAuditToken(6001, 1)];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:due
        notifyAt:due
           token:santa::MakeStubAuditToken(6002, 1)];

  [self waitForEntriesToClear:sut];
  [self drain:sut];

  // Both groups are termed, one grace period passes, both are killed.
  XCTAssertEqual(_fake.waits.size(), 1u);
  XCTAssertEqualObjects(
      SignalDescriptions(_fake.signals), (@[
        [NSString stringWithFormat:@"group:%d:%d", self.matchingPgid, SIGTERM],
        [NSString stringWithFormat:@"group:%d:%d", self.matchingPgid + 1, SIGTERM],
        [NSString stringWithFormat:@"group:%d:%d", self.matchingPgid, SIGKILL],
        [NSString stringWithFormat:@"group:%d:%d", self.matchingPgid + 1, SIGKILL],
      ]));
}

- (void)testAnEntryWhosePairsAreAllDeadKillsNothingAndIsSpent {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  _fake.pidversions[7001] = 1;

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:due
        notifyAt:due
           token:santa::MakeStubAuditToken(7001, 1)];
  [self drain:sut];
  // The recorded process exits before the deadline. Done on the component's own
  // queue: the timer is armed half a second out and its block reads pidversions,
  // and this is the only fake mutation in the suite with a live reader.
  dispatch_sync(sut.queue, ^{
    _fake.pidversions.erase(7001);
  });

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);
  XCTAssertNil(self.savedEntries);
}

// Both branches of the fire-time re-check, in one pass: the CDHash entry's rule
// was never added (gone), and the TeamID entry was recorded under an id the
// added rule does not hold (edited). Either one failing to drop signals.
- (void)testRuleThatIsGoneOrEditedDropsTheEntryWithoutKilling {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut
            type:SNTRuleTypeCDHash
      identifier:kMatchingCDHash
        deadline:deadline
        notifyAt:deadline];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kOtherRuleID
        deadline:deadline
        notifyAt:deadline
           token:santa::MakeStubAuditToken(getppid(), 1)];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 2u);

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[],
                        @"a rule that is gone or edited has no kill coming");
}

#pragma mark The warning banner

- (void)testWarningNamesTheRunningProcessAndIsRecorded {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];

  // The banner arrives long before the deadline, so the timer fired for the
  // warning rather than the kill.
  [self waitForExpectations:@[ posted ] timeout:10];
  [self drain:sut];

  XCTAssertEqual(banners.count, 1u);
  SNTTimedRuleKillDetails* details = banners.firstObject[@"details"];
  // Named from the recorded process, not from the rule it ran under.
  XCTAssertGreaterThan(details.application.length, 0u);
  XCTAssertNotEqualObjects(details.application, kMatchingTeamID);
  XCTAssertEqualWithAccuracy(details.deadline.timeIntervalSince1970, deadline.timeIntervalSince1970,
                             0.001);
  // The warning reads the recorded process and signals nothing.
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);

  // The entry is still pending, now marked warned on disk so a restart doesn't
  // warn again.
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testWarningFallsBackToTheRuleIdentifierWhenTheProcessCannotBeNamed {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  // The one recorded process is a pid nothing can be read for, which is what a
  // process that exited between the record and the banner looks like.
  _fake = FakeEnv();
  _fake.AddMatching(99999999, self.matchingPgid);

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]
           token:santa::MakeStubAuditToken(99999999, 1)];

  [self waitForExpectations:@[ posted ] timeout:10];

  XCTAssertEqual(banners.count, 1u);
  XCTAssertEqualObjects([banners.firstObject[@"details"] application], kMatchingTeamID);
}

// What the banner carries beyond the name: every row but the deadline and the
// window shape is read off the recorded process, which is this test's own
// parent, the one process the fake world holds. A recorded process is never this
// process itself, so the parent is the nearest one whose fields the test can
// check. The identity rows come from the fake csops, which answers for the
// recorded pid, so they are pinned; Publisher comes from a real signature check
// on the parent and is not.
- (void)testWarningDetailsComeFromTheRecordedProcess {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  // Reads the deadline as 18:00, past the window's close, so the warning pass
  // leaves the deadline standing and the banner goes out.
  NSString* zone = [self zoneReading:deadline asHour:18];
  [sut recordKillForDecision:[self decisionForRuleType:SNTRuleTypeTeamID
                                            identifier:kMatchingTeamID
                                                ruleId:kRuleID
                                              deadline:deadline
                                              notifyAt:notifyAt
                                            windowDays:kEveryDay
                                           windowStart:@"09:00"
                                             windowEnd:@"17:00"
                                            windowZone:zone]
                     process:santa::MakeStubAuditToken(getppid(), 1)];

  [self runPassOn:sut asOf:notifyAt];

  char pathBuf[PROC_PIDPATHINFO_MAXSIZE] = {};
  XCTAssertGreaterThan(proc_pidpath(getppid(), pathBuf, sizeof(pathBuf)), 0);
  NSString* path = @(pathBuf);

  XCTAssertEqual(banners.count, 1u);
  SNTTimedRuleKillDetails* details = banners.firstObject[@"details"];
  XCTAssertEqualObjects(details.path, path);
  XCTAssertEqualObjects(details.application, path.lastPathComponent);
  // The recorded process launched this test, so it runs as the same user.
  XCTAssertEqualObjects(details.user, NSUserName());
  XCTAssertGreaterThan(details.ppid.intValue, 0);
  // The shape the entry was recorded with, carried through for the dialog to
  // spell out.
  XCTAssertEqualObjects(details.timeWindow.days, kEveryDay);
  XCTAssertEqualObjects(details.timeWindow.startOfDay, @"09:00");
  XCTAssertEqualObjects(details.timeWindow.endOfDay, @"17:00");
  XCTAssertEqualObjects(details.timeWindow.zoneName, zone);
  NSString* expectedSigningID =
      [NSString stringWithFormat:@"%@:%@", kMatchingTeamID, kMatchingSigningID];
  XCTAssertEqualObjects(details.signingID, expectedSigningID);
  XCTAssertEqualObjects(details.cdhash, kMatchingCDHash);
}

// A pid libproc cannot read, standing in for a process that exited between the
// record and the banner. The fake still answers its token and csops, so the
// identity rows stay; every row read through libproc is absent and the dialog
// hides those.
- (void)testWarningDetailsAreBestEffortForAProcessThatIsGone {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  _fake = FakeEnv();
  _fake.AddMatching(INT_MAX, self.matchingPgid);

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(INT_MAX, 1)];

  [self runPassOn:sut asOf:notifyAt];

  XCTAssertEqual(banners.count, 1u);
  SNTTimedRuleKillDetails* details = banners.firstObject[@"details"];
  XCTAssertEqualObjects(details.application, kMatchingTeamID);
  XCTAssertEqualWithAccuracy(details.deadline.timeIntervalSince1970, deadline.timeIntervalSince1970,
                             0.001);
  XCTAssertEqual(details.ruleType, SNTRuleTypeTeamID);
  XCTAssertNil(details.path);
  XCTAssertNil(details.user);
  XCTAssertNil(details.publisher);
  NSString* expectedSigningID =
      [NSString stringWithFormat:@"%@:%@", kMatchingTeamID, kMatchingSigningID];
  XCTAssertEqualObjects(details.signingID, expectedSigningID);
  XCTAssertEqualObjects(details.cdhash, kMatchingCDHash);
}

// The warning reads a pair's token once, then DetailsForEntry reads it again
// after collecting the process's details. A process that exits between the two
// reads yields no details, and the next recorded pair is named instead. The
// recycle is armed after the records land so the record-time prune reads are
// not the ones that trip it.
- (void)testWarningSkipsAPairWhoseProcessVanishesWhileReadAndNamesTheNext {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];
  _fake.pidversions[9001] = 1;

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(9001, 1)];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:notifyAt];
  [self drain:sut];

  // The fake counts a pid's reads only once a recycle is armed, so the prune
  // reads at record are not counted. The warning's own read is the first: it
  // returns the matching pidversion and then bumps it, so DetailsForEntry's
  // re-check fails.
  _fake.recycleAfterNthRead[9001] = 1;

  [self runPassOn:sut asOf:notifyAt];

  char pathBuf[PROC_PIDPATHINFO_MAXSIZE] = {};
  XCTAssertGreaterThan(proc_pidpath(getppid(), pathBuf, sizeof(pathBuf)), 0);
  XCTAssertEqual(banners.count, 1u);
  XCTAssertEqualObjects([banners.firstObject[@"details"] path], @(pathBuf));
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testNoWarningWhenTheOnlyRecordedProcessVanishesWhileRead {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:notifyAt];
  [self drain:sut];

  // Armed after the record lands, as in the test above.
  _fake.recycleAfterNthRead[getppid()] = 1;

  [self runPassOn:sut asOf:notifyAt];

  XCTAssertEqual(banners.count, 0u);
  // One warning attempt per rule deadline, banner or not.
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testNoWarningWhenNothingMatchingIsRunning {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  // Nothing is running at all: the recorded pair has no token, so it is pruned
  // at record and nothing is left to name.
  _fake = FakeEnv();

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];

  [self
      waitUntil:^BOOL {
        return [self.savedEntries.firstObject[@"Notified"] boolValue];
      }
      described:@"warning pass ran"];
  [self drain:sut];

  XCTAssertEqual(banners.count, 0u);
  // The pass is recorded even though no banner went out: it runs once per
  // (rule, deadline), whether or not it had anything to warn about.
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

// A rule withdrawn during the lead window has no kill coming, so warning about
// it would promise a quit that never happens. The entry goes at warning time
// rather than sitting until a deadline it will never act on.
- (void)testNoWarningWhenTheRuleIsGoneAndTheEntryIsDropped {
  // No rule is ever added, so the warning-time re-check finds nothing. The
  // recorded process is live, so a banner would go out if the pass ever got as
  // far as looking.
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);

  // Cleared at warning time, an hour before the deadline it was recorded for.
  [self waitForEntriesToClear:sut];

  XCTAssertEqual(banners.count, 0u);
}

- (void)testWarningNeverDelaysTheKill {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:kMatchingCDHash ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  // Warning the entry that is being killed is what a regression here looks
  // like, and an over-fulfilled expectation aborts the whole process; let the
  // assertions below report it instead.
  posted.assertForOverFulfill = NO;
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  // One entry warning at `due`, one entry deadlined at `due`: the same pass.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:due];
  [self record:sut type:SNTRuleTypeCDHash identifier:kMatchingCDHash deadline:due notifyAt:due];

  [self waitForExpectations:@[ posted ] timeout:10];
  [self drain:sut];

  // Both of the kill's deliveries were already out when the banner went, so
  // the process snapshot behind the warning never held the kill up.
  XCTAssertEqual(banners.count, 1u);
  XCTAssertEqualObjects(banners.firstObject[@"signals"], @2);
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

#pragma mark Restart

- (void)testRestartDoesNotWarnAgainForAnAlreadyWarnedEntry {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                           ruleId:kRuleID
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                      liveProcess:YES] mutableCopy];
  entry[@"NotifyAt"] = @([NSDate dateWithTimeIntervalSinceNow:-60].timeIntervalSince1970);
  entry[@"Notified"] = @YES;
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  id proxy = [self setUpNotifierProxy];
  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  [sut resumeFromSavedState];
  [self drain:sut];

  // The entry's recorded process is live, so the only reason no banner went
  // out is the flag the entry was restored with.
  XCTAssertEqual(banners.count, 0u);
  XCTAssertEqual(self.savedEntries.count, 1u);
}

// A Notified value that isn't a number (an array here, from a corrupted or
// hand-edited state file) must never reach -boolValue: that raises
// unrecognized-selector and crash-loops the daemon at every startup, since
// resumeFromSavedState runs on every launch. The entry loads with notified = NO
// instead, so the load is clean and the warning it still owes goes out.
- (void)testMalformedNotifiedValueLoadsAsNotWarnedAndDoesNotThrow {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                           ruleId:kRuleID
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                      liveProcess:YES] mutableCopy];
  // A warning is still owed, and Notified is the wrong type.
  entry[@"NotifyAt"] = @([NSDate dateWithTimeIntervalSinceNow:-60].timeIntervalSince1970);
  entry[@"Notified"] = @[ @"not", @"a", @"number" ];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  id proxy = [self setUpNotifierProxy];
  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  // Not throwing here is the point: the malformed Notified was guarded, not sent
  // -boolValue.
  [sut resumeFromSavedState];

  // The warning fires, which only happens if the entry loaded with notified NO.
  [self waitForExpectations:@[ posted ] timeout:10];
  [self drain:sut];

  XCTAssertEqual(banners.count, 1u);
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testRestartRunsPastDueEntryAfterRecheck {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  XCTAssertTrue([self.configurator
      persistTimedRuleKills:@[ [self
                                entryDictForRuleType:SNTRuleTypeTeamID
                                          identifier:kMatchingTeamID
                                              ruleId:kRuleID
                                            deadline:[NSDate dateWithTimeIntervalSinceNow:-3600]
                                         liveProcess:YES] ]]);

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
  XCTAssertNil(self.savedEntries);
}

- (void)testRestartRestoresTheTimerForAFutureEntry {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  XCTAssertTrue([self.configurator
      persistTimedRuleKills:@[ [self entryDictForRuleType:SNTRuleTypeTeamID
                                               identifier:kMatchingTeamID
                                                   ruleId:kRuleID
                                                 deadline:[NSDate dateWithTimeIntervalSinceNow:1]
                                              liveProcess:YES] ]]);

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];
  // Not due yet: still pending, waiting on the restored timer.
  XCTAssertEqual(self.savedEntries.count, 1u);

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

- (void)testRestartDropsMalformedEntries {
  // A plist real round-trips both infinities and NaN, and neither is an instant.
  // A NaN deadline is the worst of them: it answers false to every "has this come
  // due" question and leaves the countdown arming for zero seconds forever.
  NSMutableDictionary* notANumber = [[self entryDictForRuleType:SNTRuleTypeCDHash
                                                     identifier:kMatchingCDHash
                                                         ruleId:kRuleID
                                                       deadline:[NSDate date]] mutableCopy];
  notANumber[@"Deadline"] = @(NAN);
  NSMutableDictionary* infinite =
      [[self entryDictForRuleType:SNTRuleTypeSigningID
                       identifier:kMatchingSigningID
                           ruleId:kRuleID
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]] mutableCopy];
  infinite[@"NotifyAt"] = @(INFINITY);

  NSArray<NSDictionary*>* saved = @[
    // No type, rule id or deadline.
    @{@"Identifier" : kMatchingTeamID},
    // No identifier or rule id.
    @{@"RuleType" : @(SNTRuleTypeTeamID), @"Deadline" : @1},
    notANumber,
    infinite,
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                        ruleId:kRuleID
                      deadline:[NSDate dateWithTimeIntervalSinceNow:3600]],
  ];
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  // Read back off disk, or the two non-finite rows would never have been plist
  // values at all and this would pass for the wrong reason.
  self.configurator = [self makeConfigurator];
  XCTAssertFalse(
      std::isfinite([[self savedEntryForIdentifier:kMatchingCDHash][@"Deadline"] doubleValue]));
  XCTAssertFalse(
      std::isfinite([[self savedEntryForIdentifier:kMatchingSigningID][@"NotifyAt"] doubleValue]));

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualObjects(self.savedEntries.firstObject[@"Identifier"], kMatchingTeamID);
}

// The three fields this feature added go through one validator. A RuleID that
// is not a positive whole number within its type drops the entry; a process
// element with such a pid or pidversion is dropped on its own and the rest of
// the list loads.
- (void)testMalformedRuleIDsDropTheEntryAndMalformedProcessesDropTheElement {
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSMutableArray<NSDictionary*>* saved = [NSMutableArray array];

  // Each is a TEAMID entry with a distinct identifier so the survivors can be
  // told apart; none of these may load.
  NSArray* badRuleIDs = @[ @0, @-1, @1.5, @(NAN), @(INFINITY), @(1e19) ];
  for (NSUInteger index = 0; index < badRuleIDs.count; index++) {
    NSMutableDictionary* entry =
        [[self entryDictForRuleType:SNTRuleTypeTeamID
                         identifier:[NSString stringWithFormat:@"BAD%07lu", (unsigned long)index]
                             ruleId:kRuleID
                           deadline:deadline] mutableCopy];
    entry[@"RuleID"] = badRuleIDs[index];
    [saved addObject:entry];
  }

  // The largest id its type holds is still a valid id.
  NSMutableDictionary* maxRuleID = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                    identifier:@"MAXRULEID0"
                                                        ruleId:kRuleID
                                                      deadline:deadline] mutableCopy];
  maxRuleID[@"RuleID"] = @(std::numeric_limits<int64_t>::max());
  [saved addObject:maxRuleID];

  // One entry under this boot's stamp whose list holds one valid pair among
  // several that are not.
  NSMutableDictionary* processes = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                    identifier:kMatchingTeamID
                                                        ruleId:kRuleID
                                                      deadline:deadline] mutableCopy];
  processes[@"BootSessionUUID"] = [SNTSystemInfo bootSessionUUID];
  processes[@"Processes"] = @[
    @{@"Pid" : @0, @"Pidversion" : @1},
    @{@"Pid" : @2.5, @"Pidversion" : @1},
    @{@"Pid" : @((long long)std::numeric_limits<int>::max() + 1), @"Pidversion" : @1},
    @{@"Pid" : @10, @"Pidversion" : @-3},
    @"not a dictionary",
    @{@"Pid" : @(std::numeric_limits<int>::max()), @"Pidversion" : @1},
  ];
  [saved addObject:processes];
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  // Read back off disk, so every value went through the plist round trip.
  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];
  // An unrelated record rewrites the set, so what lands is what loaded.
  [self record:sut
            type:SNTRuleTypeCDHash
      identifier:kMatchingCDHash
        deadline:deadline
        notifyAt:deadline];
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, 3u);
  XCTAssertNotNil([self savedEntryForIdentifier:@"MAXRULEID0"]);
  NSArray<NSDictionary*>* loaded = [self savedEntryForIdentifier:kMatchingTeamID][@"Processes"];
  XCTAssertEqual(loaded.count, 1u);
  XCTAssertEqualObjects(loaded.firstObject[@"Pid"], @(std::numeric_limits<int>::max()));
}

#pragma mark The window re-check

// The stored zone is the calendar the window is re-checked in, not the host's,
// and an occurrence still standing at a deadline moves it rather than firing it.
// Two entries past due at one instant with one window and two stored fixed
// offsets five hours apart: the first reads the instant as 12:00, inside 09:00
// to 17:00, so its deadline goes to the end of the occurrence in progress; the
// second reads it as 17:00, where the occurrence has just ended, so its deadline
// arrived on time and what its rule covers is quit. A re-check that read the
// host's zone would read one clock for both and answer the same way twice.
// Fixed offsets rather than named zones so the instants are arithmetic, and
// offsets read off the clock rather than written down so the pair means the same
// thing on any host at any time of day.
- (void)testTheStoredZoneGovernsTheWindowRecheck {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:kMatchingCDHash ruleId:kRuleID];

  NSDate* now = [NSDate date];
  NSString* openZone = [self zoneReading:now asHour:12];
  NSString* closedZone = [self zoneReading:now asHour:17];

  NSMutableArray<NSDictionary*>* saved = [NSMutableArray array];
  // The open row is a deadline an hour old, which is what a machine that slept
  // through one wakes up to. The closed row's deadline is the occurrence's own
  // end: a window holds up to but not including its end, so this is the deadline
  // arriving on time rather than a window standing open at it.
  for (NSArray* row in @[
         @[ @(SNTRuleTypeTeamID), kMatchingTeamID, openZone, [now dateByAddingTimeInterval:-3600] ],
         @[ @(SNTRuleTypeCDHash), kMatchingCDHash, closedZone, [self minuteFloor:now] ],
       ]) {
    NSMutableDictionary* entry = [[self entryDictForRuleType:(SNTRuleType)[row[0] integerValue]
                                                  identifier:row[1]
                                                      ruleId:kRuleID
                                                    deadline:row[3]
                                                 liveProcess:YES] mutableCopy];
    entry[@"WindowDays"] = kEveryDay;
    entry[@"WindowStart"] = @"09:00";
    entry[@"WindowEnd"] = @"17:00";
    entry[@"WindowZone"] = row[2];
    // A warning already delivered for the old deadline, on both rows: the moved
    // deadline is a different one and owes its own, and the row that is quit is
    // gone before the warning pass looks at it.
    entry[@"Notified"] = @YES;
    [saved addObject:entry];
  }
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  // One rule's worth of deliveries: the row whose window had ended. The
  // rescheduled row covers the same process and would have doubled them.
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);

  // The other moved to 17:00 in its own zone, five hours on from the clock, and
  // kept the shape so the next pass can ask again.
  XCTAssertEqual(self.savedEntries.count, 1u);
  NSDictionary* rescheduled = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqualWithAccuracy([rescheduled[@"Deadline"] doubleValue],
                             [self minuteFloor:now].timeIntervalSince1970 + 5 * 3600, 1);
  // The lead the new occurrence earns: a tenth of its 8 hours, 48 minutes.
  XCTAssertEqualWithAccuracy([rescheduled[@"NotifyAt"] doubleValue],
                             [rescheduled[@"Deadline"] doubleValue] - 2880, 0.001);
  // The warning is owed again: this is a different deadline from the one the
  // user was already warned about.
  XCTAssertFalse([rescheduled[@"Notified"] boolValue]);
  XCTAssertEqualObjects(rescheduled[@"WindowZone"], openZone);
  XCTAssertEqualObjects(rescheduled[@"WindowDays"], kEveryDay);
  // A moved appointment keeps the executions it was recorded for.
  XCTAssertEqual([rescheduled[@"Processes"] count], 1u);
}

// A window that cannot be asked is no window, and its deadline stands. The first
// row would reschedule if its day list could be read: its zone reads the instant
// as 12:00, inside 09:00 to 17:00, which is the arrangement the open row of
// testTheStoredZoneGovernsTheWindowRecheck moves from. The rows differ in where
// the shape gives out: the day list and the absent zone give out at load, the
// unresolvable zone at the re-check, which is the one row of the three that
// keeps its shape on the way in. Every row is past due, so a kill is the defect
// being read as no window rather than as an open one.
- (void)testUnusablePersistedWindowShapesKillRatherThanRescheduling {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  NSDate* now = [NSDate date];
  NSDictionary<NSString*, NSDictionary*>* shapes = @{
    @"a day list holding something that isn't a number" :
        @{@"WindowDays" : @[ @1, @"Wednesday" ], @"WindowZone" : [self zoneReading:now asHour:12]},
    // The shape loads whole, and the resolver refuses the zone when the re-check
    // asks: no zone, so no window to be inside. The design calls that past-due,
    // which means kill.
    @"a zone the resolver refuses" : @{@"WindowDays" : kEveryDay, @"WindowZone" : @"Mars/Olympus"},
    // A partial shape, however it got there: "09:00" names no instant without a
    // zone, so the entry behaves exactly like one that never had a shape.
    @"a shape whole but for its zone" : @{@"WindowDays" : kEveryDay},
  };

  for (NSString* defect in shapes) {
    _fake.signals.clear();
    NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                  identifier:kMatchingTeamID
                                                      ruleId:kRuleID
                                                    deadline:[now dateByAddingTimeInterval:-3600]
                                                 liveProcess:YES] mutableCopy];
    entry[@"WindowStart"] = @"09:00";
    entry[@"WindowEnd"] = @"17:00";
    [entry addEntriesFromDictionary:shapes[defect]];
    XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]], @"%@", defect);

    // A fresh configurator reads the entry just written back off disk, so each
    // row is a restart of its own.
    self.configurator = [self makeConfigurator];
    SNTTimedRuleKills* sut = [self makeSUT];
    [sut resumeFromSavedState];
    [self drain:sut];

    XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup],
                          @"%@", defect);
    XCTAssertNil(self.savedEntries, @"%@", defect);
  }
}

// A window with no gap between occurrences, at a deadline the pass reached a
// fraction of a second early, which is what a timer firing marginally early
// looks like. The occurrence that closes at the deadline is still standing at
// that instant, so asking the window there answers "open until the deadline" and
// spends the deadline on a kill the window never asked for. The window is asked
// at the deadline instead, where the occurrence standing is the next one, so the
// appointment moves. Start equal to end is the 24-hour form of a contiguous
// window; back-to-back occurrences behave the same way.
- (void)testAnEarlyFireOnAContiguousWindowMovesTheDeadlineRatherThanKilling {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  // On a whole minute, which is where a window edge lands, and far enough ahead
  // that the component's own timer cannot reach it while the test runs: the pass
  // below is the one being driven.
  NSDate* deadline = [[self minuteFloor:[NSDate date]] dateByAddingTimeInterval:120];
  NSString* zone = [self zoneReading:deadline asHour:9];
  NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                identifier:kMatchingTeamID
                                                    ruleId:kRuleID
                                                  deadline:deadline
                                               liveProcess:YES] mutableCopy];
  // 09:00 to 09:00 in a zone that reads the deadline as exactly 09:00: one
  // occurrence ends there and the next begins there.
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"09:00";
  entry[@"WindowZone"] = zone;
  entry[@"Notified"] = @YES;
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u, @"not due yet");

  // Inside the due tolerance, but before the deadline.
  [self runPassOn:sut asOf:[deadline dateByAddingTimeInterval:-0.1]];

  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[],
                        @"the window runs on, so nothing is quit");
  XCTAssertEqual(self.savedEntries.count, 1u);
  NSDictionary* rescheduled = self.savedEntries.firstObject;
  // The end of the occurrence that stands at the deadline, a day on.
  XCTAssertEqualWithAccuracy([rescheduled[@"Deadline"] doubleValue],
                             deadline.timeIntervalSince1970 + 24 * 3600, 0.001);
  XCTAssertFalse([rescheduled[@"Notified"] boolValue]);
  XCTAssertEqualObjects(rescheduled[@"WindowZone"], zone);
  XCTAssertEqual([rescheduled[@"Processes"] count], 1u);
}

// The warning a lead window before a deadline the kill path will refuse to
// spend. The occurrences of a 09:00 to 09:00 window abut, so at the deadline the
// next one is standing and the appointment moves; the warning pass asks the
// window too, so the deadline moves here instead of a banner promising a quit
// that nothing five minutes later carries out. Without that check the banner
// goes out at every notify time for as long as the window recurs.
- (void)testAWarningOnAnAbuttingWindowMovesTheDeadlineRatherThanBannering {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  // On a whole minute, where a window edge lands, and far enough ahead that the
  // component's own timer cannot reach the notify time while the test runs: the
  // pass below is the one being driven.
  NSDate* deadline = [[self minuteFloor:[NSDate date]] dateByAddingTimeInterval:3600];
  // The lead a 24 hour occurrence earns, which is where the warning pass runs.
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  [sut recordKillForDecision:[self decisionForRuleType:SNTRuleTypeTeamID
                                            identifier:kMatchingTeamID
                                                ruleId:kRuleID
                                              deadline:deadline
                                              notifyAt:notifyAt
                                            windowDays:kEveryDay
                                           windowStart:@"09:00"
                                             windowEnd:@"09:00"
                                            windowZone:[self zoneReading:deadline asHour:9]]
                     process:santa::MakeStubAuditToken(getppid(), 1)];

  [self runPassOn:sut asOf:notifyAt];

  // The recorded process is live, so a banner would have gone out if the pass
  // had got as far as looking for something to name.
  XCTAssertEqual(banners.count, 0u);
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);
  // The end of the occurrence standing at the old deadline, a day on, with the
  // warning owed again against it.
  NSDictionary* rescheduled = self.savedEntries.firstObject;
  XCTAssertEqualWithAccuracy([rescheduled[@"Deadline"] doubleValue],
                             deadline.timeIntervalSince1970 + 24 * 3600, 0.001);
  XCTAssertFalse([rescheduled[@"Notified"] boolValue]);
}

// The defer above is the window's answer, not the presence of a window. Here the
// day list leaves out the day the deadline lands on, so nothing stands there and
// the occurrence before it closed at that instant: the last occurrence of a
// bounded schedule, which is a weekdays-only window warning at 08:55 on the
// Saturday. The deadline is real, so the banner goes out and is recorded.
- (void)testAWarningOnTheLastOccurrenceOfABoundedWindowStillBanners {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  NSDate* deadline = [[self minuteFloor:[NSDate date]] dateByAddingTimeInterval:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  // A fixed offset from -zoneReading:asHour: moves the clock without moving the
  // date, so the day the deadline falls on in that zone is its UTC day. Epoch day
  // zero was a Thursday, which is where the 4 comes from.
  NSInteger deadlineDay = ((NSInteger)floor(deadline.timeIntervalSince1970 / 86400) + 4) % 7;
  NSMutableArray<NSNumber*>* days = [NSMutableArray array];
  for (NSInteger day = 0; day < 7; day++) {
    if (day != deadlineDay) {
      [days addObject:@(day)];
    }
  }

  [sut recordKillForDecision:[self decisionForRuleType:SNTRuleTypeTeamID
                                            identifier:kMatchingTeamID
                                                ruleId:kRuleID
                                              deadline:deadline
                                              notifyAt:notifyAt
                                            windowDays:days
                                           windowStart:@"09:00"
                                             windowEnd:@"09:00"
                                            windowZone:[self zoneReading:deadline asHour:9]]
                     process:santa::MakeStubAuditToken(getppid(), 1)];

  [self runPassOn:sut asOf:notifyAt];

  XCTAssertEqual(banners.count, 1u);
  // Named the deadline it was recorded for: nothing moved it.
  XCTAssertEqualWithAccuracy([[banners.firstObject[@"details"] deadline] timeIntervalSince1970],
                             deadline.timeIntervalSince1970, 0.001);
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

// The notify time of an entry recorded within a lead of its window's close is
// clamped to the exec, so the distance from it to the deadline is no measure of
// anything. A reschedule takes the lead from the new occurrence's length, or that
// clamp would follow the entry into every occurrence after it.
- (void)testAClampedNotifyTimeIsNotCarriedOntoTheNextOccurrence {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  NSDate* now = [NSDate date];
  NSDate* deadline = [now dateByAddingTimeInterval:-3600];
  NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                identifier:kMatchingTeamID
                                                    ruleId:kRuleID
                                                  deadline:deadline
                                               liveProcess:YES] mutableCopy];
  // Recorded a second before the window closed, which is all the warning that
  // exec could have had.
  entry[@"NotifyAt"] = @(deadline.timeIntervalSince1970 - 1);
  // A 30 minute occurrence standing open now, so the past-due deadline moves to
  // its end.
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"09:30";
  entry[@"WindowZone"] = [self zoneReading:now asHour:9];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);
  NSDictionary* rescheduled = self.savedEntries.firstObject;
  XCTAssertEqualWithAccuracy([rescheduled[@"Deadline"] doubleValue],
                             [self minuteFloor:now].timeIntervalSince1970 + 30 * 60, 1);
  // The 30 minute occurrence earns the 5 minute floor, not the one second the
  // old notify time was clamped to.
  XCTAssertEqualWithAccuracy([rescheduled[@"NotifyAt"] doubleValue],
                             [rescheduled[@"Deadline"] doubleValue] - 300, 0.001);
}

// A shape the window math itself refuses, which is what a day outside 0 through
// 6 is. There is no window to be inside, so the answer is the same as a closed
// one: proceed to the kill, rather than throwing or holding the entry forever.
- (void)testAWindowEvaluationErrorProceedsToTheKill {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [sut recordKillForDecision:[self decisionForRuleType:SNTRuleTypeTeamID
                                            identifier:kMatchingTeamID
                                                ruleId:kRuleID
                                              deadline:deadline
                                              notifyAt:deadline
                                            windowDays:@[ @42 ]
                                           windowStart:@"09:00"
                                             windowEnd:@"17:00"
                                            windowZone:@"local"]
                     process:santa::MakeStubAuditToken(getppid(), 1)];

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

#pragma mark A moved clock

// A recording carries the mach deadline the wall one was measured against, and
// the boot session that mach value belongs to. Both are what let a later pass
// tell how much time has really gone by.
- (void)testRecordingCapturesTheMachDeadlineAndBootSession {
  SNTTimedRuleKills* sut = [self makeSUT];
  uint64_t machBefore = mach_continuous_time();
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:[deadline dateByAddingTimeInterval:-300]];
  [self drain:sut];

  NSDictionary* saved = self.savedEntries.firstObject;
  XCTAssertEqualObjects(saved[@"BootSessionUUID"], [SNTSystemInfo bootSessionUUID]);
  XCTAssertEqualWithAccuracy(
      MachSecondsBetween(machBefore, [saved[@"MachDeadline"] unsignedLongLongValue]), 3600, 5);
}

/// A fast-refreshing component over `host` with one kill recorded an hour out,
/// which is where both rollback cases start from.
- (SNTTimedRuleKills*)makeSUTWithAnHourOutKillOnHost:(FakeHost*)host {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];

  NSDate* deadline = [NSDate dateWithTimeIntervalSince1970:host.wall + 3600];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:deadline];
  [self drain:sut];
  return sut;
}

// The system clock goes back a day while an hour of mach continuous time passes.
// The hour is the part a rolled-back clock cannot argue with, so the deadline an
// hour out has come due, and the refresh is what notices: the countdown timer
// runs on the system clock and is still counting the hour it was armed for.
- (void)testARolledBackClockStillKillsAtTheNextRefresh {
  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut = [self makeSUTWithAnHourOutKillOnHost:host];
  XCTAssertEqual(self.savedEntries.count, 1u);

  host.machOffsetSeconds = 3600;
  host.wall -= 86400;

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

// The same rollback with less mach time behind it leaves the deadline in the
// future, so nothing is killed; what the refresh does instead is re-arm the
// countdown for the ten minutes the believable clock says are left, rather than
// leaving it counting the hour it was armed for on a clock that has since moved.
- (void)testTheCountdownIsReArmedFromTheBelievableClockAfterARollback {
  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut = [self makeSUTWithAnHourOutKillOnHost:host];
  XCTAssertEqual(sut.armedTimerSeconds, 3600u);

  host.machOffsetSeconds = 3000;
  host.wall -= 86400;

  [self
      waitUntil:^BOOL {
        return sut.armedTimerSeconds != 3600;
      }
      described:@"the countdown was re-armed"];
  XCTAssertEqualWithAccuracy((double)sut.armedTimerSeconds, 600, 2);
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);
  XCTAssertEqual(self.savedEntries.count, 1u);
}

/// A fast-refreshing component resumed onto one saved entry whose wall deadline
/// is an hour out, whose mach half is `machDeadline` in `bootSession`, and whose
/// recorded process is the fake world's one, stamped with that same session.
- (SNTTimedRuleKills*)resumeOnHost:(FakeHost*)host
                  withMachDeadline:(uint64_t)machDeadline
                       bootSession:(NSString*)bootSession {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                           ruleId:kRuleID
                         deadline:[NSDate dateWithTimeIntervalSince1970:host.wall + 3600]
                      liveProcess:YES] mutableCopy];
  entry[@"MachDeadline"] = @(machDeadline);
  entry[@"BootSessionUUID"] = bootSession;
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  [sut resumeFromSavedState];
  return sut;
}

// A mach deadline half a second out against a wall deadline an hour out:
// whichever of the two arrives first fires the kill, so this one fires at the
// next refresh rather than in an hour.
- (void)testAMachDeadlineFiresWhileTheWallDeadlineIsStillOut {
  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut =
      [self resumeOnHost:host
          withMachDeadline:AddNanosecondsToMachTime((uint64_t)(0.5 * NSEC_PER_SEC),
                                                    mach_continuous_time())
               bootSession:[SNTSystemInfo bootSessionUUID]];

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

// The same entry from an earlier boot session. Its mach value belongs to a
// counter that has since restarted, so it says nothing at all and the wall
// instant is left to govern: an hour out, so nothing is killed.
- (void)testAMachDeadlineFromAnEarlierBootSessionIsIgnored {
  FakeHost* host = [self makeHost];
  // A mach deadline long past, from a boot session that is not this machine's.
  SNTTimedRuleKills* sut = [self resumeOnHost:host
                             withMachDeadline:1
                                  bootSession:kOtherBootSessionUUID];
  [self drain:sut];

  // Several refreshes go by, every one of them looking at the entry. Every
  // refresh rewrites the reading, and the clock's construction wrote one.
  [self
      waitUntil:^BOOL {
        return self.configurator.clockReadingWrites > 3;
      }
      described:@"refreshes ran"];
  [self drain:sut];

  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);
  XCTAssertEqual(self.savedEntries.count, 1u);
}

// The boot stamp says which boot the mach deadline and the process list belong
// to. A mach half that is missing, malformed or stamped with another boot is
// absent after the load, and the entry itself still loads with its wall
// deadline governing. Not throwing is half the point, since reaching
// -unsignedLongLongValue or -isEqualToString: on the wrong type would crash-loop
// the daemon: every pass over the entries looks at these fields.
- (void)testBootBoundFieldsLoadOnlyUnderThisBootsStamp {
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  // A mach deadline long past, so an entry that wrongly honored half a pair
  // would be due the moment it loaded.
  NSNumber* pastMachDeadline = @1;

  // identifier -> what is written over the entry. MachDeadline must be absent on
  // every row: none carries a usable one under this boot's stamp, and an entry
  // that honored half a pair would be due the moment it loaded. Every row comes
  // back stamped with this boot, since load stamps whatever it keeps.
  NSString* currentBoot = [SNTSystemInfo bootSessionUUID];
  NSDictionary<NSString*, NSDictionary*>* pairs = @{
    // Neither field is the type it should be.
    @"1111111111111111111111111111111111111111" :
        @{@"MachDeadline" : @[ @"not", @"a", @"number" ], @"BootSessionUUID" : @17},
    // A mach deadline with no boot session to read it against.
    @"2222222222222222222222222222222222222222" : @{@"MachDeadline" : pastMachDeadline},
    // A boot session with no mach deadline.
    @"3333333333333333333333333333333333333333" : @{@"BootSessionUUID" : currentBoot},
    // A usable mach deadline whose boot session is the wrong type.
    @"4444444444444444444444444444444444444444" :
        @{@"MachDeadline" : pastMachDeadline, @"BootSessionUUID" : @17},
    // This boot's stamp over a mach deadline that is not a number: the stamp
    // loads and the mach half does not, so the next record captures one.
    @"5555555555555555555555555555555555555555" :
        @{@"MachDeadline" : @"soon", @"BootSessionUUID" : currentBoot},
  };

  NSMutableArray<NSDictionary*>* saved = [NSMutableArray array];
  for (NSString* identifier in pairs) {
    [self addRuleOfType:SNTRuleTypeCDHash identifier:identifier ruleId:kRuleID];
    NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeCDHash
                                                  identifier:identifier
                                                      ruleId:kRuleID
                                                    deadline:deadline] mutableCopy];
    [entry addEntriesFromDictionary:pairs[identifier]];
    [saved addObject:entry];
  }

  // A foreign boot's entry: the stamp does not match, so the pair and the mach
  // deadline under it are both meaningless and both go. The wall schedule is all
  // that survives, which is why the entry itself is still here, restamped.
  [self addRuleOfType:SNTRuleTypeCDHash
           identifier:@"6666666666666666666666666666666666666666"
               ruleId:kRuleID];
  NSMutableDictionary* foreignBoot =
      [[self entryDictForRuleType:SNTRuleTypeCDHash
                       identifier:@"6666666666666666666666666666666666666666"
                           ruleId:kRuleID
                         deadline:deadline
                      liveProcess:YES] mutableCopy];
  foreignBoot[@"MachDeadline"] = pastMachDeadline;
  foreignBoot[@"BootSessionUUID"] = kOtherBootSessionUUID;
  [saved addObject:foreignBoot];
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  // An unrelated recording rewrites the whole set, so what lands on disk for
  // these entries is what the reload deserialized.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:deadline];
  [self drain:sut];

  // Every wall deadline is an hour out, and no half pair may make one due.
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);
  XCTAssertEqual(self.savedEntries.count, pairs.count + 2);
  for (NSString* identifier in pairs) {
    NSDictionary* entry = [self savedEntryForIdentifier:identifier];
    XCTAssertNotNil(entry, @"%@ should still have loaded", identifier);
    XCTAssertNil(entry[@"MachDeadline"], @"%@", identifier);
    XCTAssertEqualObjects(entry[@"BootSessionUUID"], currentBoot, @"%@", identifier);
  }

  NSDictionary* restamped =
      [self savedEntryForIdentifier:@"6666666666666666666666666666666666666666"];
  XCTAssertNotNil(restamped);
  XCTAssertNil(restamped[@"Processes"]);
  XCTAssertNil(restamped[@"MachDeadline"]);
  XCTAssertEqualObjects(restamped[@"BootSessionUUID"], currentBoot);
}

// A clock that jumps forward is believed, so both the warning's moment and the
// deadline are behind us in the same pass. The kill goes ahead and the banner is
// dropped: a warning is never allowed to hold up a kill, and there is nothing
// left to warn about.
- (void)testAForwardJumpKillsAndSkipsTheBanner {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];
  id proxy = [self setUpNotifierProxy];

  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  NSDate* deadline = [NSDate dateWithTimeIntervalSince1970:host.wall + 3600];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:[deadline dateByAddingTimeInterval:-60]];
  [self drain:sut];

  host.wall += 7200;

  [self waitForEntriesToClear:sut];
  [self drain:sut];

  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
  XCTAssertEqual(banners.count, 0u);
}

// The window re-check reached on the mach side: the mach deadline says the
// moment has passed while the believable wall clock still sits inside the
// occurrence. The entry's deadline is that occurrence's own end, so there is no
// later end to move to and the kill goes ahead rather than being deferred by the
// size of whatever moved the wall clock.
- (void)testAMachDueEntryInsideItsOwnOccurrenceKills {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID ruleId:kRuleID];

  FakeHost* host = [self makeHost];
  host.wall = [self todayAtHour:16 minute:0].timeIntervalSince1970;

  NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                identifier:kMatchingTeamID
                                                    ruleId:kRuleID
                                                  deadline:[self todayAtHour:17 minute:0]
                                               liveProcess:YES] mutableCopy];
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"17:00";
  entry[@"WindowZone"] = @"local";
  // Long past, and this boot session's, so the mach side is what makes it due.
  entry[@"MachDeadline"] = @1;
  entry[@"BootSessionUUID"] = [SNTSystemInfo bootSessionUUID];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  [sut resumeFromSavedState];

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

- (void)testAnEntryLoadedFromAForeignBootGetsItsMachDeadlineBackOnTheNextRecord {
  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                           ruleId:kRuleID
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]] mutableCopy];
  entry[@"MachDeadline"] = @1;
  entry[@"BootSessionUUID"] = kOtherBootSessionUUID;
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  uint64_t machBefore = mach_continuous_time();
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:3300]];
  [self drain:sut];

  NSDictionary* saved = self.savedEntries.firstObject;
  XCTAssertEqualObjects(saved[@"BootSessionUUID"], [SNTSystemInfo bootSessionUUID]);
  XCTAssertEqualWithAccuracy(
      MachSecondsBetween(machBefore, [saved[@"MachDeadline"] unsignedLongLongValue]), 3600, 5);
}

- (void)testAPriorMachDeadlineIsKeptUnchangedAcrossRecords {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:deadline
        notifyAt:notifyAt];
  [self drain:sut];
  uint64_t first = [self.savedEntries.firstObject[@"MachDeadline"] unsignedLongLongValue];

  // A later exec at the deadline that already governs appends its pair and
  // leaves the anchored mach deadline alone.
  _fake.pidversions[8001] = 1;
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
          ruleId:kRuleID
        deadline:deadline
        notifyAt:notifyAt
           token:santa::MakeStubAuditToken(8001, 1)];
  [self drain:sut];
  XCTAssertEqual([self.savedEntries.firstObject[@"MachDeadline"] unsignedLongLongValue], first);
  XCTAssertEqual([self.savedEntries.firstObject[@"Processes"] count], 2u);
}

// A deadline further out than a tick count carries stores no mach deadline, and
// must not lose the boot stamp the process list depends on.
- (void)testADeadlineBeyondTheMachHorizonKeepsTheBootStampAndTheProcesses {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* farOut = [NSDate dateWithTimeIntervalSinceNow:11 * 365 * 24 * 3600.0];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
        deadline:farOut
        notifyAt:[farOut dateByAddingTimeInterval:-300]];
  [self drain:sut];

  NSDictionary* saved = self.savedEntries.firstObject;
  XCTAssertNil(saved[@"MachDeadline"]);
  XCTAssertEqualObjects(saved[@"BootSessionUUID"], [SNTSystemInfo bootSessionUUID]);
  XCTAssertEqual([saved[@"Processes"] count], 1u);

  // The same boot after a restart: the stamp matches, so the list survives.
  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* restarted = [self makeSUT];
  [restarted resumeFromSavedState];
  [self drain:restarted];
  [self record:restarted
            type:SNTRuleTypeCDHash
      identifier:kMatchingCDHash
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:3300]];
  [self drain:restarted];

  NSDictionary* reloaded = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqual([reloaded[@"Processes"] count], 1u);
  XCTAssertNil(reloaded[@"MachDeadline"]);
}

#pragma mark Helpers that wait

/// Polls `condition` until it holds. The component works on its own queue at a
/// time the test doesn't control, so state it has written is waited for rather
/// than assumed.
- (void)waitUntil:(BOOL (^)(void))condition described:(NSString*)description {
  XCTestExpectation* met = [self expectationWithDescription:description];
  dispatch_source_t poll =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
  dispatch_source_set_timer(poll, dispatch_time(DISPATCH_TIME_NOW, 0), 50 * NSEC_PER_MSEC, 0);
  __block BOOL done = NO;
  dispatch_source_set_event_handler(poll, ^{
    if (!done && condition()) {
      done = YES;
      [met fulfill];
    }
  });
  dispatch_resume(poll);
  [self waitForExpectations:@[ met ] timeout:10];
  dispatch_source_cancel(poll);
}

/// Polls until the component has cleared its persisted entries, which happens
/// once every recorded deadline has been processed. Drains first: a record is
/// asynchronous, and "no entries persisted" is also true before its write lands,
/// so polling straight away can pass before the deadline was ever processed.
- (void)waitForEntriesToClear:(SNTTimedRuleKills*)sut {
  [self drain:sut];
  [self
      waitUntil:^BOOL {
        return self.savedEntries == nil;
      }
      described:@"entries cleared"];
}

@end
