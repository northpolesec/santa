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
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#import <arpa/inet.h>
#include <mach/mach_time.h>
#include <signal.h>

#include <cmath>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTSystemInfo.h"
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
@end

// The seam the clock keeps private: its refresh cadence and the three host
// readings it is built on. Nothing a test runs can move the host's wall clock,
// and no test should wait ten minutes for a refresh, so this is the only way to
// exercise either. Same declaration SNTBelievableClockTest uses.
@interface SNTBelievableClock (Testing)
- (instancetype)initWithConfigurator:(SNTConfigurator*)configurator
                     refreshInterval:(NSTimeInterval)refreshInterval
                           wallClock:(NSDate* (^)(void))wallClock
                      machContinuous:(uint64_t (^)(void))machContinuous
                     bootSessionUUID:(NSString* (^)(void))bootSessionUUID;
@end

// The seams SNTTimedRuleKills keeps private: the kill pass and the process
// snapshot behind a warning, neither of which has a safe form to exercise
// against real processes, the interval the countdown timer was last armed for,
// which is how a test sees a rolled-back clock being corrected, and the serial
// queue the component does all of its work on, which a test drains to observe
// the result of a record.
@interface SNTTimedRuleKills (Testing)
@property(copy) NSArray<SNTKillResponse*>* (^killBlock)
    (NSArray<SNTKillRequest*>* requests, NSTimeInterval grace);
@property(copy) NSNumber* (^matchBlock)(SNTKillRequest* request);
@property uint32_t armedTimerSeconds;
@property(readonly) dispatch_queue_t queue;
@end

// Counts the writes the component makes, so a test can assert that a repeated
// recording of the same deadline writes nothing, and the clock's, which is how a
// test waits for a refresh to have happened rather than for a length of time.
// Everything else about the configurator is real, including the state file on
// disk.
@interface CountingConfigurator : SNTConfigurator
@property NSUInteger timedRuleKillWrites;
@property NSUInteger clockReadingWrites;
@end

@implementation CountingConfigurator
- (BOOL)persistTimedRuleKills:(NSArray<NSDictionary*>*)entries {
  self.timedRuleKillWrites++;
  return [super persistTimedRuleKills:entries];
}

- (BOOL)persistClockReading:(NSDictionary*)reading {
  self.clockReadingWrites++;
  return [super persistClockReading:reading];
}
@end

namespace {

// The fake kill env, its team IDs and the fake host clock are shared with
// KillingMachineTest and TimedRuleKillsScenarioTest; this suite fakes every seam
// the same way, so it takes them as they come.
using FakeEnv = santa::testing::FakeKillEnv;
using santa::testing::kMatchingTeamID;
using santa::testing::kSecondTeamID;
using santa::testing::MakeKillEnv;
using santa::testing::SignalDescriptions;

// Seconds of mach continuous time between two readings, which is how a test
// checks where a persisted mach deadline points without knowing the machine's
// timebase.
NSTimeInterval MachSecondsBetween(uint64_t earlier, uint64_t later) {
  return later <= earlier ? 0 : (NSTimeInterval)MachTimeToNanos(later - earlier) / NSEC_PER_SEC;
}

}  // namespace

// A CEL expression that compiles under CELv2, so the rule table accepts the
// rules these tests insert. The text itself is never evaluated here; only its
// hash matters.
static NSString* const kCELExpr = @"euid == 0 ? REQUIRE_TOUCHID : ALLOWLIST";
static NSString* const kEditedCELExpr = @"euid == 1 ? REQUIRE_TOUCHID : ALLOWLIST";

static NSString* const kTimedRuleKillsStateKey = @"TimedRuleKills";
static NSString* const kTMMStateKey = @"TMM";
static NSString* const kTAMStateKey = @"TempAdmin";

// Every day of the week, which is what makes a recurring HH:MM window in these
// tests land the same way whichever day they run on.
static NSArray<NSNumber*>* const kEveryDay = @[ @0, @1, @2, @3, @4, @5, @6 ];

// A refresh cadence a test can wait for, for the cases that are about the
// refresh due-check, and one no test will sit through, for the cases whose point
// is that something other than a refresh did the work.
static const NSTimeInterval kFastRefreshInterval = 0.1;
static const NSTimeInterval kUntickableRefreshInterval = 3600;

// A boot session that is not this machine's, for an entry left by an earlier one.
static NSString* const kOtherBootSessionUUID = @"6A2B4C8E-0000-0000-0000-00000000000B";

// The component's due tolerance, mirrored here so the case that stands inside it
// can say where it stood. Not a seam: if the two ever disagree, the boundary case
// below fails its own precondition and says so.
static const NSTimeInterval kDueTolerance = 0.25;

@interface SNTTimedRuleKillsTest : XCTestCase
@property NSFileManager* fileMgr;
@property NSString* testDir;
@property NSString* statePath;
@property CountingConfigurator* configurator;
/// The clock the last makeSUTOnHost: built, so a case can ask the component's own
/// believable time -- which is how the one case standing in a fraction of a
/// second proves it really stood there.
@property SNTBelievableClock* believableClock;
@property SNTRuleTable* ruleTable;
@property FMDatabaseQueue* dbq;
@property id mockConfiguratorClass;
@property id mockNotifierQueue;
@property id mockNotifierConnection;
@property id mockNotifierProxy;
@end

@implementation SNTTimedRuleKillsTest

- (void)setUp {
  [super setUp];

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

/// The component under test, wired to whatever notifier queue setUpNotifierProxy
/// left behind: nil unless a test asked for one, which is the "no GUI running"
/// case.
- (SNTTimedRuleKills*)makeSUT {
  // A real clock over the test's own state file: nothing here moves the host's
  // clock, so the believable time is the system time, which is what these tests
  // build their deadlines from.
  SNTBelievableClock* clock = [[SNTBelievableClock alloc] initWithConfigurator:self.configurator];
  SNTTimedRuleKills* sut = [[SNTTimedRuleKills alloc] initWithNotifierQueue:self.mockNotifierQueue
                                                                  ruleTable:self.ruleTable
                                                               configurator:self.configurator
                                                                      clock:clock];
  XCTAssertNotNil(sut);
  return sut;
}

/// A host at the current wall time, in this machine's boot session, with no mach
/// time pretended to have elapsed yet.
- (FakeHost*)makeHost {
  FakeHost* host = [[FakeHost alloc] init];
  host.wall = [NSDate date].timeIntervalSince1970;
  host.bootUUID = [SNTSystemInfo bootSessionUUID];
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
        return host.bootUUID;
      }];
  XCTAssertNotNil(clock);
  self.believableClock = clock;
  SNTTimedRuleKills* sut = [[SNTTimedRuleKills alloc] initWithNotifierQueue:self.mockNotifierQueue
                                                                  ruleTable:self.ruleTable
                                                               configurator:self.configurator
                                                                      clock:clock];
  XCTAssertNotNil(sut);
  return sut;
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

- (void)addRuleOfType:(SNTRuleType)type identifier:(NSString*)identifier cel:(NSString*)cel {
  SNTRule* rule = [[SNTRule alloc] init];
  rule.identifier = identifier;
  rule.type = type;
  rule.state = SNTRuleStateCELv2;
  rule.celExpr = cel;

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

/// Sets a kill block that records the requests it is handed and fulfills
/// `expectation` for each one, without signaling anything.
- (void)captureKillsOn:(SNTTimedRuleKills*)sut
                  into:(NSMutableArray<SNTKillRequest*>*)requests
           expectation:(XCTestExpectation*)expectation {
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    @synchronized(requests) {
      [requests addObjectsFromArray:pass];
    }
    // One response per request, none of them having signaled anything, so the
    // grace period and the SIGKILL pass are never reached: a test that wants
    // those routes into the real kill pass instead.
    NSMutableArray<SNTKillResponse*>* responses = [NSMutableArray array];
    for (NSUInteger index = 0; index < pass.count; index++) {
      [responses addObject:[[SNTKillResponse alloc] initWithKilledProcesses:@[]]];
      [expectation fulfill];
    }
    return responses;
  };
}

/// Records every banner the component sends, in order, as
/// @{@"app": ..., @"deadline": ...}, fulfilling `expectation` for each one.
/// Pass a nil expectation when the test's point is that no banner arrives.
- (void)recordBannersOn:(id)proxy
                   into:(NSMutableArray<NSDictionary*>*)banners
            expectation:(XCTestExpectation*)expectation {
  OCMStub([proxy postTimedRuleKillNotificationForApplication:OCMOCK_ANY deadline:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        __unsafe_unretained NSString* app;
        __unsafe_unretained NSDate* deadline;
        [invocation getArgument:&app atIndex:2];
        [invocation getArgument:&deadline atIndex:3];
        // Built key by key rather than as a literal: andDo() is a macro, and a
        // comma inside a braced literal would be read as another argument to it.
        NSMutableDictionary* banner = [NSMutableDictionary dictionary];
        banner[@"app"] = app;
        banner[@"deadline"] = deadline;
        @synchronized(banners) {
          [banners addObject:banner];
        }
        [expectation fulfill];
      });
}

/// An instant today at a local wall time. The recurring window an entry carries
/// is HH:MM in the host's local zone, so a test that wants to stand inside or
/// outside one places the clock it hands the component with this.
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

/// The recording most tests here need: a TEAMID entry for kMatchingTeamID under
/// kCELExpr, warned about at the deadline itself, with no window shape. Tests
/// whose subject is one of those fields spell it out with the longer form below.
- (void)record:(SNTTimedRuleKills*)sut deadline:(NSDate*)deadline {
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:deadline
        notifyAt:deadline];
}

/// The same with the four fields tests vary spelled out, and the window shape
/// still absent. The three tests that record a shape call the component directly
/// with all nine arguments, so a recording that carries a window always reads
/// differently from one that does not.
- (void)record:(SNTTimedRuleKills*)sut
          type:(SNTRuleType)type
    identifier:(NSString*)identifier
       celHash:(NSString*)celHash
      deadline:(NSDate*)deadline
      notifyAt:(NSDate*)notifyAt {
  [sut recordKillForRuleType:type
                  identifier:identifier
                     celHash:celHash
                    deadline:deadline
                    notifyAt:notifyAt
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
}

- (NSDictionary*)entryDictForRuleType:(SNTRuleType)type
                           identifier:(NSString*)identifier
                              celHash:(NSString*)celHash
                             deadline:(NSDate*)deadline {
  return @{
    @"RuleType" : @(type),
    @"Identifier" : identifier,
    @"CELHash" : celHash,
    @"Deadline" : @(deadline.timeIntervalSince1970),
    @"NotifyAt" : @(deadline.timeIntervalSince1970 - 60),
    @"Notified" : @NO,
  };
}

#pragma mark Recording

- (void)testCELHashIsSHA256OfTheExpression {
  // sha256("abc")
  XCTAssertEqualObjects([SNTTimedRuleKills celHashForExpression:@"abc"],
                        @"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  XCTAssertNil([SNTTimedRuleKills celHashForExpression:nil]);
  XCTAssertNil([SNTTimedRuleKills celHashForExpression:@""]);
}

- (void)testEarlierDeadlineWinsAndLaterIsIgnored {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];

  NSDate* far = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* near = [NSDate dateWithTimeIntervalSinceNow:1800];
  NSDate* farther = [NSDate dateWithTimeIntervalSinceNow:7200];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:hash
        deadline:far
        notifyAt:[far dateByAddingTimeInterval:-60]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             far.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 1u);

  // Earlier deadline replaces it.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:hash
        deadline:near
        notifyAt:[near dateByAddingTimeInterval:-60]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             near.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u);

  // A later deadline for the same key changes nothing, and writes nothing.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:hash
        deadline:farther
        notifyAt:[farther dateByAddingTimeInterval:-60]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             near.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u);
}

- (void)testRepeatedIdenticalRecordingWritesNothing {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  for (int i = 0; i < 5; i++) {
    [self record:sut
              type:SNTRuleTypeTeamID
        identifier:kMatchingTeamID
           celHash:hash
          deadline:deadline
          notifyAt:[deadline dateByAddingTimeInterval:-60]];
  }
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 1u);
}

- (void)testDifferentCELHashIsADifferentEntry {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  [self record:sut deadline:deadline];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kEditedCELExpr]
        deadline:deadline
        notifyAt:deadline];
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, 2u);
}

- (void)testBinaryAndCertificateRuleTypesAreRefused {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  [self record:sut
            type:SNTRuleTypeBinary
      identifier:@"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670"
         celHash:hash
        deadline:deadline
        notifyAt:deadline];
  [self record:sut
            type:SNTRuleTypeCertificate
      identifier:@"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258"
         celHash:hash
        deadline:deadline
        notifyAt:deadline];
  [self drain:sut];

  XCTAssertNil(self.savedEntries);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 0u);
}

- (void)testIncompleteRecordingsAreRefused {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:@""
         celHash:hash
        deadline:deadline
        notifyAt:deadline];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:nil
        deadline:deadline
        notifyAt:deadline];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:hash
        deadline:nil
        notifyAt:deadline];
  [self drain:sut];

  XCTAssertNil(self.savedEntries);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 0u);
}

#pragma mark Persistence

- (void)testEntryWritesPreserveOtherStateKeys {
  [self.configurator persistTimedSessionState:@{@"Deadline" : @123} forKey:kTMMStateKey];
  [self.configurator persistTimedSessionState:@{@"Deadline" : @456} forKey:kTAMStateKey];
  XCTAssertTrue([self.configurator persistDemotedAdmins:@[ @{@"Username" : @"jane"} ]]);

  SNTTimedRuleKills* sut = [self makeSUT];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:3540]];
  [self drain:sut];

  NSDictionary* onDisk = [self rawStateFile];
  XCTAssertEqualObjects(onDisk[kTMMStateKey], (@{@"Deadline" : @123}));
  XCTAssertEqualObjects(onDisk[kTAMStateKey], (@{@"Deadline" : @456}));
  XCTAssertEqualObjects(onDisk[@"DemotedAdmins"], (@[ @{@"Username" : @"jane"} ]));
  XCTAssertNotNil(onDisk[@"LastBootUUID"]);
  XCTAssertEqual([onDisk[kTimedRuleKillsStateKey] count], 1u);
}

- (void)testEntriesSurviveReloadAndUnknownKeysStillDoNot {
  NSDictionary* entry = [self entryDictForRuleType:SNTRuleTypeTeamID
                                        identifier:kMatchingTeamID
                                           celHash:@"abc"
                                          deadline:[NSDate dateWithTimeIntervalSinceNow:3600]];
  NSDictionary* onDisk = @{
    kTimedRuleKillsStateKey : @[ entry ],
    kTMMStateKey : @{@"Deadline" : @1},
    @"Bogus" : @"unknown",
  };
  XCTAssertTrue([onDisk writeToFile:self.statePath atomically:YES]);

  CountingConfigurator* reloaded = [self makeConfigurator];
  XCTAssertEqual([reloaded savedTimedRuleKills].count, 1u);
  XCTAssertNotNil([reloaded savedTimedSessionStateForKey:kTMMStateKey]);
  XCTAssertNil([reloaded savedTimedSessionStateForKey:@"Bogus"]);

  // A value of the wrong type under the key is stripped by the allowlist too.
  NSDictionary* wrongType = @{kTimedRuleKillsStateKey : @"not-an-array"};
  XCTAssertTrue([wrongType writeToFile:self.statePath atomically:YES]);
  XCTAssertNil([[self makeConfigurator] savedTimedRuleKills]);
}

// The window shape is part of the entry: written with it, read back with it and
// written out again unchanged, which is what lets a restart re-check the window
// a deadline came from. The kills recorded from a timestamp or duration window
// carry no shape, so their entries have no window fields at all.
- (void)testWindowShapePersistsAndSurvivesAReload {
  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* notifyAt = [deadline dateByAddingTimeInterval:-300];

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:deadline
                    notifyAt:notifyAt
                  windowDays:@[ @1, @3, @5 ]
                 windowStart:@"09:00"
                   windowEnd:@"17:00"
                  windowZone:@"local"];
  [self drain:sut];

  NSDictionary* saved = self.savedEntries.firstObject;
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
      identifier:cdhash
         celHash:hash
        deadline:deadline
        notifyAt:notifyAt];
  [self drain:restarted];

  NSDictionary* reloaded = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqualObjects(reloaded[@"WindowDays"], (@[ @1, @3, @5 ]));
  XCTAssertEqualObjects(reloaded[@"WindowStart"], @"09:00");
  XCTAssertEqualObjects(reloaded[@"WindowEnd"], @"17:00");
  XCTAssertEqualObjects(reloaded[@"WindowZone"], @"local");

  NSDictionary* shapeless = [self savedEntryForIdentifier:cdhash];
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
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
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
    // A zone that is not a string, which must not be sent -UTF8String. The other
    // two ways a zone can be unusable, a name the resolver refuses and a shape
    // whole but for the zone, are pinned at the kill seam instead by
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
                                                     celHash:hash
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
  [self record:sut deadline:deadline];
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

- (void)testEntryIsRemovedAndPersistedAfterFiring {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut deadline:deadline];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];

  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
  XCTAssertNil([self rawStateFile][kTimedRuleKillsStateKey]);
}

#pragma mark The kill

/// The request a deadline builds, one row per rule type that can be matched
/// against a running process: the class it becomes and the identifying fields it
/// carries, read back by name. targetProcessGroups is asserted on every row
/// because KillRequestForEntry sets it for every type.
- (void)testKillRequestShapePerRuleType {
  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  struct Row {
    SNTRuleType type;
    NSString* identifier;
    Class expected;
    // Property name to expected value on the request the entry became.
    NSDictionary<NSString*, NSString*>* fields;
  };

  std::vector<Row> rows = {
      {SNTRuleTypeTeamID, kMatchingTeamID, [SNTKillRequestTeamID class],
       @{@"teamID" : kMatchingTeamID}},
      // The one type whose identifier is split rather than passed through: the
      // "platform:" prefix becomes the team ID and the rest the signing ID, so
      // this row is the only one with two fields to check.
      {SNTRuleTypeSigningID, @"platform:com.apple.ls", [SNTKillRequestSigningID class],
       @{@"teamID" : @"platform", @"signingID" : @"com.apple.ls"}},
      {SNTRuleTypeCDHash, cdhash, [SNTKillRequestCDHash class], @{@"cdhash" : cdhash}},
  };

  // The rows share the fixture: each adds a rule of its own type and identifier,
  // and an entry is dropped once its deadline has fired, so nothing a row leaves
  // behind is visible to the next one.
  for (const Row& row : rows) {
    [self addRuleOfType:row.type identifier:row.identifier cel:kCELExpr];

    SNTTimedRuleKills* sut = [self makeSUT];
    XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
    NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
    [self captureKillsOn:sut into:requests expectation:killed];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
    [self record:sut
              type:row.type
        identifier:row.identifier
           celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
          deadline:deadline
          notifyAt:deadline];
    [self waitForExpectations:@[ killed ] timeout:10];

    XCTAssertEqual(requests.count, 1u, @"%@", row.identifier);
    SNTKillRequest* request = requests.firstObject;
    XCTAssertTrue([request isKindOfClass:row.expected], @"%@", row.identifier);
    for (NSString* field in row.fields) {
      XCTAssertEqualObjects([request valueForKey:field], row.fields[field], @"%@ of %@", field,
                            row.identifier);
    }
    XCTAssertTrue(request.targetProcessGroups, @"%@", row.identifier);
  }
}

- (void)testSIGTERMThenSIGKILLWithFiveSecondGrace {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  pid_t pgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = {100};
  fake.pidversions = {{100, 1}};
  fake.matching = {100};
  fake.pgids = {{100, pgid}};

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  // A block captures a C++ object by const copy, so the fake is reached
  // through a pointer; it outlives the block, which runs before the wait below
  // returns.
  FakeEnv* fakePtr = &fake;
  // The seam routes into the real term-then-kill against a fully faked
  // KillEnv, so the ordering under test is the production one.
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    santa::KillEnv env = MakeKillEnv(fakePtr);
    NSArray<SNTKillResponse*>* responses = santa::KillingMachineTermThenKill(pass, grace, env);
    [killed fulfill];
    return responses;
  };

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut deadline:deadline];
  [self waitForExpectations:@[ killed ] timeout:10];

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:%d", pgid, SIGTERM],
                          [NSString stringWithFormat:@"group:%d:%d", pgid, SIGKILL],
                        ]));
  XCTAssertEqual(fake.waits.size(), 1u);
  XCTAssertEqualWithAccuracy(fake.waits.front(), 5.0, 0.001);
}

// Deadlines that land together are one kill pass, not one each: every entry's
// SIGTERM goes out, then the one grace period they share, then the SIGKILL
// re-matches. Run per entry instead, two deadlines would hold the component's
// queue for two grace periods and the second quit would be five seconds late.
- (void)testSimultaneousDeadlinesShareOneGracePeriod {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kSecondTeamID cel:kCELExpr];

  pid_t firstPgid = getpgrp() + 1;
  pid_t secondPgid = getpgrp() + 2;

  // One process per entry, each in its own group, so both entries really signal
  // something: a grace period taken per entry would show up as two waits.
  FakeEnv fake;
  fake.pids = {100, 101};
  fake.pidversions = {{100, 1}, {101, 2}};
  fake.matching = {100};
  fake.matchingSecond = {101};
  fake.pgids = {{100, firstPgid}, {101, secondPgid}};

  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* past = [NSDate dateWithTimeIntervalSinceNow:-3600];
  // Parenthesized: the comma between the two entries would otherwise read as
  // another argument to the assertion macro.
  XCTAssertTrue(([self.configurator persistTimedRuleKills:@[
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                       celHash:hash
                      deadline:past],
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kSecondTeamID
                       celHash:hash
                      deadline:past],
  ]]));

  SNTTimedRuleKills* sut = [self makeSUT];
  __block NSUInteger passes = 0;
  __block NSUInteger requestsInPass = 0;
  FakeEnv* fakePtr = &fake;
  // The seam routes into the real kill pass against a fully faked KillEnv, so
  // the ordering under test is the production one.
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    passes++;
    requestsInPass = pass.count;
    santa::KillEnv env = MakeKillEnv(fakePtr);
    return santa::KillingMachineTermThenKill(pass, grace, env);
  };

  [sut resumeFromSavedState];
  [self waitForEntriesToClear];
  [self drain:sut];

  XCTAssertEqual(passes, 1u);
  XCTAssertEqual(requestsInPass, 2u);
  // The one wait is the whole point: both entries signaled, so a grace period
  // per entry would be two of them, and the second quit would be five seconds
  // late.
  XCTAssertEqual(fake.waits.size(), 1u);
  XCTAssertEqualWithAccuracy(fake.waits.front(), 5.0, 0.001);
  // The SIGTERM-before-SIGKILL ordering inside the pass is KillingMachine's
  // contract, pinned in order and per request by
  // KillingMachineTest.testTermThenKillSharesOneGracePeriodAcrossRequests. What
  // is this test's own is the batching above: one pass, two requests in it, one
  // grace period.
}

/// The two ways the fire-time re-check fails, which differ only in when the rule
/// stops being the one the entry was recorded under: it was never there at all,
/// or its text changed after the entry was recorded and before the deadline
/// arrived. Either way the entry is dropped and nothing is quit.
- (void)testARuleThatNoLongerGovernsDropsTheEntryWithoutKilling {
  for (BOOL edited : {NO, YES}) {
    NSString* row = edited ? @"the rule's text changed after recording" : @"no rule was added";
    if (edited) {
      [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
    }

    SNTTimedRuleKills* sut = [self makeSUT];
    __block BOOL killCalled = NO;
    sut.killBlock =
        ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
      killCalled = YES;
      return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
    };

    [self record:sut deadline:[NSDate dateWithTimeIntervalSinceNow:0.5]];
    [self drain:sut];
    // The entry really was persisted before the re-check dropped it.
    XCTAssertEqual(self.savedEntries.count, 1u, @"%@", row);

    // The edit lands between the recording and the deadline, which is the whole
    // difference between the two rows.
    if (edited) {
      [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kEditedCELExpr];
    }

    [self waitForEntriesToClear];
    XCTAssertFalse(killCalled, @"%@", row);
  }
}

#pragma mark The warning banner

- (void)testWarningNamesTheRunningProcessAndIsRecorded {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];
  // Nothing a test runs can be made to match a rule, so the match is faked.
  // Naming the pid it returns is the production path.
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    return @(getpid());
  };

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:deadline
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];

  // The banner arrives long before the deadline, so the timer fired for the
  // warning rather than the kill.
  [self waitForExpectations:@[ posted ] timeout:10];
  [self drain:sut];

  XCTAssertEqual(banners.count, 1u);
  // Named from the process, not from the rule it matched.
  XCTAssertGreaterThan([banners.firstObject[@"app"] length], 0u);
  XCTAssertNotEqualObjects(banners.firstObject[@"app"], kMatchingTeamID);
  XCTAssertEqualWithAccuracy([banners.firstObject[@"deadline"] timeIntervalSince1970],
                             deadline.timeIntervalSince1970, 0.001);

  // The entry is still pending, now marked warned on disk so a restart doesn't
  // warn again.
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testWarningFallsBackToTheRuleIdentifierWhenTheProcessCannotBeNamed {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];
  // A pid nothing can be read for, which is what a process that exited between
  // the match and the banner looks like.
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    return @(99999999);
  };

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];

  [self waitForExpectations:@[ posted ] timeout:10];

  XCTAssertEqual(banners.count, 1u);
  XCTAssertEqualObjects(banners.firstObject[@"app"], kMatchingTeamID);
}

- (void)testNoWarningWhenNothingMatchingIsRunning {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    return nil;
  };

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];

  [self waitForTheWarningPass];
  [self drain:sut];

  XCTAssertEqual(banners.count, 0u);
  // The pass is recorded even though no banner went out: it runs once per
  // (rule, deadline), whether or not it had anything to warn about.
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testOneWarningPerRuleAndDeadline {
  // Two entries, so the warning pass comes back over the first one.
  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:cdhash cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"two banners"];
  posted.expectedFulfillmentCount = 2;
  posted.assertForOverFulfill = YES;
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    return @(getpid());
  };

  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* firstDeadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  NSDate* secondDeadline = [NSDate dateWithTimeIntervalSinceNow:7200];

  // Already past, so the first warning goes out as soon as it is recorded.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:hash
        deadline:firstDeadline
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:-10]];
  // A later warning, which is what brings the pass back over the first entry.
  [self record:sut
            type:SNTRuleTypeCDHash
      identifier:cdhash
         celHash:hash
        deadline:secondDeadline
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.7]];

  [self waitForExpectations:@[ posted ] timeout:10];
  [self drain:sut];

  NSCountedSet* deadlines = [NSCountedSet set];
  for (NSDictionary* banner in banners) {
    [deadlines addObject:banner[@"deadline"]];
  }
  XCTAssertEqual(banners.count, 2u);
  XCTAssertEqual([deadlines countForObject:firstDeadline], 1u);
  XCTAssertEqual([deadlines countForObject:secondDeadline], 1u);
}

// A rule withdrawn during the lead window has no kill coming, so warning about
// it would promise a quit that never happens. The entry goes at warning time
// rather than sitting until a deadline it will never act on.
- (void)testNoWarningWhenTheRuleIsGoneAndTheEntryIsDropped {
  // No rule is ever added, so the warning-time re-check finds nothing.
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];
  __block BOOL snapshotTaken = NO;
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    snapshotTaken = YES;
    return @(getpid());
  };

  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);

  // Cleared at warning time, an hour before the deadline it was recorded for.
  [self waitForEntriesToClear];

  XCTAssertEqual(banners.count, 0u);
  XCTAssertFalse(snapshotTaken, @"snapshot taken for a rule that no longer governs");
}

- (void)testWarningIsSkippedWhenTheDeadlineIsAlreadyDue {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];
  __block BOOL snapshotTaken = NO;
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    snapshotTaken = YES;
    return @(getpid());
  };

  // Warning time and deadline land in the same pass.
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [self record:sut deadline:deadline];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];

  XCTAssertEqual(requests.count, 1u);
  XCTAssertFalse(snapshotTaken, @"snapshot taken for an entry that was already being killed");
  XCTAssertEqual(banners.count, 0u);
}

- (void)testWarningNeverDelaysTheKill {
  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:cdhash cel:kCELExpr];
  [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSString*>* order = [NSMutableArray array];

  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    @synchronized(order) {
      [order addObject:@"kill"];
    }
    [killed fulfill];
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  // A slow snapshot: taken before the kill it would hold the kill for a second.
  XCTestExpectation* snapshotted = [self expectationWithDescription:@"snapshot taken"];
  // Taking more snapshots than expected is what a regression here looks like;
  // let `order` be the thing that reports it.
  snapshotted.assertForOverFulfill = NO;
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    @synchronized(order) {
      [order addObject:@"match"];
    }
    [NSThread sleepForTimeInterval:1.0];
    [snapshotted fulfill];
    return nil;
  };

  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  // One entry warning at `due`, one entry deadlined at `due`: the same pass.
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:hash
        deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
        notifyAt:due];
  [self record:sut type:SNTRuleTypeCDHash identifier:cdhash celHash:hash deadline:due notifyAt:due];

  [self waitForExpectations:@[ killed, snapshotted ] timeout:10];
  XCTAssertEqualObjects(order, (@[ @"kill", @"match" ]));
}

#pragma mark Restart

- (void)testRestartDoesNotWarnAgainForAnAlreadyWarnedEntry {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                          celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]] mutableCopy];
  entry[@"NotifyAt"] = @([NSDate dateWithTimeIntervalSinceNow:-60].timeIntervalSince1970);
  entry[@"Notified"] = @YES;
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  id proxy = [self setUpNotifierProxy];
  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];
  __block BOOL snapshotTaken = NO;
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    snapshotTaken = YES;
    return @(getpid());
  };

  [sut resumeFromSavedState];
  [self drain:sut];

  XCTAssertFalse(snapshotTaken);
  XCTAssertEqual(banners.count, 0u);
  XCTAssertEqual(self.savedEntries.count, 1u);
}

// A Notified value that isn't a number (an array here, from a corrupted or
// hand-edited state file) must never reach -boolValue: that raises
// unrecognized-selector and crash-loops the daemon at every startup, since
// resumeFromSavedState runs on every launch. The entry loads with notified = NO
// instead, so the load is clean and the warning it still owes goes out.
- (void)testMalformedNotifiedValueLoadsAsNotWarnedAndDoesNotThrow {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                          celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]] mutableCopy];
  // A warning is still owed, and Notified is the wrong type.
  entry[@"NotifyAt"] = @([NSDate dateWithTimeIntervalSinceNow:-60].timeIntervalSince1970);
  entry[@"Notified"] = @[ @"not", @"a", @"number" ];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  id proxy = [self setUpNotifierProxy];
  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    return @(getpid());
  };

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
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                       celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                      deadline:[NSDate dateWithTimeIntervalSinceNow:-3600]]
  ]]);

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut resumeFromSavedState];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];
  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
}

- (void)testRestartDropsPastDueEntryWhoseRuleIsGone {
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                       celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                      deadline:[NSDate dateWithTimeIntervalSinceNow:-3600]]
  ]]);

  SNTTimedRuleKills* sut = [self makeSUT];
  __block BOOL killCalled = NO;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    killCalled = YES;
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  [sut resumeFromSavedState];
  [self drain:sut];

  XCTAssertFalse(killCalled);
  XCTAssertNil(self.savedEntries);
}

- (void)testRestartRestoresTheTimerForAFutureEntry {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                       celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                      deadline:[NSDate dateWithTimeIntervalSinceNow:1]]
  ]]);

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut resumeFromSavedState];
  [self drain:sut];
  // Not due yet: still pending, waiting on the restored timer.
  XCTAssertEqual(self.savedEntries.count, 1u);

  [self waitForExpectations:@[ killed ] timeout:10];
  XCTAssertEqual(requests.count, 1u);
}

// A plist real round-trips both infinities and NaN, and neither is an instant.
// A NaN deadline is the dangerous one: it answers no to every "has this come
// due" question while leaving the countdown to arm for zero seconds, fire, find
// nothing due, and arm for zero again. Such a record is no appointment, so it is
// dropped on the way in (and logged with the other unusable records), which is
// what stops that spin.
- (void)testANonFiniteDeadlineOrNotifyAtDropsTheEntry {
  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:cdhash cel:kCELExpr];

  NSMutableDictionary* notANumber = [[self entryDictForRuleType:SNTRuleTypeTeamID
                                                     identifier:kMatchingTeamID
                                                        celHash:hash
                                                       deadline:[NSDate date]] mutableCopy];
  notANumber[@"Deadline"] = @(NAN);
  NSMutableDictionary* infinite =
      [[self entryDictForRuleType:SNTRuleTypeCDHash
                       identifier:cdhash
                          celHash:hash
                         deadline:[NSDate dateWithTimeIntervalSinceNow:3600]] mutableCopy];
  infinite[@"NotifyAt"] = @(INFINITY);
  XCTAssertTrue(([self.configurator persistTimedRuleKills:@[ notANumber, infinite ]]));

  self.configurator = [self makeConfigurator];
  // The fixture has to really carry non-finite values, or this case would pass
  // for the wrong reason.
  XCTAssertFalse(
      std::isfinite([[self savedEntryForIdentifier:kMatchingTeamID][@"Deadline"] doubleValue]));
  XCTAssertFalse(std::isfinite([[self savedEntryForIdentifier:cdhash][@"NotifyAt"] doubleValue]));

  SNTTimedRuleKills* sut = [self makeSUT];
  __block BOOL killCalled = NO;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    killCalled = YES;
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  [sut resumeFromSavedState];
  [self drain:sut];

  // Both records were dropped, so the key was rewritten with nothing under it.
  XCTAssertFalse(killCalled);
  XCTAssertNil(self.savedEntries);
}

- (void)testRestartDropsMalformedEntries {
  NSArray<NSDictionary*>* saved = @[
    // No type, hash or deadline.
    @{@"Identifier" : kMatchingTeamID},
    // No identifier or hash.
    @{@"RuleType" : @(SNTRuleTypeTeamID), @"Deadline" : @1},
    [self entryDictForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                       celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                      deadline:[NSDate dateWithTimeIntervalSinceNow:3600]],
  ];
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut resumeFromSavedState];
  [self drain:sut];

  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualObjects(self.savedEntries.firstObject[@"Identifier"], kMatchingTeamID);
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
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:deadline
        notifyAt:[deadline dateByAddingTimeInterval:-300]];
  [self drain:sut];

  NSDictionary* saved = self.savedEntries.firstObject;
  XCTAssertEqualObjects(saved[@"BootSessionUUID"], [SNTSystemInfo bootSessionUUID]);
  XCTAssertEqualWithAccuracy(
      MachSecondsBetween(machBefore, [saved[@"MachDeadline"] unsignedLongLongValue]), 3600, 5);
}

// The system clock goes back a day while an hour of mach continuous time passes.
// The hour is the part a rolled-back clock cannot argue with, so the deadline an
// hour out has come due, and the refresh is what notices: the countdown timer
// runs on the system clock and is still counting the hour it was armed for.
- (void)testARolledBackClockStillKillsAtTheNextRefresh {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  NSDate* deadline = [NSDate dateWithTimeIntervalSince1970:host.wall + 3600];
  [self record:sut deadline:deadline];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);

  host.machOffsetSeconds = 3600;
  host.wall -= 86400;

  [self waitForExpectations:@[ killed ] timeout:10];
  XCTAssertEqual(requests.count, 1u);
}

// The same rollback with less mach time behind it leaves the deadline in the
// future, so nothing is killed; what the refresh does instead is re-arm the
// countdown for the ten minutes the believable clock says are left, rather than
// leaving it counting the hour it was armed for on a clock that has since moved.
- (void)testTheCountdownIsReArmedFromTheBelievableClockAfterARollback {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  __block BOOL killCalled = NO;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    killCalled = YES;
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  NSDate* deadline = [NSDate dateWithTimeIntervalSince1970:host.wall + 3600];
  [self record:sut deadline:deadline];
  [self drain:sut];
  XCTAssertEqual(sut.armedTimerSeconds, 3600u);

  host.machOffsetSeconds = 3000;
  host.wall -= 86400;

  [self
      waitUntil:^BOOL {
        return sut.armedTimerSeconds != 3600;
      }
      described:@"the countdown was re-armed"];
  XCTAssertEqualWithAccuracy((double)sut.armedTimerSeconds, 600, 2);
  XCTAssertFalse(killCalled);
  XCTAssertEqual(self.savedEntries.count, 1u);
}

// A daemon comes back up to an entry whose wall deadline is an hour out and whose
// mach deadline is half a second out: whichever of the two arrives first fires
// the kill, so this one fires at the next refresh rather than in an hour.
- (void)testAMachDeadlineFiresWhileTheWallDeadlineIsStillOut {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  NSMutableDictionary* entry = [[self
      entryDictForRuleType:SNTRuleTypeTeamID
                identifier:kMatchingTeamID
                   celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                  deadline:[NSDate dateWithTimeIntervalSince1970:host.wall + 3600]] mutableCopy];
  entry[@"MachDeadline"] =
      @(AddNanosecondsToMachTime((uint64_t)(0.5 * NSEC_PER_SEC), mach_continuous_time()));
  entry[@"BootSessionUUID"] = [SNTSystemInfo bootSessionUUID];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut resumeFromSavedState];

  [self waitForExpectations:@[ killed ] timeout:10];
  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
}

// The same entry from an earlier boot session. Its mach value belongs to a
// counter that has since restarted, so it says nothing at all and the wall
// instant is left to govern: an hour out, so nothing is killed.
- (void)testAMachDeadlineFromAnEarlierBootSessionIsIgnored {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  NSMutableDictionary* entry = [[self
      entryDictForRuleType:SNTRuleTypeTeamID
                identifier:kMatchingTeamID
                   celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                  deadline:[NSDate dateWithTimeIntervalSince1970:host.wall + 3600]] mutableCopy];
  // Long past, and from a boot session that is not this machine's.
  entry[@"MachDeadline"] = @1;
  entry[@"BootSessionUUID"] = kOtherBootSessionUUID;
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  __block BOOL killCalled = NO;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    killCalled = YES;
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  [sut resumeFromSavedState];
  [self drain:sut];
  // Several refreshes go by, every one of them looking at the entry.
  [self waitForRefreshCount:3];
  [self drain:sut];

  XCTAssertFalse(killCalled);
  XCTAssertEqual([self.configurator savedTimedRuleKills].count, 1u);
}

// A mach pair that is only half there, or holds something that isn't a number,
// is no pair: the entry still loads, its wall deadline still governs, and
// nothing on the way in is sent a message it doesn't answer. Reaching -boolValue
// or -isEqualToString: on the wrong type here would crash-loop the daemon, since
// every pass over the entries looks at the pair.
- (void)testAMalformedOrHalfWrittenMachPairLoadsAsAbsent {
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  // A mach deadline long past, so an entry that wrongly honored half a pair
  // would be due the moment it loaded.
  NSNumber* pastMachDeadline = @1;

  // One unusable pair per entry, keyed by the CDHash identifier its entry gets
  // so they can all be asserted together after the reload.
  NSDictionary<NSString*, NSDictionary*>* pairs = @{
    // Neither field is the type it should be.
    @"1111111111111111111111111111111111111111" :
        @{@"MachDeadline" : @[ @"not", @"a", @"number" ], @"BootSessionUUID" : @17},
    // A mach deadline with no boot session to read it against.
    @"2222222222222222222222222222222222222222" : @{@"MachDeadline" : pastMachDeadline},
    // A boot session with no mach deadline.
    @"3333333333333333333333333333333333333333" :
        @{@"BootSessionUUID" : [SNTSystemInfo bootSessionUUID]},
    // A usable mach deadline whose boot session is the wrong type.
    @"4444444444444444444444444444444444444444" :
        @{@"MachDeadline" : pastMachDeadline, @"BootSessionUUID" : @17},
    // A usable boot session whose mach deadline is not a number.
    @"5555555555555555555555555555555555555555" :
        @{@"MachDeadline" : @"soon", @"BootSessionUUID" : [SNTSystemInfo bootSessionUUID]},
  };

  NSMutableArray<NSDictionary*>* saved = [NSMutableArray array];
  for (NSString* identifier in pairs) {
    [self addRuleOfType:SNTRuleTypeCDHash identifier:identifier cel:kCELExpr];
    NSMutableDictionary* entry = [[self entryDictForRuleType:SNTRuleTypeCDHash
                                                  identifier:identifier
                                                     celHash:hash
                                                    deadline:deadline] mutableCopy];
    [entry addEntriesFromDictionary:pairs[identifier]];
    [saved addObject:entry];
  }
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUT];
  __block BOOL killCalled = NO;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    killCalled = YES;
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  // Not throwing here is half the point: nothing on the way in was sent a
  // message it does not answer. Reaching -unsignedLongLongValue or
  // -isEqualToString: on the wrong type would crash-loop the daemon, since every
  // pass over the entries looks at the pair.
  [sut resumeFromSavedState];
  [self drain:sut];

  // An unrelated recording rewrites the whole set, so what lands on disk for
  // these entries is what the reload deserialized.
  [self record:sut deadline:deadline];
  [self drain:sut];

  // Every wall deadline is an hour out, and no half pair may make one due.
  XCTAssertFalse(killCalled);
  XCTAssertEqual(self.savedEntries.count, pairs.count + 1);
  for (NSString* identifier in pairs) {
    NSDictionary* entry = [self savedEntryForIdentifier:identifier];
    XCTAssertNotNil(entry, @"%@ should still have loaded", identifier);
    XCTAssertNil(entry[@"MachDeadline"], @"%@", identifier);
    XCTAssertNil(entry[@"BootSessionUUID"], @"%@", identifier);
  }
}

// A clock that jumps forward is believed, so both the warning's moment and the
// deadline are behind us in the same pass. The kill goes ahead and the banner is
// dropped: a warning is never allowed to hold up a kill, and there is nothing
// left to warn about.
- (void)testAForwardJumpKillsAndSkipsTheBanner {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  FakeHost* host = [self makeHost];
  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kFastRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];
  __block BOOL snapshotTaken = NO;
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    snapshotTaken = YES;
    return @(getpid());
  };

  NSDate* deadline = [NSDate dateWithTimeIntervalSince1970:host.wall + 3600];
  [self record:sut
            type:SNTRuleTypeTeamID
      identifier:kMatchingTeamID
         celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
        deadline:deadline
        notifyAt:[deadline dateByAddingTimeInterval:-60]];
  [self drain:sut];

  host.wall += 7200;

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];

  XCTAssertEqual(requests.count, 1u);
  XCTAssertFalse(snapshotTaken, @"snapshot taken for an entry that was already being killed");
  XCTAssertEqual(banners.count, 0u);
  XCTAssertNil(self.savedEntries);
}

#pragma mark The window re-check

// A deadline that came due while the daemon was down, or while the machine
// slept, lands in a window that has opened again. The window is what the
// deadline meant, so the entry moves to the end of the occurrence standing now
// rather than quitting anything: the lead the warning was recorded with is
// preserved, the warning is owed again, and the mach pair is recaptured for the
// deadline it now points at.
- (void)testAPastDueEntryReschedulesWhileItsWindowIsOpen {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  host.wall = [self todayAtHour:12 minute:0].timeIntervalSince1970;
  NSDate* windowEnd = [self todayAtHour:17 minute:0];

  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                          celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                         deadline:[self todayAtHour:11 minute:0]] mutableCopy];
  // A five minute lead, and a warning already delivered for the old deadline.
  entry[@"NotifyAt"] = @([self todayAtHour:10 minute:55].timeIntervalSince1970);
  entry[@"Notified"] = @YES;
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"17:00";
  entry[@"WindowZone"] = @"local";
  // Long past, so the entry is due on both clocks.
  entry[@"MachDeadline"] = @1;
  entry[@"BootSessionUUID"] = [SNTSystemInfo bootSessionUUID];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  __block BOOL killCalled = NO;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    killCalled = YES;
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };

  uint64_t machBefore = mach_continuous_time();
  [sut resumeFromSavedState];
  [self drain:sut];

  XCTAssertFalse(killCalled);
  XCTAssertEqual(self.savedEntries.count, 1u);
  NSDictionary* saved = self.savedEntries.firstObject;
  XCTAssertEqualWithAccuracy([saved[@"Deadline"] doubleValue], windowEnd.timeIntervalSince1970, 1);
  XCTAssertEqualWithAccuracy([saved[@"NotifyAt"] doubleValue],
                             windowEnd.timeIntervalSince1970 - 300, 1);
  XCTAssertFalse([saved[@"Notified"] boolValue]);
  XCTAssertEqualObjects(saved[@"BootSessionUUID"], [SNTSystemInfo bootSessionUUID]);
  // Five hours from noon to the end of the occurrence.
  XCTAssertEqualWithAccuracy(
      MachSecondsBetween(machBefore, [saved[@"MachDeadline"] unsignedLongLongValue]), 5 * 3600, 5);
  // The window shape rides along unchanged, so the next pass can ask again.
  XCTAssertEqualObjects(saved[@"WindowDays"], kEveryDay);
  XCTAssertEqualObjects(saved[@"WindowStart"], @"09:00");
  XCTAssertEqualObjects(saved[@"WindowEnd"], @"17:00");
}

// The same entry an hour after the window closed. Nothing is standing now, so
// the deadline is what it always was and the kill goes ahead.
- (void)testAPastDueEntryKillsOnceItsWindowIsClosed {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  host.wall = [self todayAtHour:18 minute:0].timeIntervalSince1970;

  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                          celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                         deadline:[self todayAtHour:17 minute:0]] mutableCopy];
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"17:00";
  entry[@"WindowZone"] = @"local";
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut resumeFromSavedState];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];
  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
}

// A deadline that arrives on time is the moment the window closed, and the end
// of an occurrence is outside it, so the kill goes ahead rather than rescheduling
// to the occurrence that just ended. The clock stands at the occurrence end
// rather than safely past it, so a reading that held the window to include its
// end would take the reschedule branch here.
- (void)testAnOnTimeFireAtTheWindowEndKills {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  NSDate* windowEnd = [self todayAtHour:17 minute:0];
  host.wall = windowEnd.timeIntervalSince1970;

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:windowEnd
                    notifyAt:[windowEnd dateByAddingTimeInterval:-300]
                  windowDays:kEveryDay
                 windowStart:@"09:00"
                   windowEnd:@"17:00"
                  windowZone:@"local"];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];
  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
}

// The due tolerance treats an entry as due in the fraction of a second before
// its deadline, and a window still holds there, so this is the one pass that can
// see an open window whose end is the deadline itself. That is the on-time fire
// arriving a hair early, not a window that re-opened: the kill goes ahead, the
// deadline is not rewritten to the instant it already names, and the warning the
// user was already given is not sent a second time.
- (void)testAPassInsideTheDueToleranceBeforeTheWindowEndKillsWithoutASecondBanner {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  FakeHost* host = [self makeHost];
  NSDate* windowEnd = [self todayAtHour:17 minute:0];
  // Inside the tolerance, so the resume below finds the entry due while the
  // window is still open. The clock's floor rises on mach continuous time even
  // with this wall clock standing still, so the pass has to reach the kill inside
  // that fraction of a second; it normally does so in microseconds. Overshooting
  // would make the window read closed and prove nothing, so where the pass
  // actually stood is captured below and asserted rather than assumed.
  host.wall = windowEnd.timeIntervalSince1970 - 0.2;

  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                          celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                         deadline:windowEnd] mutableCopy];
  // The one banner this deadline was owed has already gone out.
  entry[@"NotifyAt"] = @(windowEnd.timeIntervalSince1970 - 300);
  entry[@"Notified"] = @YES;
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"17:00";
  entry[@"WindowZone"] = @"local";
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  // The believable time the kill path itself ran at, read from the component's
  // own clock at the moment it reached the kill.
  __block NSTimeInterval nowAtKill = 0;
  SNTBelievableClock* clock = self.believableClock;
  sut.killBlock =
      ^NSArray<SNTKillResponse*>*(NSArray<SNTKillRequest*>* pass, NSTimeInterval grace) {
    nowAtKill = [clock now].timeIntervalSince1970;
    [requests addObjectsFromArray:pass];
    [killed fulfill];
    return @[ [[SNTKillResponse alloc] initWithKilledProcesses:@[]] ];
  };
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];
  __block BOOL snapshotTaken = NO;
  sut.matchBlock = ^NSNumber*(SNTKillRequest* request) {
    snapshotTaken = YES;
    return @(getpid());
  };

  [sut resumeFromSavedState];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];

  // The precondition, not an outcome: the kill has to have run in the sliver
  // where the entry is due and the window is still open, or this case is about
  // the on-time branch instead and says nothing about the guard. Asserted rather
  // than trusted, because nothing here can hold the clock still.
  NSTimeInterval end = windowEnd.timeIntervalSince1970;
  if (nowAtKill >= end || nowAtKill < end - kDueTolerance) {
    XCTFail(@"the kill ran %g s from the occurrence end, outside the tolerance sliver this case "
            @"exists to stand in",
            end - nowAtKill);
  }

  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
  XCTAssertEqual(banners.count, 0u);
  XCTAssertFalse(snapshotTaken, @"snapshot taken for an entry that was already being killed");
}

// The same equality reached without leaning on the tolerance: the mach deadline
// says the moment has passed while the believable wall clock still sits inside
// the occurrence. The entry's deadline is that occurrence's end, so there is no
// later end to move to and the kill goes ahead rather than being deferred by the
// size of whatever moved the wall clock.
- (void)testAMachDueEntryInsideItsOwnOccurrenceKills {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  host.wall = [self todayAtHour:16 minute:0].timeIntervalSince1970;

  NSMutableDictionary* entry =
      [[self entryDictForRuleType:SNTRuleTypeTeamID
                       identifier:kMatchingTeamID
                          celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                         deadline:[self todayAtHour:17 minute:0]] mutableCopy];
  entry[@"WindowDays"] = kEveryDay;
  entry[@"WindowStart"] = @"09:00";
  entry[@"WindowEnd"] = @"17:00";
  entry[@"WindowZone"] = @"local";
  // Long past, and this boot session's, so the mach side is what makes it due.
  entry[@"MachDeadline"] = @1;
  entry[@"BootSessionUUID"] = [SNTSystemInfo bootSessionUUID];
  XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]]);

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut resumeFromSavedState];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];
  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
}

// A window shape that could not be rebuilt from the state file is no shape: the
// entry has nothing to re-check, so its deadline stands. Every row here stands at
// noon with a past-due deadline inside a 09:00 to 17:00 window, which is exactly
// the arrangement that reschedules when the shape is whole (see
// testAPastDueEntryReschedulesWhileItsWindowIsOpen), so a kill is the defect
// being treated as absent rather than as a window.
- (void)testUnusablePersistedWindowShapesKillRatherThanRescheduling {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  NSDictionary<NSString*, NSDictionary*>* shapes = @{
    @"a day list holding something that isn't a number" :
        @{@"WindowDays" : @[ @1, @"Wednesday" ], @"WindowZone" : @"local"},
    // The zone cannot be resolved, so the window cannot be asked. The design
    // calls that past-due, which means kill.
    @"a zone the resolver refuses" : @{@"WindowDays" : kEveryDay, @"WindowZone" : @"Mars/Olympus"},
    // What an upgraded daemon finds on disk: a shape whole but for the zone. It
    // loses its shape, so it behaves exactly like an entry that never had one.
    @"a shape written before the zone existed" : @{@"WindowDays" : kEveryDay},
  };

  for (NSString* defect in shapes) {
    FakeHost* host = [self makeHost];
    host.wall = [self todayAtHour:12 minute:0].timeIntervalSince1970;

    NSMutableDictionary* entry =
        [[self entryDictForRuleType:SNTRuleTypeTeamID
                         identifier:kMatchingTeamID
                            celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                           deadline:[self todayAtHour:11 minute:0]] mutableCopy];
    entry[@"WindowStart"] = @"09:00";
    entry[@"WindowEnd"] = @"17:00";
    [entry addEntriesFromDictionary:shapes[defect]];
    XCTAssertTrue([self.configurator persistTimedRuleKills:@[ entry ]], @"%@", defect);

    // A fresh configurator reads the entry just written back off disk, so each
    // row is a restart of its own.
    self.configurator = [self makeConfigurator];
    SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
    XCTestExpectation* killed = [self expectationWithDescription:defect];
    NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
    [self captureKillsOn:sut into:requests expectation:killed];

    [sut resumeFromSavedState];

    [self waitForExpectations:@[ killed ] timeout:10];
    [self drain:sut];
    XCTAssertEqual(requests.count, 1u, @"%@", defect);
    XCTAssertNil(self.savedEntries, @"%@", defect);
  }
}

// The stored zone is the calendar the window is re-checked in, not the host's.
// Two entries at one instant with one window and two stored fixed offsets eight
// hours apart: 12:00 in the first, 20:00 in the second. A re-check that read the
// host's zone would read the same clock for both and so answer the same way for
// both, whatever that answer was; here the first is inside its window and moves
// its deadline to the occurrence end, and the second is outside its window and is
// quit. Fixed offsets rather than named zones so the instants are arithmetic, and
// an absolute instant rather than "today" so nothing depends on this host.
- (void)testTheStoredZoneGovernsTheWindowRecheck {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kSecondTeamID cel:kCELExpr];

  // 2026-06-03T12:00:00Z, and the deadline an hour before it, so both entries are
  // past due whichever zone they are read in.
  NSDate* noonUTC = [NSDate dateWithTimeIntervalSince1970:1780488000];
  NSDate* deadline = [noonUTC dateByAddingTimeInterval:-3600];

  FakeHost* host = [self makeHost];
  host.wall = noonUTC.timeIntervalSince1970;

  NSMutableArray<NSDictionary*>* saved = [NSMutableArray array];
  for (NSArray* row in @[ @[ kMatchingTeamID, @"+00:00" ], @[ kSecondTeamID, @"+08:00" ] ]) {
    NSMutableDictionary* entry =
        [[self entryDictForRuleType:SNTRuleTypeTeamID
                         identifier:row[0]
                            celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                           deadline:deadline] mutableCopy];
    entry[@"WindowDays"] = kEveryDay;
    entry[@"WindowStart"] = @"09:00";
    entry[@"WindowEnd"] = @"17:00";
    entry[@"WindowZone"] = row[1];
    [saved addObject:entry];
  }
  XCTAssertTrue([self.configurator persistTimedRuleKills:saved]);

  self.configurator = [self makeConfigurator];
  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  [sut resumeFromSavedState];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];

  // Only the entry whose stored zone puts it outside its window was quit.
  XCTAssertEqual(requests.count, 1u);
  XCTAssertEqualObjects(((SNTKillRequestTeamID*)requests.firstObject).teamID, kSecondTeamID);

  // The other moved to 17:00 in its own zone, five hours on from the clock.
  XCTAssertEqual(self.savedEntries.count, 1u);
  NSDictionary* rescheduled = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqualWithAccuracy([rescheduled[@"Deadline"] doubleValue],
                             noonUTC.timeIntervalSince1970 + 5 * 3600, 1);
  XCTAssertEqualObjects(rescheduled[@"WindowZone"], @"+00:00");
}

// A shape the window math itself refuses, which is what a day outside 0 through
// 6 is. There is no window to be inside, so the answer is the same as a closed
// one: proceed to the kill, rather than throwing or holding the entry forever.
- (void)testAWindowEvaluationErrorProceedsToTheKill {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  FakeHost* host = [self makeHost];
  host.wall = [self todayAtHour:12 minute:0].timeIntervalSince1970;

  SNTTimedRuleKills* sut = [self makeSUTOnHost:host refreshInterval:kUntickableRefreshInterval];
  XCTestExpectation* killed = [self expectationWithDescription:@"kill ran"];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  [self captureKillsOn:sut into:requests expectation:killed];

  NSDate* deadline = [self todayAtHour:11 minute:0];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:@[ @42 ]
                 windowStart:@"09:00"
                   windowEnd:@"17:00"
                  windowZone:@"local"];

  [self waitForExpectations:@[ killed ] timeout:10];
  [self drain:sut];
  XCTAssertEqual(requests.count, 1u);
  XCTAssertNil(self.savedEntries);
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
/// once every recorded deadline has been processed.
- (void)waitForEntriesToClear {
  [self
      waitUntil:^BOOL {
        return self.savedEntries == nil;
      }
      described:@"entries cleared"];
}

/// Polls until the component has recorded that it ran the warning pass for its
/// single pending entry.
- (void)waitForTheWarningPass {
  [self
      waitUntil:^BOOL {
        return [self.savedEntries.firstObject[@"Notified"] boolValue];
      }
      described:@"warning pass ran"];
}

/// Polls until the clock has refreshed `count` times, which is how a test that
/// asserts a refresh did nothing waits for the refreshes to have happened rather
/// than for a length of time. Every refresh rewrites the reading, and the clock's
/// construction wrote one of its own.
- (void)waitForRefreshCount:(NSUInteger)count {
  [self
      waitUntil:^BOOL {
        return self.configurator.clockReadingWrites > count;
      }
      described:@"refreshes ran"];
}

@end
