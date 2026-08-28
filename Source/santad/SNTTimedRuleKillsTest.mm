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
#include <signal.h>
#include <unistd.h>

#include <cmath>
#include <cstdint>
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
#import "Source/common/SNTRule.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/KillingMachine.h"
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

// The serial queue the component does all of its work on, which a test drains
// to observe the result of a record.
@interface SNTTimedRuleKills (Testing)
@property(readonly) dispatch_queue_t queue;
@end

// Counts the writes the component makes, so a test can assert that a repeated
// recording of the same deadline writes nothing. Everything else about the
// configurator is real, including the state file on disk.
@interface CountingConfigurator : SNTConfigurator
@property NSUInteger timedRuleKillWrites;
@end

@implementation CountingConfigurator
- (BOOL)persistTimedRuleKills:(NSArray<NSDictionary*>*)entries {
  self.timedRuleKillWrites++;
  return [super persistTimedRuleKills:entries];
}
@end

namespace {

// The code signing identity the fake csops reports for every matched pid.
// Each rule below is written against one of these criteria.
static NSString* const kMatchingTeamID = @"ABCDE12345";
static NSString* const kMatchingSigningID = @"com.apple.ls";
// The hex form of kMatchingCDHashBytes, which is what a CDHASH rule holds.
static NSString* const kMatchingCDHash = @"deadbeefcafebabe0123456789abcdeffedcba98";
static const uint8_t kMatchingCDHashBytes[CS_CDHASH_LEN] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23,
    0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};

// One recorded signal delivery. `target` is a pgid when `group` is true.
struct FakeSignal {
  pid_t target;
  int sig;
  bool group;
};

// State behind a fully faked santa::KillEnv, trimmed from KillingMachineTest's.
// Every seam is replaced, so nothing here can reach a real syscall.
struct FakeEnv {
  std::vector<pid_t> pids;
  // pid -> pidversion. A pid that isn't here has no audit token.
  std::map<pid_t, int> pidversions;
  // pids the fake csops reports the identity above for.
  std::set<pid_t> matching;
  // pid -> pgid.
  std::map<pid_t, pid_t> pgids;

  std::vector<FakeSignal> signals;
  std::vector<NSTimeInterval> waits;

  // Puts one process in the fake world that every rule below matches, in a
  // process group of its own.
  void AddMatching(pid_t pid, pid_t pgid) {
    pids.push_back(pid);
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
  santa::KillEnv env;

  env.list_pids = [fake]() -> std::optional<std::vector<pid_t>> { return fake->pids; };

  env.token_for_pid = [fake](pid_t pid, audit_token_t* token) {
    auto it = fake->pidversions.find(pid);
    if (it == fake->pidversions.end()) {
      return false;
    }
    *token = santa::MakeStubAuditToken(pid, it->second);
    return true;
  };

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

  env.pgid_for_pid = [fake](pid_t pid) -> pid_t {
    auto it = fake->pgids.find(pid);
    return it == fake->pgids.end() ? -1 : it->second;
  };

  env.signal_token = [fake](audit_token_t* token, int sig) {
    fake->signals.push_back({santa::Pid(*token), sig, false});
    return 0;
  };

  env.signal_group = [fake](pid_t pgid, int sig) {
    fake->signals.push_back({pgid, sig, true});
    return 0;
  };

  env.wait = [fake](NSTimeInterval seconds) { fake->waits.push_back(seconds); };

  return env;
}

// Renders recorded deliveries as "group:100:15" so a failing assertion prints
// the whole sequence instead of a count mismatch.
NSArray<NSString*>* SignalDescriptions(const std::vector<FakeSignal>& signals) {
  NSMutableArray<NSString*>* out = [NSMutableArray array];
  for (const FakeSignal& signal : signals) {
    [out addObject:[NSString stringWithFormat:@"%@:%d:%d", signal.group ? @"group" : @"pid",
                                              signal.target, signal.sig]];
  }
  return out;
}

}  // namespace

// A CEL expression that compiles under CELv2, so the rule table accepts the
// rules these tests insert. The text itself is never evaluated here; only its
// hash matters.
static NSString* const kCELExpr = @"euid == 0 ? REQUIRE_TOUCHID : ALLOWLIST";
static NSString* const kEditedCELExpr = @"euid == 1 ? REQUIRE_TOUCHID : ALLOWLIST";

// Every day of the week, which is what makes a recurring HH:MM window in these
// tests land the same way whichever day they run on.
static NSArray<NSNumber*>* const kEveryDay = @[ @0, @1, @2, @3, @4, @5, @6 ];

static NSString* const kTimedRuleKillsStateKey = @"TimedRuleKills";
static NSString* const kTMMStateKey = @"TMM";

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

/// The component under test, wired to whatever notifier queue setUpNotifierProxy
/// left behind: nil unless a test asked for one, which is the "no GUI running"
/// case.
- (SNTTimedRuleKills*)makeSUT {
  SNTTimedRuleKills* sut = [[SNTTimedRuleKills alloc] initWithNotifierQueue:self.mockNotifierQueue
                                                                  ruleTable:self.ruleTable
                                                               configurator:self.configurator
                                                                    killEnv:MakeEnv(&_fake)];
  XCTAssertNotNil(sut);
  return sut;
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

/// The start of the minute `instant` falls in, which is the instant a zone from
/// -zoneReading:asHour: reads as exactly that hour, and so what the end of an
/// occurrence is measured from.
- (NSDate*)minuteFloor:(NSDate*)instant {
  return [NSDate dateWithTimeIntervalSince1970:floor(instant.timeIntervalSince1970 / 60) * 60];
}

/// Records every banner the component sends, in order, as
/// @{@"app": ..., @"deadline": ..., @"signals": ...}, fulfilling `expectation`
/// for each one. `signals` is how many deliveries the kill pass had already made
/// when the banner went out, which is what an ordering test reads. Pass a nil
/// expectation when the test's point is that no banner arrives.
- (void)recordBannersOn:(id)proxy
                   into:(NSMutableArray<NSDictionary*>*)banners
            expectation:(XCTestExpectation*)expectation {
  FakeEnv* fake = &_fake;
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
        banner[@"signals"] = @(fake->signals.size());
        @synchronized(banners) {
          [banners addObject:banner];
        }
        [expectation fulfill];
      });
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

  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:far
                    notifyAt:[far dateByAddingTimeInterval:-60]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             far.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 1u);

  // Earlier deadline replaces it.
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:near
                    notifyAt:[near dateByAddingTimeInterval:-60]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             near.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u);

  // A later deadline for the same key changes nothing, and writes nothing.
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:farther
                    notifyAt:[farther dateByAddingTimeInterval:-60]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u, @"a later deadline");
  XCTAssertEqualWithAccuracy([self.savedEntries.firstObject[@"Deadline"] doubleValue],
                             near.timeIntervalSince1970, 0.001);
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u, @"a later deadline");

  // Re-recording the deadline that already governs is the common case of a
  // binary executing repeatedly inside its window: nothing changes, so nothing
  // is written.
  for (int i = 0; i < 5; i++) {
    [sut recordKillForRuleType:SNTRuleTypeTeamID
                    identifier:kMatchingTeamID
                       celHash:hash
                      deadline:near
                      notifyAt:[near dateByAddingTimeInterval:-60]
                    windowDays:nil
                   windowStart:nil
                     windowEnd:nil
                    windowZone:nil];
  }
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u, @"the same deadline again");
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 2u, @"the same deadline again");

  // A different CEL hash is a different key, so it is a second entry rather
  // than an arbitration against the first.
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kEditedCELExpr]
                    deadline:farther
                    notifyAt:[farther dateByAddingTimeInterval:-60]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 2u, @"a different CEL hash");
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 3u, @"a different CEL hash");
}

// Both guards on the recording path: rule types no kill request can be built
// for, and each field the completeness check requires.
- (void)testUnsupportedAndIncompleteRecordingsAreRefused {
  SNTTimedRuleKills* sut = [self makeSUT];
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];

  [sut recordKillForRuleType:SNTRuleTypeBinary
                  identifier:@"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670"
                     celHash:hash
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeCertificate
                  identifier:@"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258"
                     celHash:hash
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:@""
                     celHash:hash
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:nil
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:nil
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:deadline
                    notifyAt:nil
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];

  XCTAssertNil(self.savedEntries, @"one of: BINARY, CERTIFICATE, empty identifier, nil celHash, "
                                  @"nil deadline, nil notifyAt");
  XCTAssertEqual(self.configurator.timedRuleKillWrites, 0u);
}

#pragma mark Persistence

- (void)testEntryWritesPreserveOtherStateKeys {
  [self.configurator persistTimedSessionState:@{@"Deadline" : @123} forKey:kTMMStateKey];

  SNTTimedRuleKills* sut = [self makeSUT];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                    notifyAt:[NSDate dateWithTimeIntervalSinceNow:3540]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];

  NSDictionary* onDisk = [self rawStateFile];
  XCTAssertEqualObjects(onDisk[kTMMStateKey], (@{@"Deadline" : @123}));
  XCTAssertEqual([onDisk[kTimedRuleKillsStateKey] count], 1u);
}

- (void)testEntriesSurviveReloadButAWrongTypedValueDoesNot {
  NSDictionary* entry = [self entryDictForRuleType:SNTRuleTypeTeamID
                                        identifier:kMatchingTeamID
                                           celHash:@"abc"
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
// a deadline came from. The kills recorded from a timestamp or duration window
// carry no shape, so their entries have no window fields at all.
- (void)testWindowShapePersistsAndSurvivesAReload {
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
  [restarted recordKillForRuleType:SNTRuleTypeCDHash
                        identifier:kMatchingCDHash
                           celHash:hash
                          deadline:deadline
                          notifyAt:notifyAt
                        windowDays:nil
                       windowStart:nil
                         windowEnd:nil
                        windowZone:nil];
  [self drain:restarted];

  NSDictionary* reloaded = [self savedEntryForIdentifier:kMatchingTeamID];
  XCTAssertEqualObjects(reloaded[@"WindowDays"], (@[ @1, @3, @5 ]));
  XCTAssertEqualObjects(reloaded[@"WindowStart"], @"09:00");
  XCTAssertEqualObjects(reloaded[@"WindowEnd"], @"17:00");
  XCTAssertEqualObjects(reloaded[@"WindowZone"], @"local");

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
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
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

// Every rule type builds a different kill request, and each must quit the
// process group of what it matches: SIGTERM, five seconds, then SIGKILL to
// whatever is still there. The rows are not interchangeable: the `platform:`
// SIGNINGID one is the only end-to-end cover of the flags-plus-signingID split,
// since the whole identifier is not an identity anything reports.
- (void)testEachRuleTypeTermsThenKillsTheProcessGroup {
  NSArray<NSArray*>* rows = @[
    @[ @(SNTRuleTypeTeamID), kMatchingTeamID ],
    @[ @(SNTRuleTypeSigningID), [NSString stringWithFormat:@"platform:%@", kMatchingSigningID] ],
    @[ @(SNTRuleTypeCDHash), kMatchingCDHash ],
  ];

  SNTTimedRuleKills* sut = [self makeSUT];
  for (NSArray* row in rows) {
    SNTRuleType type = (SNTRuleType)[row[0] integerValue];
    NSString* identifier = row[1];
    _fake.signals.clear();
    _fake.waits.clear();
    [self addRuleOfType:type identifier:identifier cel:kCELExpr];

    NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
    [sut recordKillForRuleType:type
                    identifier:identifier
                       celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                      deadline:deadline
                      notifyAt:deadline
                    windowDays:nil
                   windowStart:nil
                     windowEnd:nil
                    windowZone:nil];
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
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:kMatchingCDHash cel:kCELExpr];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:due
                    notifyAt:due
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeCDHash
                  identifier:kMatchingCDHash
                     celHash:hash
                    deadline:due
                    notifyAt:due
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];

  [self waitForEntriesToClear:sut];
  [self drain:sut];

  XCTAssertEqual(_fake.waits.size(), 1u);
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
}

// Both branches of the fire-time re-check, in one pass: the CDHash entry's rule
// was never added (gone), and the TeamID entry was recorded against text the
// added rule does not hold (edited). Either one failing to drop signals.
- (void)testRuleThatIsGoneOrEditedDropsTheEntryWithoutKilling {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [sut recordKillForRuleType:SNTRuleTypeCDHash
                  identifier:kMatchingCDHash
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kEditedCELExpr]
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 2u);

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[],
                        @"a rule that is gone or edited has no kill coming");
}

#pragma mark The warning banner

- (void)testWarningNamesTheRunningProcessAndIsRecorded {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:3600];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:deadline
                    notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];

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
  // The warning is the match pass on its own: nothing was signaled.
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), @[]);

  // The entry is still pending, now marked warned on disk so a restart doesn't
  // warn again.
  XCTAssertEqual(self.savedEntries.count, 1u);
  XCTAssertTrue([self.savedEntries.firstObject[@"Notified"] boolValue]);
}

- (void)testWarningFallsBackToTheRuleIdentifierWhenTheProcessCannotBeNamed {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  // The one matching process is a pid nothing can be read for, which is what a
  // process that exited between the match and the banner looks like.
  _fake = FakeEnv();
  _fake.AddMatching(99999999, self.matchingPgid);

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                    notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];

  [self waitForExpectations:@[ posted ] timeout:10];

  XCTAssertEqual(banners.count, 1u);
  XCTAssertEqualObjects(banners.firstObject[@"app"], kMatchingTeamID);
}

- (void)testNoWarningWhenNothingMatchingIsRunning {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  // Nothing is running at all, so the match pass finds nothing.
  _fake = FakeEnv();

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                    notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];

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
  // fake process would match if the pass ever got as far as looking.
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:nil];

  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                    notifyAt:[NSDate dateWithTimeIntervalSinceNow:0.3]
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [self drain:sut];
  XCTAssertEqual(self.savedEntries.count, 1u);

  // Cleared at warning time, an hour before the deadline it was recorded for.
  [self waitForEntriesToClear:sut];

  XCTAssertEqual(banners.count, 0u);
}

- (void)testWarningNeverDelaysTheKill {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:kMatchingCDHash cel:kCELExpr];
  id proxy = [self setUpNotifierProxy];

  SNTTimedRuleKills* sut = [self makeSUT];
  XCTestExpectation* posted = [self expectationWithDescription:@"banner sent"];
  // Warning the entry that is being killed is what a regression here looks
  // like, and an over-fulfilled expectation aborts the whole process; let the
  // assertions below report it instead.
  posted.assertForOverFulfill = NO;
  NSMutableArray<NSDictionary*>* banners = [NSMutableArray array];
  [self recordBannersOn:proxy into:banners expectation:posted];

  NSString* hash = [SNTTimedRuleKills celHashForExpression:kCELExpr];
  NSDate* due = [NSDate dateWithTimeIntervalSinceNow:0.5];
  // One entry warning at `due`, one entry deadlined at `due`: the same pass.
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:hash
                    deadline:[NSDate dateWithTimeIntervalSinceNow:3600]
                    notifyAt:due
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];
  [sut recordKillForRuleType:SNTRuleTypeCDHash
                  identifier:kMatchingCDHash
                     celHash:hash
                    deadline:due
                    notifyAt:due
                  windowDays:nil
                 windowStart:nil
                   windowEnd:nil
                  windowZone:nil];

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

  [sut resumeFromSavedState];
  [self drain:sut];

  // The fake process matches the entry's rule, so the only reason no banner
  // went out is the flag the entry was restored with.
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
  [sut resumeFromSavedState];

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
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
  [sut resumeFromSavedState];
  [self drain:sut];
  // Not due yet: still pending, waiting on the restored timer.
  XCTAssertEqual(self.savedEntries.count, 1u);

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
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
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];
  [self addRuleOfType:SNTRuleTypeCDHash identifier:kMatchingCDHash cel:kCELExpr];

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
    NSMutableDictionary* entry =
        [[self entryDictForRuleType:(SNTRuleType)[row[0] integerValue]
                         identifier:row[1]
                            celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                           deadline:row[3]] mutableCopy];
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
  // The lead the old deadline was warned with, carried onto the new one.
  XCTAssertEqualWithAccuracy([rescheduled[@"NotifyAt"] doubleValue],
                             [rescheduled[@"Deadline"] doubleValue] - 60, 0.001);
  // The warning is owed again: this is a different deadline from the one the
  // user was already warned about.
  XCTAssertFalse([rescheduled[@"Notified"] boolValue]);
  XCTAssertEqualObjects(rescheduled[@"WindowZone"], openZone);
  XCTAssertEqualObjects(rescheduled[@"WindowDays"], kEveryDay);
}

// A window shape that could not be rebuilt from the state file is no shape: the
// entry has nothing to re-check, so its deadline stands. The first row stands at
// 12:00 inside a 09:00 to 17:00 window, which is the arrangement the open row of
// testTheStoredZoneGovernsTheWindowRecheck reschedules from, so it would
// reschedule too if its day list could be read. The other two lose their shape at
// the zone itself, which leaves no zone for them to stand in at all. Every row is
// past due, so a kill is the defect being read as absent rather than as a window.
- (void)testUnusablePersistedWindowShapesKillRatherThanRescheduling {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  NSDate* now = [NSDate date];
  NSDictionary<NSString*, NSDictionary*>* shapes = @{
    @"a day list holding something that isn't a number" :
        @{@"WindowDays" : @[ @1, @"Wednesday" ], @"WindowZone" : [self zoneReading:now asHour:12]},
    // The zone cannot be resolved, so the window cannot be asked. The design
    // calls that past-due, which means kill.
    @"a zone the resolver refuses" : @{@"WindowDays" : kEveryDay, @"WindowZone" : @"Mars/Olympus"},
    // What an upgraded daemon finds on disk: a shape whole but for the zone. It
    // loses its shape, so it behaves exactly like an entry that never had one.
    @"a shape written before the zone existed" : @{@"WindowDays" : kEveryDay},
  };

  for (NSString* defect in shapes) {
    _fake.signals.clear();
    NSMutableDictionary* entry =
        [[self entryDictForRuleType:SNTRuleTypeTeamID
                         identifier:kMatchingTeamID
                            celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                           deadline:[now dateByAddingTimeInterval:-3600]] mutableCopy];
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

// A shape the window math itself refuses, which is what a day outside 0 through
// 6 is. There is no window to be inside, so the answer is the same as a closed
// one: proceed to the kill, rather than throwing or holding the entry forever.
- (void)testAWindowEvaluationErrorProceedsToTheKill {
  [self addRuleOfType:SNTRuleTypeTeamID identifier:kMatchingTeamID cel:kCELExpr];

  SNTTimedRuleKills* sut = [self makeSUT];
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:0.5];
  [sut recordKillForRuleType:SNTRuleTypeTeamID
                  identifier:kMatchingTeamID
                     celHash:[SNTTimedRuleKills celHashForExpression:kCELExpr]
                    deadline:deadline
                    notifyAt:deadline
                  windowDays:@[ @42 ]
                 windowStart:@"09:00"
                   windowEnd:@"17:00"
                  windowZone:@"local"];

  [self waitForEntriesToClear:sut];
  [self drain:sut];
  XCTAssertEqualObjects(SignalDescriptions(_fake.signals), [self termThenKillOfTheProcessGroup]);
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
