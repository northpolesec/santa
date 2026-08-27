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

#include "Source/santad/KillingMachine.h"

#import <Foundation/Foundation.h>
#import <Kernel/kern/cs_blobs.h>
#import <XCTest/XCTest.h>
#import <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/santad/KillEnvTestSupport.h"

// Forward declare test-only functions exposed by KillingMachine.mm
namespace santa {

extern bool TestCDHashMatcher(pid_t pid, NSString* cdhash, CSOpsFunc csops_func);
extern bool TestTeamIDMatcher(pid_t pid, NSString* teamID, CSOpsFunc csops_func);
extern bool TestSigningIDMatcher(pid_t pid, NSString* signingID, CSOpsFunc csops_func);
extern bool TestStatusFlagsMatcher(pid_t pid, uint32_t mask, CSOpsFunc csops_func);

}  // namespace santa

namespace {

using santa::testing::kMatchingTeamID;
using santa::testing::kSecondTeamID;
using santa::testing::SignalDescriptions;

// The shared fake env plus the models only this suite drives: a pid being
// recycled under the matcher, an errno from a delivery that reached its target,
// and a hook that runs while the grace period is being waited out.
struct FakeEnv : santa::testing::FakeKillEnv {
  // pid -> the audit token read after which that pid is recycled: its live
  // pidversion changes, modeling a different process taking over the pid.
  // Reads are counted per pid across the whole call. Matching reads a pid's
  // token twice, so 1 recycles mid-match and 2 recycles after it matched.
  std::map<pid_t, int> recycleAfterNthRead;
  // errno both signal seams return for a delivery that reaches its target.
  int signalError = 0;

  std::map<pid_t, int> tokenReads;
  // Runs when the term-then-kill grace wait starts, so a test can retire the
  // processes that died from SIGTERM.
  std::function<void()> onWait = [] {};
};

santa::KillEnv MakeEnv(FakeEnv* fake) {
  santa::KillEnv env = santa::testing::MakeKillEnv(fake);

  // The recycling model: the shared token seam hands out a stable pidversion,
  // this one changes it under the caller on the read a test nominates.
  env.token_for_pid = [fake](pid_t pid, audit_token_t* token) {
    auto it = fake->pidversions.find(pid);
    if (it == fake->pidversions.end()) {
      return false;
    }
    *token = santa::MakeStubAuditToken(pid, it->second);

    auto recycle = fake->recycleAfterNthRead.find(pid);
    if (recycle != fake->recycleAfterNthRead.end() && ++fake->tokenReads[pid] == recycle->second) {
      it->second += 1;
    }
    return true;
  };

  env.signal_token = [fake](audit_token_t* token, int sig) {
    pid_t pid = santa::Pid(*token);
    fake->signals.push_back({pid, sig, false});

    // proc_signal_with_audittoken validates the token against the live
    // process, so a token captured before the pid was recycled signals nothing.
    auto it = fake->pidversions.find(pid);
    if (it == fake->pidversions.end() || it->second != santa::Pidversion(*token)) {
      return ESRCH;
    }
    return fake->signalError;
  };

  env.signal_group = [fake](pid_t pgid, int sig) {
    fake->signals.push_back({pgid, sig, true});
    return fake->signalError;
  };

  env.wait = [fake](NSTimeInterval seconds) {
    fake->waits.push_back(seconds);
    fake->onWait();
  };

  return env;
}

}  // namespace

@interface KillingMachineTest : XCTestCase
@end

@implementation KillingMachineTest

- (void)testCDHashMatcherSuccess {
  std::vector<uint8_t> actualCDhash = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23,
                                       0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98};

  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  XCTAssertTrue(santa::TestCDHashMatcher(
      12345, cdhash, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopCDHash && usersize == actualCDhash.size()) {
          std::memcpy(useraddr, actualCDhash.data(), actualCDhash.size());
          return 0;
        }
        return -1;
      }));
}

- (void)testCDHashMatcherMismatch {
  std::vector<uint8_t> actualCDhash(CS_CDHASH_LEN, 0xff);

  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  XCTAssertFalse(santa::TestCDHashMatcher(
      12345, cdhash, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopCDHash) {
          std::memcpy(useraddr, actualCDhash.data(), actualCDhash.size());
          return 0;
        }
        return -1;
      }));
}

- (void)testCDHashMatcherCSopsFailure {
  NSString* cdhash = @"deadbeefcafebabe0123456789abcdeffedcba98";
  XCTAssertFalse(santa::TestCDHashMatcher(
      12345, cdhash, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        return -1;
      }));
}

- (void)testTeamIDMatcherSuccess {
  NSString* teamID = @"ABCDE12345";

  XCTAssertTrue(santa::TestTeamIDMatcher(
      12345, teamID, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopTeamID) {
          santa::csops_blob* blob = (santa::csops_blob*)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + teamID.length);
          std::memcpy(blob->data, teamID.UTF8String, teamID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testTeamIDMatcherMismatch {
  NSString* teamID = @"ZZZZZ99999";

  XCTAssertFalse(santa::TestTeamIDMatcher(
      12345, @"ABCDE12345", ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopTeamID) {
          santa::csops_blob* blob = (santa::csops_blob*)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + teamID.length);
          std::memcpy(blob->data, teamID.UTF8String, teamID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testTeamIDMatcherCSopsFailure {
  XCTAssertFalse(santa::TestTeamIDMatcher(
      12345, @"ABCDE12345", ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        return -1;
      }));
}

- (void)testSigningIDMatcherSuccess {
  NSString* signingID = @"com.example.app";

  XCTAssertTrue(santa::TestSigningIDMatcher(
      12345, @"com.example.app", ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopIdentity) {
          santa::csops_blob* blob = (santa::csops_blob*)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + signingID.length);
          std::memcpy(blob->data, signingID.UTF8String, signingID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testSigningIDMatcherMismatch {
  NSString* signingID = @"com.other.app";

  XCTAssertFalse(santa::TestSigningIDMatcher(
      12345, @"com.example.app", ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopIdentity) {
          santa::csops_blob* blob = (santa::csops_blob*)useraddr;
          blob->type = 0;
          blob->len = htonl(sizeof(santa::csops_blob) + 1 + signingID.length);
          std::memcpy(blob->data, signingID.UTF8String, signingID.length);
          return 0;
        }
        return -1;
      }));
}

- (void)testStatusFlagsMatcherSuccess {
  XCTAssertTrue(santa::TestStatusFlagsMatcher(
      12345, CS_PLATFORM_BINARY, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopStatus && usersize == sizeof(uint32_t)) {
          uint32_t* flags = (uint32_t*)useraddr;
          *flags = CS_PLATFORM_BINARY | CS_VALID;
          return 0;
        }
        return -1;
      }));
}

- (void)testStatusFlagsMatcherMismatch {
  XCTAssertFalse(santa::TestStatusFlagsMatcher(
      12345, CS_PLATFORM_BINARY, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        if (ops == santa::kCsopStatus && usersize == sizeof(uint32_t)) {
          uint32_t* flags = (uint32_t*)useraddr;
          *flags = CS_VALID;
          return 0;
        }
        return -1;
      }));
}

- (void)testStatusFlagsMatcherCSopsFailure {
  XCTAssertFalse(santa::TestStatusFlagsMatcher(
      12345, CS_PLATFORM_BINARY, ^(pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
        return -1;
      }));
}

//
// Signal delivery
//

// Pins today's behavior: a request built with the existing initializer signals
// each matched pid individually with SIGKILL, even where the pids share a
// process group.
- (void)testDefaultRequestKeepsSigkillPerPid {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11, 12};
  fake.pidversions = {{10, 1}, {11, 2}, {12, 3}};
  fake.matching = {10, 11, 12};
  fake.pgids = {{10, getpgrp() + 1}, {11, getpgrp() + 1}, {12, getpgrp() + 1}};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];
  XCTAssertEqual(request.signal, SIGKILL);
  XCTAssertFalse(request.targetProcessGroups);

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqual(response.error, SNTKillResponseErrorNone);
  XCTAssertEqualObjects(SignalDescriptions(fake.signals),
                        (@[ @"pid:10:9", @"pid:11:9", @"pid:12:9" ]));
  XCTAssertEqual(response.killedProcesses.count, 3);
  XCTAssertEqual(response.killedProcesses[0].pid, 10);
  XCTAssertEqual(response.killedProcesses[0].pidversion, 1);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorNone);
}

- (void)testRequestSignalIsHonored {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10};
  fake.pidversions = {{10, 1}};
  fake.matching = {10};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID
                                                                signal:SIGTERM
                                                   targetProcessGroups:NO];

  santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[ @"pid:10:15" ]));
}

// Three pids share a process group, so that group is signaled once and the
// later members are skipped. A fourth pid in another group gets its own signal.
// Reporting follows delivery: one record per signal sent, attributed to the pid
// that triggered it.
- (void)testGroupTargetingSignalsEachGroupOnce {
  pid_t pgidA = getpgrp() + 1;
  pid_t pgidB = getpgrp() + 2;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11, 12, 20};
  fake.pidversions = {{10, 1}, {11, 2}, {12, 3}, {20, 4}};
  fake.matching = {10, 11, 12, 20};
  fake.pgids = {{10, pgidA}, {11, pgidA}, {12, pgidA}, {20, pgidB}};
  fake.signalError = EPERM;

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID
                                                                signal:SIGTERM
                                                   targetProcessGroups:YES];

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:15", pgidA],
                          [NSString stringWithFormat:@"group:%d:15", pgidB]
                        ]));

  XCTAssertEqual(response.killedProcesses.count, 2);
  XCTAssertEqual(response.killedProcesses[0].pid, 10);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorNotPermitted);
  XCTAssertEqual(response.killedProcesses[1].pid, 20);
  XCTAssertEqual(response.killedProcesses[1].error, SNTKilledProcessErrorNotPermitted);
}

// kill(2) reads a pgid of 1 as every process on the machine and a pgid of 0 as
// the caller's own group, and santad's own group would take santad down. Those
// pids fall back to a direct signal.
- (void)testGroupTargetingSkipsUnsafeGroups {
  // Some group that isn't ours. Derived from our own so they can never collide.
  pid_t otherPgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11, 12, 13};
  fake.pidversions = {{10, 1}, {11, 2}, {12, 3}, {13, 4}};
  fake.matching = {10, 11, 12, 13};
  fake.pgids = {{10, 1}, {11, 0}, {12, getpgrp()}, {13, otherPgid}};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID
                                                                signal:SIGKILL
                                                   targetProcessGroups:YES];

  santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(
      SignalDescriptions(fake.signals), (@[
        @"pid:10:9", @"pid:11:9", @"pid:12:9", [NSString stringWithFormat:@"group:%d:9", otherPgid]
      ]));
}

- (void)testGroupTargetingFallsBackWhenPgidUnreadable {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10};
  fake.pidversions = {{10, 1}};
  fake.matching = {10};
  // No pgids entry, so the lookup fails.

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID
                                                                signal:SIGKILL
                                                   targetProcessGroups:YES];

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[ @"pid:10:9" ]));
  XCTAssertEqual(response.killedProcesses.count, 1);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorNone);
}

- (void)testSelfAndLaunchdAreNeverSignaled {
  pid_t selfPid = getpid();
  pid_t otherPgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{1, selfPid, 20};
  fake.pidversions = {{1, 1}, {selfPid, 2}, {20, 3}};
  fake.matching = {1, selfPid, 20};
  // launchd leads process group 1 and we are in our own group, so neither is a
  // usable group target either. Only pid 20's group is.
  fake.pgids = {{1, 1}, {selfPid, getpgrp()}, {20, otherPgid}};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID
                                                                signal:SIGKILL
                                                   targetProcessGroups:YES];

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals),
                        (@[ [NSString stringWithFormat:@"group:%d:9", otherPgid] ]));
  XCTAssertEqual(response.killedProcesses.count, 3);
  XCTAssertEqual(response.killedProcesses[0].pid, 1);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorInvalidTarget);
  XCTAssertEqual(response.killedProcesses[1].pid, selfPid);
  XCTAssertEqual(response.killedProcesses[1].error, SNTKilledProcessErrorInvalidTarget);
  XCTAssertEqual(response.killedProcesses[2].pid, 20);
  XCTAssertEqual(response.killedProcesses[2].error, SNTKilledProcessErrorNone);
}

// The audit token is read before and after matching so a pid recycled mid-match
// is never signaled at all.
- (void)testPidRecycledDuringMatchIsNotSignaled {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10, 11};
  fake.recycleAfterNthRead = {{10, 1}};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[ @"pid:11:9" ]));
  XCTAssertEqual(response.killedProcesses.count, 1);
  XCTAssertEqual(response.killedProcesses[0].pid, 11);
}

// A pid recycled after it matched is signaled against the token captured while
// it matched, which the new process can't satisfy, so the signal lands nowhere.
- (void)testPidRecycledAfterMatchIsNotSignaled {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10};
  fake.pidversions = {{10, 1}};
  fake.matching = {10};
  fake.recycleAfterNthRead = {{10, 2}};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[ @"pid:10:9" ]));
  XCTAssertEqual(response.killedProcesses.count, 1);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorNoSuchProcess);
}

- (void)testRunningProcessRequestHonorsSignalAndGroupTargeting {
  pid_t pgid = getpgrp() + 3;

  FakeEnv fake;
  // The running process path resolves its target from the request, so it must
  // never consult the pid snapshot.
  fake.pids = std::nullopt;
  fake.pidversions = {{10, 7}};
  fake.pgids = {{10, pgid}};

  SNTKillRequest* request =
      [[SNTKillRequestRunningProcess alloc] initWithUUID:@"uuid"
                                                     pid:10
                                              pidversion:7
                                         bootSessionUUID:[SNTSystemInfo bootSessionUUID]
                                                  signal:SIGTERM
                                     targetProcessGroups:YES];
  XCTAssertNotNil(request);

  SNTKillResponse* response = santa::KillingMachine(request, MakeEnv(&fake));

  XCTAssertEqual(response.error, SNTKillResponseErrorNone);
  XCTAssertEqualObjects(SignalDescriptions(fake.signals),
                        (@[ [NSString stringWithFormat:@"group:%d:15", pgid] ]));
  XCTAssertEqual(response.killedProcesses.count, 1);
  XCTAssertEqual(response.killedProcesses[0].pid, 10);
  XCTAssertEqual(response.killedProcesses[0].pidversion, 7);
}

//
// KillingMachineTermThenKill
//

- (void)testTermThenKillSigkillsSurvivors {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10, 11};
  // pid 10 exits during the grace period; pid 11 survives SIGTERM.
  fake.onWait = [&fake] {
    fake.matching.erase(10);
    fake.pidversions.erase(10);
  };

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  SNTKillResponse* response = santa::KillingMachineTermThenKill(request, 5.0, MakeEnv(&fake));

  XCTAssertEqual(response.error, SNTKillResponseErrorNone);
  XCTAssertEqualObjects(SignalDescriptions(fake.signals),
                        (@[ @"pid:10:15", @"pid:11:15", @"pid:11:9" ]));
  XCTAssertEqual(fake.waits.size(), 1);
  XCTAssertEqual(fake.waits[0], 5.0);

  // Both passes are reported: the two processes sent SIGTERM, then the survivor
  // sent SIGKILL.
  XCTAssertEqual(response.killedProcesses.count, 3);
  XCTAssertEqual(response.killedProcesses[2].pid, 11);
}

- (void)testTermThenKillGroupTargeting {
  pid_t sharedPgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10, 11};
  fake.pgids = {{10, sharedPgid}, {11, sharedPgid}};
  fake.onWait = [&fake] {
    fake.matching.erase(10);
    fake.pidversions.erase(10);
  };

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID
                                                                signal:SIGKILL
                                                   targetProcessGroups:YES];

  SNTKillResponse* response = santa::KillingMachineTermThenKill(request, 1.5, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:15", sharedPgid],
                          [NSString stringWithFormat:@"group:%d:9", sharedPgid],
                        ]));
  XCTAssertEqual(fake.waits.size(), 1);
  XCTAssertEqual(fake.waits[0], 1.5);
  // One result per group per pass, not per matched pid: the SIGTERM pass reports
  // the group once and the SIGKILL pass reports the survivor's group once.
  XCTAssertEqual(response.killedProcesses.count, 2);
}

// Nothing matched the SIGTERM pass, so nothing can survive it. The caller's
// queue must not be blocked for the grace period.
- (void)testTermThenKillSkipsWaitWhenNothingMatched {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10};
  fake.pidversions = {{10, 1}};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  SNTKillResponse* response = santa::KillingMachineTermThenKill(request, 5.0, MakeEnv(&fake));

  XCTAssertEqual(response.error, SNTKillResponseErrorNone);
  XCTAssertEqual(response.killedProcesses.count, 0);
  XCTAssertEqual(fake.signals.size(), 0);
  XCTAssertEqual(fake.waits.size(), 0);
}

// A SIGTERM that was never delivered has nothing to escalate either.
- (void)testTermThenKillSkipsWaitWhenNoSignalLanded {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10};
  fake.pidversions = {{10, 1}};
  fake.matching = {10};
  fake.signalError = ESRCH;

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  SNTKillResponse* response = santa::KillingMachineTermThenKill(request, 5.0, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[ @"pid:10:15" ]));
  XCTAssertEqual(fake.waits.size(), 0);
  XCTAssertEqual(response.killedProcesses.count, 1);
  XCTAssertEqual(response.killedProcesses[0].error, SNTKilledProcessErrorNoSuchProcess);
}

// Several requests in one call share the grace period: every request's SIGTERM
// goes out, the caller is held once, and only then is each request re-matched
// for its SIGKILL. Run one request at a time this would hold the caller twice,
// and the second process would not even be sent SIGTERM until the first had
// already been SIGKILLed.
- (void)testTermThenKillSharesOneGracePeriodAcrossRequests {
  pid_t firstPgid = getpgrp() + 1;
  pid_t secondPgid = getpgrp() + 2;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10};
  fake.matchingSecond = {11};
  fake.pgids = {{10, firstPgid}, {11, secondPgid}};
  // The first request's process exits during the shared grace period and the
  // second's survives it, so the re-match has to answer per request.
  fake.onWait = [&fake] {
    fake.matching.erase(10);
    fake.pidversions.erase(10);
  };

  NSArray<SNTKillRequest*>* requests = @[
    [[SNTKillRequestTeamID alloc] initWithUUID:@"first"
                                        teamID:kMatchingTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
    [[SNTKillRequestTeamID alloc] initWithUUID:@"second"
                                        teamID:kSecondTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
  ];

  NSArray<SNTKillResponse*>* responses =
      santa::KillingMachineTermThenKill(requests, 5.0, MakeEnv(&fake));

  // Both SIGTERMs precede any SIGKILL, and there is one wait between them.
  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:15", firstPgid],
                          [NSString stringWithFormat:@"group:%d:15", secondPgid],
                          [NSString stringWithFormat:@"group:%d:9", secondPgid],
                        ]));
  XCTAssertEqual(fake.waits.size(), 1);
  XCTAssertEqual(fake.waits[0], 5.0);

  // One response per request, in the order given: the first request's group was
  // gone by the re-match, the second's was escalated.
  XCTAssertEqual(responses.count, 2);
  XCTAssertEqual(responses[0].killedProcesses.count, 1);
  XCTAssertEqual(responses[1].killedProcesses.count, 2);
}

// Two requests whose matches share a process group: the group is signaled once
// per pass, not once per request. Delivering twice would take an application
// that reads a second SIGTERM as "quit now" straight past the grace period it
// was just given.
- (void)testTermThenKillSignalsASharedGroupOncePerPass {
  pid_t sharedPgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10};
  fake.matchingSecond = {11};
  fake.pgids = {{10, sharedPgid}, {11, sharedPgid}};

  NSArray<SNTKillRequest*>* requests = @[
    [[SNTKillRequestTeamID alloc] initWithUUID:@"first"
                                        teamID:kMatchingTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
    [[SNTKillRequestTeamID alloc] initWithUUID:@"second"
                                        teamID:kSecondTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
  ];

  NSArray<SNTKillResponse*>* responses =
      santa::KillingMachineTermThenKill(requests, 5.0, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:15", sharedPgid],
                          [NSString stringWithFormat:@"group:%d:9", sharedPgid],
                        ]));
  XCTAssertEqual(fake.waits.size(), 1);

  // The request that signaled the group is the one that reports the delivery; the
  // second request's match was covered by that signal, so it reports none of its
  // own even though it was re-matched at SIGKILL and found the group already
  // signaled there too.
  XCTAssertEqual(responses.count, 2);
  XCTAssertEqual(responses[0].killedProcesses.count, 2);
  XCTAssertEqual(responses[1].killedProcesses.count, 0);
}

// The same shared group, with the process that owned the group signal honoring
// SIGTERM during the grace period. Its request no longer matches anything, so if
// being covered by that signal had also cost the second request its re-match, the
// survivor in the group would never be sent SIGKILL at all: nothing else retries,
// and by this point santad has already dropped both entries. Deduplicating a
// delivery must never deduplicate a match.
- (void)testTermThenKillEscalatesACoveredRequestWhenTheGroupOwnerExits {
  pid_t sharedPgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10};
  fake.matchingSecond = {11};
  fake.pgids = {{10, sharedPgid}, {11, sharedPgid}};
  // pid 10, whose match signaled the group, quits on SIGTERM. pid 11, the second
  // request's match, ignores it.
  fake.onWait = [&fake] {
    fake.matching.erase(10);
    fake.pidversions.erase(10);
  };

  NSArray<SNTKillRequest*>* requests = @[
    [[SNTKillRequestTeamID alloc] initWithUUID:@"first"
                                        teamID:kMatchingTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
    [[SNTKillRequestTeamID alloc] initWithUUID:@"second"
                                        teamID:kSecondTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
  ];

  NSArray<SNTKillResponse*>* responses =
      santa::KillingMachineTermThenKill(requests, 5.0, MakeEnv(&fake));

  // The survivor's group is still SIGKILLed, and still only once.
  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:15", sharedPgid],
                          [NSString stringWithFormat:@"group:%d:9", sharedPgid],
                        ]));
  XCTAssertEqual(fake.waits.size(), 1);

  // The escalation is reported against the request that delivered it, which this
  // time is the second one: the first had nothing left to match.
  XCTAssertEqual(responses.count, 2);
  XCTAssertEqual(responses[0].killedProcesses.count, 1);
  XCTAssertEqual(responses[1].killedProcesses.count, 1);
  XCTAssertEqual(responses[1].killedProcesses[0].pid, 11);
}

// A group signal that failed leaves the group open for another attempt: only a
// delivery that landed can stand in for one that has not been made. Nothing
// landed here at all, so no grace period is served either.
- (void)testTermThenKillRetriesAGroupWhoseSignalFailed {
  pid_t sharedPgid = getpgrp() + 1;

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {10};
  fake.matchingSecond = {11};
  fake.pgids = {{10, sharedPgid}, {11, sharedPgid}};
  fake.signalError = ESRCH;

  NSArray<SNTKillRequest*>* requests = @[
    [[SNTKillRequestTeamID alloc] initWithUUID:@"first"
                                        teamID:kMatchingTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
    [[SNTKillRequestTeamID alloc] initWithUUID:@"second"
                                        teamID:kSecondTeamID
                                        signal:SIGKILL
                           targetProcessGroups:YES],
  ];

  NSArray<SNTKillResponse*>* responses =
      santa::KillingMachineTermThenKill(requests, 5.0, MakeEnv(&fake));

  XCTAssertEqualObjects(SignalDescriptions(fake.signals), (@[
                          [NSString stringWithFormat:@"group:%d:15", sharedPgid],
                          [NSString stringWithFormat:@"group:%d:15", sharedPgid],
                        ]));
  XCTAssertEqual(fake.waits.size(), 0);
  XCTAssertEqual(responses.count, 2);
  XCTAssertEqual(responses[0].killedProcesses[0].error, SNTKilledProcessErrorNoSuchProcess);
  XCTAssertEqual(responses[1].killedProcesses[0].error, SNTKilledProcessErrorNoSuchProcess);
}

- (void)testTermThenKillPropagatesFirstPassFailure {
  FakeEnv fake;
  fake.pids = std::nullopt;

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  SNTKillResponse* response = santa::KillingMachineTermThenKill(request, 5.0, MakeEnv(&fake));

  XCTAssertEqual(response.error, SNTKillResponseErrorListPids);
  XCTAssertEqual(fake.waits.size(), 0);
  XCTAssertEqual(fake.signals.size(), 0);
}

//
// KillingMachineAnyMatch
//

- (void)testAnyMatchFindsAMatchingPidAndSignalsNothing {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  fake.matching = {11};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  std::optional<pid_t> match = santa::KillingMachineAnyMatch(request, MakeEnv(&fake));

  XCTAssertTrue(match.has_value());
  XCTAssertEqual(*match, 11);
  // A match pass is not a kill pass.
  XCTAssertEqual(fake.signals.size(), 0);
}

- (void)testAnyMatchReturnsNothingWhenNothingMatches {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10, 11};
  fake.pidversions = {{10, 1}, {11, 2}};
  // Nothing reports the team ID.

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  XCTAssertFalse(santa::KillingMachineAnyMatch(request, MakeEnv(&fake)).has_value());
  XCTAssertEqual(fake.signals.size(), 0);
}

// The processes KillProcess refuses to signal must not be reported as matches
// either: naming one in a warning would promise a kill that never happens.
- (void)testAnyMatchSkipsKernelLaunchdAndSelf {
  pid_t selfPid = getpid();

  FakeEnv fake;
  fake.pids = std::vector<pid_t>{0, 1, selfPid};
  fake.pidversions = {{0, 1}, {1, 2}, {selfPid, 3}};
  fake.matching = {0, 1, selfPid};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  XCTAssertFalse(santa::KillingMachineAnyMatch(request, MakeEnv(&fake)).has_value());
}

- (void)testAnyMatchReturnsNothingWhenThePidSnapshotFails {
  FakeEnv fake;
  fake.pids = std::nullopt;

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid"
                                                                teamID:kMatchingTeamID];

  XCTAssertFalse(santa::KillingMachineAnyMatch(request, MakeEnv(&fake)).has_value());
}

// `platform` as a bare team ID is refused by the kill pass, so the match pass
// must refuse it too rather than reporting every platform binary as a match.
- (void)testAnyMatchRefusesPlatformTeamID {
  FakeEnv fake;
  fake.pids = std::vector<pid_t>{10};
  fake.pidversions = {{10, 1}};
  fake.matching = {10};

  SNTKillRequest* request = [[SNTKillRequestTeamID alloc] initWithUUID:@"uuid" teamID:@"platform"];

  XCTAssertFalse(santa::KillingMachineAnyMatch(request, MakeEnv(&fake)).has_value());
}

@end
