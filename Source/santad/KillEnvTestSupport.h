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

#ifndef SANTA_SANTAD_KILLENVTESTSUPPORT_H
#define SANTA_SANTAD_KILLENVTESTSUPPORT_H

#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#include <mach/mach_time.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#include "Source/santad/KillingMachine.h"

/// The fakes the kill suites (KillingMachineTest and SNTTimedRuleKillsTest) had
/// a copy of each. One definition here, and a suite that discriminates on
/// something this does not model derives from the struct and overwrites the
/// seam: SNTTimedRuleKillsTest does that with the code signing lookups, since it
/// matches rules on more than a team ID.
namespace santa::testing {

/// The team ID the fake csops reports for the pids a test wants matched. Paired
/// with a TEAMID rule or request for the same value, this is how a test chooses
/// what the real (unfaked) matching machinery matches.
inline NSString* const kMatchingTeamID = @"ABCDE12345";

/// A second team ID, for the cases that need two requests matching two different
/// processes. Same length as the first, so the fake blob math is the same.
inline NSString* const kSecondTeamID = @"FGHIJ67890";

/// One recorded signal delivery. `target` is a pid when `group` is false and a
/// pgid when it is true.
struct FakeSignal {
  pid_t target;
  int sig;
  bool group;
};

/// State behind a fully faked santa::KillEnv. Every seam is replaced, so no test
/// can reach a real syscall (or signal a real process) by forgetting to override
/// one. A suite that needs more state derives from this and adds it.
struct FakeKillEnv {
  // nullopt makes the pid snapshot fail.
  std::optional<std::vector<pid_t>> pids = std::vector<pid_t>{};
  // pid -> pidversion. A pid that isn't here has no audit token.
  std::map<pid_t, int> pidversions;
  // pids the fake csops reports kMatchingTeamID for.
  std::set<pid_t> matching;
  // pids it reports kSecondTeamID for instead, so a test can have two requests
  // match two different processes.
  std::set<pid_t> matchingSecond;
  // pid -> pgid. A pid that isn't here has an unreadable process group.
  std::map<pid_t, pid_t> pgids;
  // pid -> the audit token read after which that pid is recycled: its live
  // pidversion changes, modeling a different process taking over the pid.
  // Reads are counted per pid across the whole call. Matching reads a pid's
  // token twice, so 1 recycles mid-match and 2 recycles after it matched.
  std::map<pid_t, int> recycleAfterNthRead;
  // errno both signal seams return for a delivery that reaches its target.
  int signalError = 0;

  std::vector<FakeSignal> signals;
  std::vector<NSTimeInterval> waits;
  std::map<pid_t, int> tokenReads;
  // Runs when the term-then-kill grace wait starts, so a test can retire the
  // processes that died from SIGTERM.
  std::function<void()> onWait = [] {};
};

/// Wires every seam. `EnvPtr` is anything that dereferences to a FakeKillEnv,
/// which is what lets a suite hand over a raw pointer to a stack env or a
/// shared_ptr to one that outlives the frame the env was built in; the lambdas
/// hold whichever was given.
template <typename EnvPtr>
santa::KillEnv MakeKillEnv(EnvPtr fake) {
  santa::KillEnv env;

  env.list_pids = [fake] { return fake->pids; };

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

  // The blob shape is the one CSOpsHelper parses: a length that counts the
  // wrapper and its terminator.
  env.csops_func = [fake](pid_t pid, unsigned int ops, void* useraddr, size_t usersize) {
    NSString* teamID = fake->matching.count(pid)
                           ? kMatchingTeamID
                           : (fake->matchingSecond.count(pid) ? kSecondTeamID : nil);
    if (ops != santa::kCsopTeamID || !teamID ||
        usersize < sizeof(santa::csops_blob) + teamID.length) {
      return -1;
    }
    santa::csops_blob* blob = (santa::csops_blob*)useraddr;
    blob->type = 0;
    blob->len = htonl(sizeof(santa::csops_blob) + 1 + teamID.length);
    std::memcpy(blob->data, teamID.UTF8String, teamID.length);
    return 0;
  };

  env.pgid_for_pid = [fake](pid_t pid) -> pid_t {
    auto it = fake->pgids.find(pid);
    return it == fake->pgids.end() ? -1 : it->second;
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

/// Renders recorded deliveries as "pid:10:9" / "group:100:15" so a failing
/// assertion prints the whole sequence instead of a count mismatch.
NSArray<NSString*>* SignalDescriptions(const std::vector<FakeSignal>& signals);

}  // namespace santa::testing

/// The host clocks a test builds a believable clock over: a system wall clock it
/// moves at will, and a mach continuous reading that tracks the real one plus an
/// offset. Mach continuous time is the reading nothing on the machine can move,
/// so a test only ever adds to it, which is how it says "this much time really
/// did pass" while the wall clock says otherwise.
@interface FakeHost : NSObject
@property NSTimeInterval wall;
@property NSTimeInterval machOffsetSeconds;
@property(copy) NSString* bootUUID;
@property(readonly) uint64_t mach;
@end

#endif  // SANTA_SANTAD_KILLENVTESTSUPPORT_H
