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

#include <cstring>
#include <map>
#include <optional>
#include <set>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#include "Source/santad/KillingMachine.h"

/// The fakes the three kill suites (KillingMachineTest, SNTTimedRuleKillsTest and
/// TimedRuleKillsScenarioTest) had a copy of each. One definition here, and each
/// suite overwrites the seams it discriminates on: the pid-recycling and errno
/// models in KillingMachineTest, the SIGNINGID code signing lookups and the
/// SIGTERM-honoring process groups in TimedRuleKillsScenarioTest.
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

  std::vector<FakeSignal> signals;
  std::vector<NSTimeInterval> waits;
};

/// Wires every seam the suites fake the same way. `EnvPtr` is anything that
/// dereferences to a FakeKillEnv, which is what lets a suite hand over a raw
/// pointer to a stack env or a shared_ptr to one that outlives the frame the
/// env was built in; the lambdas hold whichever was given.
///
/// The bodies here are the plain ones: a snapshot that answers whatever `pids`
/// holds, a token whose pidversion never changes under it, the TEAMID lookup
/// over `matching` and `matchingSecond`, and signal and wait seams that only
/// record. Anything that models a process changing under the caller is a
/// suite's own override.
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

/// Renders recorded deliveries as "pid:10:9" / "group:100:15" so a failing
/// assertion prints the whole sequence instead of a count mismatch.
NSArray<NSString*>* SignalDescriptions(const std::vector<FakeSignal>& signals);

}  // namespace santa::testing

/// The host clocks a test builds a believable clock over: a system wall clock it
/// moves at will, and a mach continuous reading that tracks the real one plus an
/// offset. Mach continuous time is the reading nothing on the machine can move,
/// so a test only ever adds to it, which is how it says "this much time really
/// did pass" while the wall clock says otherwise. Shared by the two suites that
/// drive a kill deadline through a clock.
@interface FakeHost : NSObject
@property NSTimeInterval wall;
@property NSTimeInterval machOffsetSeconds;
@property(copy) NSString* bootUUID;
@property(readonly) uint64_t mach;
@end

#endif  // SANTA_SANTAD_KILLENVTESTSUPPORT_H
