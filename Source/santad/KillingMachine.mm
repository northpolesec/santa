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
#include <Kernel/kern/cs_blobs.h>
#include <libproc.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <optional>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/String.h"
#include "Source/common/SystemResources.h"
#include "absl/cleanup/cleanup.h"
#include "absl/container/flat_hash_set.h"

namespace santa {

int SignalProcessGroup(pid_t pgid, int sig) {
  return kill(-pgid, sig) == 0 ? 0 : errno;
}

void BlockingWait(NSTimeInterval seconds) {
  [NSThread sleepForTimeInterval:seconds];
}

namespace {

// Base class for process matchers
class ProcessMatcher {
 public:
  virtual ~ProcessMatcher() = default;
  virtual bool Matches(pid_t pid) const = 0;
};

// StringMatcher compares a string value retrieved via a CSOps getter function
class StringMatcher : public ProcessMatcher {
 public:
  using GetterFunc = std::function<std::optional<std::string>(pid_t, CSOpsFunc)>;

  StringMatcher(NSString* desired, GetterFunc getter, CSOpsFunc csops_func)
      : desired_(NSStringToUTF8StringView(desired)),
        getter_(std::move(getter)),
        csops_func_(std::move(csops_func)) {}

  bool Matches(pid_t pid) const override {
    auto actual = getter_(pid, csops_func_);
    return actual && *actual == desired_;
  }

 private:
  std::string desired_;
  GetterFunc getter_;
  CSOpsFunc csops_func_;
};

// FlagsMatcher compares status flags against a defined mask
class FlagsMatcher : public ProcessMatcher {
 public:
  FlagsMatcher(uint32_t mask, CSOpsFunc csops_func)
      : mask_(mask), csops_func_(std::move(csops_func)) {}

  bool Matches(pid_t pid) const override {
    auto flags = CSOpsStatusFlags(pid, csops_func_);
    return flags && (*flags & mask_) != 0;
  }

 private:
  uint32_t mask_;
  CSOpsFunc csops_func_;
};

// CSOpsHelper.h now also declares audit_token_t-taking overloads of the
// getters below with the same names, so the bare function name is ambiguous
// as a make_unique<StringMatcher> argument (overload resolution needs a
// target type, and make_unique's forwarding-reference deduction doesn't
// provide one). Cast to the pid-based overload's exact type to disambiguate.
using StringGetterFunc = std::optional<std::string> (*)(pid_t, CSOpsFunc);

std::unique_ptr<ProcessMatcher> MakeCDHashMatcher(NSString* cdhash, CSOpsFunc csops_func = csops) {
  return std::make_unique<StringMatcher>(cdhash, static_cast<StringGetterFunc>(CSOpsGetCDHash),
                                         std::move(csops_func));
}

std::unique_ptr<ProcessMatcher> MakeTeamIDMatcher(NSString* teamID, CSOpsFunc csops_func = csops) {
  return std::make_unique<StringMatcher>(teamID, static_cast<StringGetterFunc>(CSOpsGetTeamID),
                                         std::move(csops_func));
}

std::unique_ptr<ProcessMatcher> MakeSigningIDMatcher(NSString* signingID,
                                                     CSOpsFunc csops_func = csops) {
  return std::make_unique<StringMatcher>(
      signingID, static_cast<StringGetterFunc>(CSOpsGetSigningID), std::move(csops_func));
}

std::unique_ptr<ProcessMatcher> MakeStatusFlagsMatcher(uint32_t mask,
                                                       CSOpsFunc csops_func = csops) {
  return std::make_unique<FlagsMatcher>(mask, std::move(csops_func));
}

SNTKilledProcessError LibprocSignalErrorToKilledProcessError(int error) {
  switch (error) {
    case 0: return SNTKilledProcessErrorNone;
    case EPERM: return SNTKilledProcessErrorNotPermitted;
    case ESRCH: return SNTKilledProcessErrorNoSuchProcess;
    case EINVAL: return SNTKilledProcessErrorInvalidArgument;
    default: return SNTKilledProcessErrorUnknown;
  }
}

// Delivers `sig` to the process `token` identifies, or to that process's group
// when the request targets process groups. `sig` is passed in rather than read
// from the request so the term-then-kill path can drive two passes at different
// signals through the same request.
//
// `signaledPgids` is shared across the pass and holds groups signaled
// successfully, so a group reached by several requests gets one delivery.
// `attemptedPgids` is per-request and holds every group tried, landed or not,
// so a failed attempt is not retried within a request but does not block
// another request's own attempt. A nil return can mean "already covered", not
// only "did not match".
SNTKilledProcess* KillProcess(SNTKillRequest* request, int sig, audit_token_t* token,
                              const KillEnv& env, absl::flat_hash_set<pid_t>* signaledPgids,
                              absl::flat_hash_set<pid_t>* attemptedPgids) {
  static pid_t myPid = getpid();
  pid_t targetPid = Pid(*token);
  pid_t targetPidversion = Pidversion(*token);

  if (targetPid == myPid || targetPid == 1) {
    LOGW(@"Rejecting request to kill disallowed process");
    return [[SNTKilledProcess alloc] initWithPid:targetPid
                                      pidversion:targetPidversion
                                           error:SNTKilledProcessErrorInvalidTarget];
  }

  if (request.targetProcessGroups) {
    // The group is read here, immediately after the caller verified the audit
    // token that brackets the match, so the raw syscall adjacency (token_after
    // -> getpgid) matches the direct path's. The safety is NOT equivalent,
    // though: the direct path's proc_signal_with_audittoken re-validates the
    // token at delivery, so a pid recycled after matching yields ESRCH and its
    // effective window is ~zero. kill(-pgid) cannot re-validate anything, so
    // here the adjacency is the sole protection: a pid recycled in the narrow
    // token_after -> getpgid window would put a stranger's group in scope. That
    // residual is inherent to kill(-pgid) and is accepted; re-reading the token
    // around this lookup would not remove it.
    pid_t targetPgid = env.pgid_for_pid(targetPid);

    // A group is only a legitimate target above pgid 1 and outside our own:
    // kill(2) reads a pgid of 0 as the caller's own group and 1 as every
    // process on the machine, and our own group would take santad down with
    // it. Anything else, an unreadable pgid included, falls through to
    // signaling the one matched process, which is never broader than what was
    // asked for.
    if (targetPgid > 1 && targetPgid != getpgrp()) {
      // Already signaled by this pass, or already tried by this request.
      if (signaledPgids->count(targetPgid) || !attemptedPgids->insert(targetPgid).second) {
        return nil;
      }

      int error = env.signal_group(targetPgid, sig);
      if (error == 0) {
        signaledPgids->insert(targetPgid);
        LOGI(@"Signaled (%d) process group: %d (from kill command: %@)", sig, targetPgid,
             request.uuid);
      } else {
        LOGW(@"Failed to signal (%d) process group: %d, error: %d (from kill command: %@)", sig,
             targetPgid, error, request.uuid);
      }

      return [[SNTKilledProcess alloc] initWithPid:targetPid
                                        pidversion:targetPidversion
                                             error:LibprocSignalErrorToKilledProcessError(error)];
    }
  }

  int error = env.signal_token(token, sig);
  if (error == 0) {
    LOGI(@"Signaled (%d) process: %d (from kill command: %@)", sig, targetPid, request.uuid);
  } else {
    LOGW(@"Failed to signal (%d) process: %d, error: %d (from kill command: %@)", sig, targetPid,
         error, request.uuid);
  }

  return [[SNTKilledProcess alloc] initWithPid:targetPid
                                    pidversion:targetPidversion
                                         error:LibprocSignalErrorToKilledProcessError(error)];
}

// `matched` is set when the named process was found, even if no signal record
// resulted.
SNTKilledProcess* KillByRunningProcess(SNTKillRequestRunningProcess* request, int sig,
                                       const KillEnv& env,
                                       absl::flat_hash_set<pid_t>* signaledPgids,
                                       absl::flat_hash_set<pid_t>* attemptedPgids, bool* matched) {
  if (![[SNTSystemInfo bootSessionUUID] isEqualToString:request.bootSessionUUID]) {
    LOGW(@"Request to kill running process with non-matching boot session UUID");
    return [[SNTKilledProcess alloc] initWithPid:request.pid
                                      pidversion:request.pidversion
                                           error:SNTKilledProcessErrorBootSessionMismatch];
  }

  audit_token_t token;
  if (env.token_for_pid(request.pid, &token)) {
    if (Pidversion(token) == request.pidversion) {
      *matched = true;
      return KillProcess(request, sig, &token, env, signaledPgids, attemptedPgids);
    } else {
      LOGW(@"Rejecting request to kill pid (%d) due to pidversion mismatch (got: %d, want: %d)",
           request.pid, Pidversion(token), request.pidversion);
      return [[SNTKilledProcess alloc] initWithPid:request.pid
                                        pidversion:request.pidversion
                                             error:SNTKilledProcessErrorNoSuchProcess];
    }
  }
  return nil;
}

// Returns the audit token to signal when every matcher matches `pid`, or
// nullopt otherwise. Signals nothing: this is the match half on its own, so
// both the kill loop and the banner's is-anything-running check share it.
std::optional<audit_token_t> MatchProcess(
    pid_t pid, const std::vector<std::unique_ptr<ProcessMatcher>>& matchers, const KillEnv& env) {
  // To protect against pid wrap races, we must grab the audit token before
  // and after the matcher checks to ensure the process that info was looked
  // up for matches the process we will signal.
  audit_token_t token_before;
  audit_token_t token_after;

  if (!env.token_for_pid(pid, &token_before)) {
    // Process likely exited.
    return std::nullopt;
  }

  // Check all matchers
  for (const auto& matcher : matchers) {
    if (!matcher->Matches(pid)) {
      return std::nullopt;
    }
  }

  // All matchers matched. Now verify the process didn't change.
  if (!env.token_for_pid(pid, &token_after)) {
    LOGD(@"Failed to get audit token for matching. Process likely exited.");
    return std::nullopt;
  }

  if (Pidversion(token_before) != Pidversion(token_after)) {
    LOGD(@"Audit token mismatch. Process exited.");
    return std::nullopt;
  }

  return token_after;
}

// `matched` is set when `pid` matched, even if its group was already signaled
// and no record resulted.
SNTKilledProcess* KillByMatchers(SNTKillRequest* request, int sig, pid_t pid,
                                 const std::vector<std::unique_ptr<ProcessMatcher>>& matchers,
                                 const KillEnv& env, absl::flat_hash_set<pid_t>* signaledPgids,
                                 absl::flat_hash_set<pid_t>* attemptedPgids, bool* matched) {
  std::optional<audit_token_t> token = MatchProcess(pid, matchers, env);
  if (!token) {
    return nil;
  }
  *matched = true;
  return KillProcess(request, sig, &token.value(), env, signaledPgids, attemptedPgids);
}

// The matchers a request's criteria come down to, or nullopt when the request
// can't be matched against running processes at all. Not for a running-process
// request, which names one process directly rather than matching for it.
std::optional<std::vector<std::unique_ptr<ProcessMatcher>>> BuildMatchers(SNTKillRequest* request,
                                                                          const KillEnv& env) {
  std::vector<std::unique_ptr<ProcessMatcher>> matchers;

  if ([request isKindOfClass:[SNTKillRequestCDHash class]]) {
    matchers.push_back(MakeCDHashMatcher(((SNTKillRequestCDHash*)request).cdhash, env.csops_func));
  } else if ([request isKindOfClass:[SNTKillRequestSigningID class]]) {
    SNTKillRequestSigningID* signingIDRequest = (SNTKillRequestSigningID*)request;
    if ([signingIDRequest.teamID isEqualToString:kPlatformTeamID]) {
      matchers.push_back(MakeStatusFlagsMatcher(CS_PLATFORM_BINARY, env.csops_func));
    } else {
      matchers.push_back(MakeTeamIDMatcher(signingIDRequest.teamID, env.csops_func));
    }
    matchers.push_back(MakeSigningIDMatcher(signingIDRequest.signingID, env.csops_func));
  } else if ([request isKindOfClass:[SNTKillRequestTeamID class]]) {
    // Don't allow `platform` here as killing all platform binaries is a bad
    // idea and isn't supported.
    SNTKillRequestTeamID* teamIDRequest = (SNTKillRequestTeamID*)request;
    if ([teamIDRequest.teamID isEqualToString:kPlatformTeamID]) {
      return std::nullopt;
    }
    matchers.push_back(MakeTeamIDMatcher(teamIDRequest.teamID, env.csops_func));
  } else {
    LOGE(@"Unexpected request type: %@", [request class]);
    return std::nullopt;
  }

  return matchers;
}

// One pass's response, plus whether the request matched anything. The two
// differ when a match's group was already signaled by another request: no
// record results, but the request still has processes to escalate at SIGKILL.
struct PassOutcome {
  SNTKillResponse* response;
  bool matched;
};

// One kill pass at signal `sig`: match every process, then signal the matches.
// `signaledPgids` is the caller's because a pass can span several requests: a
// group two requests both reach must be signaled once, not twice. Empty unless
// a request targets groups.
PassOutcome RunKillPass(SNTKillRequest* request, int sig, const KillEnv& env,
                        absl::flat_hash_set<pid_t>* signaledPgids) {
  NSMutableArray<SNTKilledProcess*>* killedProcs = [NSMutableArray array];
  bool matched = false;
  // This request's own attempts; see KillProcess.
  absl::flat_hash_set<pid_t> attemptedPgids;

  if ([request isKindOfClass:[SNTKillRequestRunningProcess class]]) {
    SNTKilledProcess* killed = KillByRunningProcess((SNTKillRequestRunningProcess*)request, sig,
                                                    env, signaledPgids, &attemptedPgids, &matched);
    if (killed) {
      [killedProcs addObject:killed];
    }
  } else {
    std::optional<std::vector<pid_t>> pids = env.list_pids();
    if (!pids) {
      LOGE(@"Unable to get list of running processes");
      return {.response = [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorListPids],
              .matched = false};
    }

    std::optional<std::vector<std::unique_ptr<ProcessMatcher>>> matchers =
        BuildMatchers(request, env);
    if (!matchers) {
      return {
          .response = [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorInvalidRequest],
          .matched = false};
    }

    for (pid_t pid : *pids) {
      if (pid == 0) {
        continue;
      }

      SNTKilledProcess* killed = KillByMatchers(request, sig, pid, *matchers, env, signaledPgids,
                                                &attemptedPgids, &matched);
      if (killed) {
        [killedProcs addObject:killed];
      }
    }
  }

  return {.response = [[SNTKillResponse alloc] initWithKilledProcesses:killedProcs],
          .matched = matched};
}

// Whether the pass delivered a signal to anything. An error response did not.
bool AnySignalDelivered(SNTKillResponse* response) {
  for (SNTKilledProcess* killedProc in response.killedProcesses) {
    if (killedProc.error == SNTKilledProcessErrorNone) {
      return true;
    }
  }
  return false;
}

}  // namespace

#ifdef DEBUG
// These test-only functions expose hooks for testing matcher functionality
// without having to expose the internal types.
bool TestCDHashMatcher(pid_t pid, NSString* cdhash, CSOpsFunc csops_func) {
  auto matcher = MakeCDHashMatcher(cdhash, csops_func);
  return matcher->Matches(pid);
}

bool TestTeamIDMatcher(pid_t pid, NSString* teamID, CSOpsFunc csops_func) {
  auto matcher = MakeTeamIDMatcher(teamID, csops_func);
  return matcher->Matches(pid);
}

bool TestSigningIDMatcher(pid_t pid, NSString* signingID, CSOpsFunc csops_func) {
  auto matcher = MakeSigningIDMatcher(signingID, csops_func);
  return matcher->Matches(pid);
}

bool TestStatusFlagsMatcher(pid_t pid, uint32_t mask, CSOpsFunc csops_func) {
  auto matcher = MakeStatusFlagsMatcher(mask, csops_func);
  return matcher->Matches(pid);
}
#endif

SNTKillResponse* KillingMachine(SNTKillRequest* request) {
  return KillingMachine(request, KillEnv());
}

SNTKillResponse* KillingMachine(SNTKillRequest* request, const KillEnv& env) {
  absl::flat_hash_set<pid_t> signaledPgids;
  return RunKillPass(request, request.signal, env, &signaledPgids).response;
}

SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace) {
  return KillingMachineTermThenKill(request, grace, KillEnv());
}

SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace,
                                            const KillEnv& env) {
  return KillingMachineTermThenKill(@[ request ], grace, env).firstObject;
}

NSArray<SNTKillResponse*>* KillingMachineTermThenKill(NSArray<SNTKillRequest*>* requests,
                                                      NSTimeInterval grace, const KillEnv& env) {
  // All SIGTERMs first, so one grace period covers every request.
  NSMutableArray<SNTKillResponse*>* termed = [NSMutableArray arrayWithCapacity:requests.count];
  std::vector<bool> matched;
  matched.reserve(requests.count);
  absl::flat_hash_set<pid_t> termedPgids;
  BOOL anySignaled = NO;
  for (SNTKillRequest* request in requests) {
    PassOutcome outcome = RunKillPass(request, SIGTERM, env, &termedPgids);
    [termed addObject:outcome.response];
    matched.push_back(outcome.matched);
    anySignaled = anySignaled || AnySignalDelivered(outcome.response);
  }

  // Nothing was signaled, so nothing can survive it: skip the grace wait.
  if (!anySignaled) {
    return termed;
  }

  env.wait(grace);

  // The SIGKILL pass dedupes groups on a set of its own; SIGTERM's is done. Its
  // results replace the SIGTERM responses in place, so `termed` ends up holding
  // both passes.
  absl::flat_hash_set<pid_t> killedPgids;
  for (NSUInteger index = 0; index < requests.count; index++) {
    // Re-match every request that matched, not only those that delivered a
    // signal: the request that signaled a shared group may no longer match
    // (its process honored SIGTERM), leaving this one's survivors to escalate.
    if (!matched[index]) {
      continue;
    }

    SNTKillResponse* killed = RunKillPass(requests[index], SIGKILL, env, &killedPgids).response;

    // Report both passes in order: SIGTERM deliveries, then SIGKILL survivors.
    NSMutableArray<SNTKilledProcess*>* both =
        [NSMutableArray arrayWithArray:termed[index].killedProcesses];
    if (killed.killedProcesses) {
      [both addObjectsFromArray:killed.killedProcesses];
    }
    termed[index] = [[SNTKillResponse alloc] initWithError:killed.error killedProcesses:both];
  }

  return termed;
}

std::optional<pid_t> KillingMachineAnyMatch(SNTKillRequest* request) {
  return KillingMachineAnyMatch(request, KillEnv());
}

std::optional<pid_t> KillingMachineAnyMatch(SNTKillRequest* request, const KillEnv& env) {
  // Before listing processes, unlike the kill pass: nothing here distinguishes
  // one failure from another, so a request that can never match shouldn't pay
  // for the snapshot.
  std::optional<std::vector<std::unique_ptr<ProcessMatcher>>> matchers =
      BuildMatchers(request, env);
  if (!matchers) {
    return std::nullopt;
  }

  std::optional<std::vector<pid_t>> pids = env.list_pids();
  if (!pids) {
    LOGE(@"Unable to get list of running processes");
    return std::nullopt;
  }

  // The processes KillProcess refuses to signal are skipped here too: reporting
  // one of them as a match would promise a kill that never happens.
  const pid_t myPid = getpid();

  for (pid_t pid : *pids) {
    if (pid == 0 || pid == 1 || pid == myPid) {
      continue;
    }

    if (std::optional<audit_token_t> token = MatchProcess(pid, *matchers, env)) {
      return Pid(*token);
    }
  }

  return std::nullopt;
}

}  // namespace santa
