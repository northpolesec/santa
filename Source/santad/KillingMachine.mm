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
// signals through the same request. `signaledPgids` holds the groups this pass
// has already signaled, so each group is signaled exactly once no matter how
// many of its members matched: the first member signals the group and later
// members return nil, having already been reached by that one signal.
SNTKilledProcess* KillProcess(SNTKillRequest* request, int sig, audit_token_t* token,
                              const KillEnv& env, absl::flat_hash_set<pid_t>* signaledPgids) {
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
      if (!signaledPgids->insert(targetPgid).second) {
        // Signaled earlier in this pass, which reached this process too.
        return nil;
      }

      int error = env.signal_group(targetPgid, sig);
      if (error == 0) {
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

SNTKilledProcess* KillByRunningProcess(SNTKillRequestRunningProcess* request, int sig,
                                       const KillEnv& env,
                                       absl::flat_hash_set<pid_t>* signaledPgids) {
  if (![[SNTSystemInfo bootSessionUUID] isEqualToString:request.bootSessionUUID]) {
    LOGW(@"Request to kill running process with non-matching boot session UUID");
    return [[SNTKilledProcess alloc] initWithPid:request.pid
                                      pidversion:request.pidversion
                                           error:SNTKilledProcessErrorBootSessionMismatch];
  }

  audit_token_t token;
  if (env.token_for_pid(request.pid, &token)) {
    if (Pidversion(token) == request.pidversion) {
      return KillProcess(request, sig, &token, env, signaledPgids);
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

SNTKilledProcess* KillByMatchers(SNTKillRequest* request, int sig, pid_t pid,
                                 const std::vector<std::unique_ptr<ProcessMatcher>>& matchers,
                                 const KillEnv& env, absl::flat_hash_set<pid_t>* signaledPgids) {
  std::optional<audit_token_t> token = MatchProcess(pid, matchers, env);
  if (!token) {
    return nil;
  }
  return KillProcess(request, sig, &token.value(), env, signaledPgids);
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

// One kill pass at signal `sig`: match every process, then signal the matches.
SNTKillResponse* RunKillPass(SNTKillRequest* request, int sig, const KillEnv& env) {
  NSMutableArray<SNTKilledProcess*>* killedProcs = [NSMutableArray array];

  // Groups already signaled by this pass, so a group with several matching
  // members is signaled once. Empty unless the request targets groups.
  absl::flat_hash_set<pid_t> signaledPgids;

  if ([request isKindOfClass:[SNTKillRequestRunningProcess class]]) {
    SNTKilledProcess* killed =
        KillByRunningProcess((SNTKillRequestRunningProcess*)request, sig, env, &signaledPgids);
    if (killed) {
      [killedProcs addObject:killed];
    }
  } else {
    std::optional<std::vector<pid_t>> pids = env.list_pids();
    if (!pids) {
      LOGE(@"Unable to get list of running processes");
      return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorListPids];
    }

    std::optional<std::vector<std::unique_ptr<ProcessMatcher>>> matchers =
        BuildMatchers(request, env);
    if (!matchers) {
      return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorInvalidRequest];
    }

    for (pid_t pid : *pids) {
      if (pid == 0) {
        continue;
      }

      SNTKilledProcess* killed = KillByMatchers(request, sig, pid, *matchers, env, &signaledPgids);
      if (killed) {
        [killedProcs addObject:killed];
      }
    }
  }

  return [[SNTKillResponse alloc] initWithKilledProcesses:killedProcs];
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
  return RunKillPass(request, request.signal, env);
}

SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace) {
  return KillingMachineTermThenKill(request, grace, KillEnv());
}

SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace,
                                            const KillEnv& env) {
  SNTKillResponse* termed = RunKillPass(request, SIGTERM, env);
  if (termed.error != SNTKillResponseErrorNone) {
    return termed;
  }

  // Nothing was actually sent SIGTERM: nothing matched, or every match was
  // rejected or already gone. Nothing can survive a signal that was never
  // delivered, so don't hold the caller's queue for a second pass.
  BOOL anySignaled = NO;
  for (SNTKilledProcess* termedProc in termed.killedProcesses) {
    if (termedProc.error == SNTKilledProcessErrorNone) {
      anySignaled = YES;
      break;
    }
  }
  if (!anySignaled) {
    return termed;
  }

  env.wait(grace);

  SNTKillResponse* killed = RunKillPass(request, SIGKILL, env);

  // Both passes are reported, in order: what was sent SIGTERM, then whichever
  // of those survived long enough to be sent SIGKILL.
  NSMutableArray<SNTKilledProcess*>* all = [NSMutableArray arrayWithArray:termed.killedProcesses];
  if (killed.killedProcesses) {
    [all addObjectsFromArray:killed.killedProcesses];
  }

  return [[SNTKillResponse alloc] initWithError:killed.error killedProcesses:all];
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
