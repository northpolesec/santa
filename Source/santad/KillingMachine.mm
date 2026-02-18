/// Copyright 2025 North Pole Security, Inc.
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

#include <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/signal.h>

#include <cerrno>
#include <memory>
#include <optional>
#include <vector>

#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/String.h"
#include "Source/common/SystemResources.h"
#include "Source/santad/CSOpsHelper.h"
#include "absl/cleanup/cleanup.h"

namespace santa {

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

  StringMatcher(NSString *desired, GetterFunc getter, CSOpsFunc csops_func)
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

std::unique_ptr<ProcessMatcher> MakeCDHashMatcher(NSString *cdhash, CSOpsFunc csops_func = csops) {
  return std::make_unique<StringMatcher>(cdhash, CSOpsGetCDHash, std::move(csops_func));
}

std::unique_ptr<ProcessMatcher> MakeTeamIDMatcher(NSString *teamID, CSOpsFunc csops_func = csops) {
  return std::make_unique<StringMatcher>(teamID, CSOpsGetTeamID, std::move(csops_func));
}

std::unique_ptr<ProcessMatcher> MakeSigningIDMatcher(NSString *signingID,
                                                     CSOpsFunc csops_func = csops) {
  return std::make_unique<StringMatcher>(signingID, CSOpsGetSigningID, std::move(csops_func));
}

std::unique_ptr<ProcessMatcher> MakeStatusFlagsMatcher(uint32_t mask,
                                                       CSOpsFunc csops_func = csops) {
  return std::make_unique<FlagsMatcher>(mask, std::move(csops_func));
}

bool AuditTokenForPid(pid_t pid, audit_token_t *token) {
  task_name_t task;
  mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;

  if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
    LOGD(@"Unable to get task name port for pid: %d", pid);
    return false;
  }

  absl::Cleanup task_cleanup = ^{
    mach_port_deallocate(mach_task_self(), task);
  };

  if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)token, &size) != KERN_SUCCESS) {
    LOGD(@"Unable to get task info for pid: %d", pid);
    return false;
  }

  return true;
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

SNTKilledProcess *KillProcess(SNTKillRequest *request, audit_token_t *token) {
  static pid_t myPid = getpid();
  pid_t targetPid = audit_token_to_pid(*token);
  pid_t targetPidversion = audit_token_to_pidversion(*token);

  if (targetPid == myPid || targetPid == 1) {
    LOGW(@"Rejecting request to kill disallowed process");
    return [[SNTKilledProcess alloc] initWithPid:targetPid
                                      pidversion:targetPidversion
                                           error:SNTKilledProcessErrorInvalidTarget];
  }

  int error = proc_signal_with_audittoken(token, SIGKILL);
  if (error == 0) {
    LOGI(@"Killed process: %d (from kill command: %@)", targetPid, request.uuid);
  } else {
    LOGW(@"Failed to kill process: %d, error: %d (from kill command: %@)", targetPid, error,
         request.uuid);
  }

  return [[SNTKilledProcess alloc] initWithPid:targetPid
                                    pidversion:targetPidversion
                                         error:LibprocSignalErrorToKilledProcessError(error)];
}

SNTKilledProcess *KillByRunningProcess(SNTKillRequestRunningProcess *request) {
  if (![[SNTSystemInfo bootSessionUUID] isEqualToString:request.bootSessionUUID]) {
    LOGW(@"Request to kill running process with non-matching boot session UUID");
    return [[SNTKilledProcess alloc] initWithPid:request.pid
                                      pidversion:request.pidversion
                                           error:SNTKilledProcessErrorBootSessionMismatch];
  }

  audit_token_t token;
  if (AuditTokenForPid(request.pid, &token)) {
    if (audit_token_to_pidversion(token) == request.pidversion) {
      return KillProcess(request, &token);
    } else {
      LOGW(@"Rejecting request to kill pid (%d) due to pidversion mismatch (got: %d, want: %d)",
           request.pid, audit_token_to_pidversion(token), request.pidversion);
      return [[SNTKilledProcess alloc] initWithPid:request.pid
                                        pidversion:request.pidversion
                                             error:SNTKilledProcessErrorNoSuchProcess];
    }
  }
  return nil;
}

SNTKilledProcess *KillByMatchers(SNTKillRequest *request, pid_t pid,
                                 const std::vector<std::unique_ptr<ProcessMatcher>> &matchers) {
  // To protect against pid wrap races, we must grab the audit token before
  // and after the matcher checks to ensure the process that info was looked
  // up for matches the process we will signal.
  audit_token_t token_before;
  audit_token_t token_after;

  if (!AuditTokenForPid(pid, &token_before)) {
    // Process likely exited.
    return nil;
  }

  // Check all matchers
  for (const auto &matcher : matchers) {
    if (!matcher->Matches(pid)) {
      return nil;
    }
  }

  // All matchers matched. Now verify the process didn't change and kill it.
  if (AuditTokenForPid(pid, &token_after)) {
    if (audit_token_to_pidversion(token_before) == audit_token_to_pidversion(token_after)) {
      LOGD(@"GOT TOK MATCH, DO KILL: %d, %d", audit_token_to_pid(token_after),
           audit_token_to_pidversion(token_after));
      return KillProcess(request, &token_after);
    } else {
      LOGD(@"Audit token mismatch. Process exited.");
    }
  } else {
    LOGD(@"Failed to get audit token for matching. Process likely exited.");
  }

  return nil;
}

}  // namespace

#ifdef DEBUG
// These test-only functions expose hooks for testing matcher functionality
// without having to expose the internal types.
bool TestCDHashMatcher(pid_t pid, NSString *cdhash, CSOpsFunc csops_func) {
  auto matcher = MakeCDHashMatcher(cdhash, csops_func);
  return matcher->Matches(pid);
}

bool TestTeamIDMatcher(pid_t pid, NSString *teamID, CSOpsFunc csops_func) {
  auto matcher = MakeTeamIDMatcher(teamID, csops_func);
  return matcher->Matches(pid);
}

bool TestSigningIDMatcher(pid_t pid, NSString *signingID, CSOpsFunc csops_func) {
  auto matcher = MakeSigningIDMatcher(signingID, csops_func);
  return matcher->Matches(pid);
}

bool TestStatusFlagsMatcher(pid_t pid, uint32_t mask, CSOpsFunc csops_func) {
  auto matcher = MakeStatusFlagsMatcher(mask, csops_func);
  return matcher->Matches(pid);
}
#endif

SNTKillResponse *KillingMachine(SNTKillRequest *request) {
  NSMutableArray<SNTKilledProcess *> *killedProcs = [NSMutableArray array];

  if ([request isKindOfClass:[SNTKillRequestRunningProcess class]]) {
    SNTKilledProcess *killed = KillByRunningProcess((SNTKillRequestRunningProcess *)request);
    if (killed) {
      [killedProcs addObject:killed];
    }
  } else {
    std::optional<std::vector<pid_t>> pids = GetPidList();
    if (!pids) {
      LOGE(@"Unable to get list of running processes");
      return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorListPids];
    }

    std::vector<std::unique_ptr<ProcessMatcher>> matchers;

    // Populate the appropriate matchers for the request
    if ([request isKindOfClass:[SNTKillRequestCDHash class]]) {
      matchers.push_back(MakeCDHashMatcher(((SNTKillRequestCDHash *)request).cdhash));
    } else if ([request isKindOfClass:[SNTKillRequestSigningID class]]) {
      SNTKillRequestSigningID *signingIDRequest = (SNTKillRequestSigningID *)request;
      if ([signingIDRequest.teamID isEqualToString:kPlatformTeamID]) {
        matchers.push_back(MakeStatusFlagsMatcher(CS_PLATFORM_BINARY));
      } else {
        matchers.push_back(MakeTeamIDMatcher(signingIDRequest.teamID));
      }
      matchers.push_back(MakeSigningIDMatcher(signingIDRequest.signingID));
    } else if ([request isKindOfClass:[SNTKillRequestTeamID class]]) {
      // Don't allow `platform` here as killing all platform binaries is a bad
      // idea and isn't supported.
      SNTKillRequestTeamID *teamIDRequest = (SNTKillRequestTeamID *)request;
      if ([teamIDRequest.teamID isEqualToString:kPlatformTeamID]) {
        return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorInvalidRequest];
      }
      matchers.push_back(MakeTeamIDMatcher(((SNTKillRequestTeamID *)request).teamID));
    } else {
      LOGE(@"Unexpected request type: %@", [request class]);
      return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorInvalidRequest];
    }

    for (pid_t pid : *pids) {
      if (pid == 0) {
        continue;
      }

      SNTKilledProcess *killed = KillByMatchers(request, pid, matchers);
      if (killed) {
        [killedProcs addObject:killed];
      }
    }
  }

  return [[SNTKillResponse alloc] initWithKilledProcesses:killedProcs];
}

}  // namespace santa
