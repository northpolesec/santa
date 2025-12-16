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
#include <arpa/inet.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/cdefs.h>
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
#include "absl/cleanup/cleanup.h"

__BEGIN_DECLS

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

__END_DECLS

namespace santa {

// csops operations defined in XNU: bsd/sys/codesign.h
static constexpr unsigned int kCsopStatus = 0;
static constexpr unsigned int kCsopCDHash = 5;
static constexpr unsigned int kCsopIdentity = 11;
static constexpr unsigned int kCsopTeamID = 14;

namespace {

// Some csops operations return data wrapped in this small structure.
struct csops_blob {
  uint32_t type;
  uint32_t len;
  char data[];
};

// Base class for process matchers
class ProcessMatcher {
 public:
  virtual ~ProcessMatcher() = default;
  virtual bool Matches(pid_t pid) const = 0;
};

// BufferMatcher compares buffer data populated by csops
class BufferMatcher : public ProcessMatcher {
 public:
  static std::unique_ptr<ProcessMatcher> CDHash(NSString *cdhash) {
    auto desired = HexStringToBuf(cdhash);
    return std::make_unique<BufferMatcher>(kCsopCDHash, std::move(desired), false);
  }

  static std::unique_ptr<ProcessMatcher> TeamID(NSString *teamID) {
    std::string_view view = NSStringToUTF8StringView(teamID);
    std::vector<uint8_t> desired(view.begin(), view.end());
    return std::make_unique<BufferMatcher>(kCsopTeamID, std::move(desired), true);
  }

  static std::unique_ptr<ProcessMatcher> SigningID(NSString *signingID) {
    std::string_view view = NSStringToUTF8StringView(signingID);
    std::vector<uint8_t> desired(view.begin(), view.end());
    return std::make_unique<BufferMatcher>(kCsopIdentity, std::move(desired), true);
  }

  BufferMatcher(unsigned int operation, std::vector<uint8_t> desiredValue, bool has_blob_wrapper)
      : op_(operation), desired_(std::move(desiredValue)), has_blob_wrapper_(has_blob_wrapper) {}

  bool Matches(pid_t pid) const override {
    std::vector<uint8_t> buffer(has_blob_wrapper_ ? (desired_.size() + wrapper_length_overhead_)
                                                  : desired_.size());
    int err = csops(pid, op_, buffer.data(), buffer.size());
    if (err != 0) {
      return false;
    }

    if (has_blob_wrapper_) {
      csops_blob *blob = (struct csops_blob *)buffer.data();
      if (ntohl(blob->len) - wrapper_length_overhead_ == desired_.size()) {
        return std::memcmp(blob->data, desired_.data(), desired_.size()) == 0;
      } else {
        return false;
      }
    } else {
      return std::memcmp(buffer.data(), desired_.data(), desired_.size()) == 0;
    }
  }

 private:
  unsigned int op_;
  std::vector<uint8_t> desired_;
  bool has_blob_wrapper_;
  static constexpr uint32_t wrapper_length_overhead_ = sizeof(struct csops_blob) + 1;
};

// FlagsMatcher compares status flags against a defined mask
class FlagsMatcher : public ProcessMatcher {
 public:
  static std::unique_ptr<ProcessMatcher> StatusFlags(uint32_t mask) {
    return std::make_unique<FlagsMatcher>(kCsopStatus, mask);
  }

  FlagsMatcher(unsigned int operation, uint32_t mask) : op_(operation), mask_(mask) {}

  bool Matches(pid_t pid) const override {
    uint32_t status_flags = 0;
    int err = csops(pid, op_, &status_flags, sizeof(status_flags));
    if (err == 0) {
      return (status_flags & mask_) != 0;
    } else {
      return false;
    }
  }

 private:
  unsigned int op_;
  uint32_t mask_;
};

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
      matchers.push_back(BufferMatcher::CDHash(((SNTKillRequestCDHash *)request).cdhash));
    } else if ([request isKindOfClass:[SNTKillRequestSigningID class]]) {
      SNTKillRequestSigningID *signingIDRequest = (SNTKillRequestSigningID *)request;
      if ([signingIDRequest.teamID isEqualToString:kPlatformTeamID]) {
        matchers.push_back(FlagsMatcher::StatusFlags(CS_PLATFORM_BINARY));
      } else {
        matchers.push_back(BufferMatcher::TeamID(signingIDRequest.teamID));
      }
      matchers.push_back(BufferMatcher::SigningID(signingIDRequest.signingID));
    } else if ([request isKindOfClass:[SNTKillRequestTeamID class]]) {
      // Don't allow `platform` here as killing all platform binaries is a bad
      // idea and isn't supported.
      SNTKillRequestTeamID *teamIDRequest = (SNTKillRequestTeamID *)request;
      if ([teamIDRequest.teamID isEqualToString:kPlatformTeamID]) {
        return [[SNTKillResponse alloc] initWithError:SNTKillResponseErrorInvalidRequest];
      }
      matchers.push_back(BufferMatcher::TeamID(((SNTKillRequestTeamID *)request).teamID));
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
