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

#ifndef SANTA_SANTAD_KILLINGMACHINE_H
#define SANTA_SANTAD_KILLINGMACHINE_H

#import <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <unistd.h>

#include <functional>
#include <optional>
#include <vector>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#import "Source/common/SNTKillCommand.h"
#include "Source/common/SystemResources.h"

namespace santa {

// Defaults for the seams in KillEnv that aren't a bare syscall. Defined in
// KillingMachine.mm.
int SignalProcessGroup(pid_t pgid, int sig);
void BlockingWait(NSTimeInterval seconds);

// Everything a kill pass reaches for outside this file, injectable because
// signal delivery has no safe form to exercise against real processes. The
// defaults are the real thing; only tests substitute. Note that santad's own
// pid and process group are deliberately not seams here: a caller-supplied
// value would defeat the guards that keep santad from signaling itself.
struct KillEnv {
  // Snapshot of the pids to consider matching.
  std::function<std::optional<std::vector<pid_t>>()> list_pids = GetPidList;

  // Audit token for a pid, read before and after matching so a recycled pid
  // can't be mistaken for the process that matched.
  std::function<bool(pid_t, audit_token_t*)> token_for_pid = AuditTokenForPid;

  // Code signing lookups the matchers make.
  CSOpsFunc csops_func = csops;

  // Process group of a pid, negative when it can't be read.
  std::function<pid_t(pid_t)> pgid_for_pid = getpgid;

  // Signal one process, validated against its audit token. Returns 0 or errno.
  std::function<int(audit_token_t*, int)> signal_token = proc_signal_with_audittoken;

  // Signal every process in a group. Returns 0 or errno.
  std::function<int(pid_t, int)> signal_group = SignalProcessGroup;

  // Blocks the calling thread for the term-then-kill grace period.
  std::function<void(NSTimeInterval)> wait = BlockingWait;
};

SNTKillResponse* KillingMachine(SNTKillRequest* request);
SNTKillResponse* KillingMachine(SNTKillRequest* request, const KillEnv& env);

// Sends SIGTERM to everything the request matches, blocks the calling thread
// for `grace`, then re-matches and SIGKILLs whatever is still there. Blocking
// is the contract: callers run this on a queue they own. The request's own
// `signal` field is not used by this path. If nothing was signaled, the grace
// wait is skipped.
SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace);
SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace,
                                            const KillEnv& env);

// The same for several requests at once, sharing one grace period. One response
// per request, in the order given. A process group reached by more than one
// request is signaled once per pass; a request whose matches were covered by
// another request's group signal is still re-matched at SIGKILL, since the
// request that signaled the group may no longer match by then.
NSArray<SNTKillResponse*>* KillingMachineTermThenKill(NSArray<SNTKillRequest*>* requests,
                                                      NSTimeInterval grace, const KillEnv& env);

// The audit token of one process the request matches, or nullopt when nothing
// does. Signals nothing: this is the match pass on its own, so a caller can
// find out whether a kill would hit anything before the kill is due, and the
// token lets it re-check, after reading the process, that the pid was not
// recycled underneath it. Which of several matches comes back is unspecified.
// Running-process requests are not supported here, as they already name the
// process the caller wants.
std::optional<audit_token_t> KillingMachineAnyMatch(SNTKillRequest* request);
std::optional<audit_token_t> KillingMachineAnyMatch(SNTKillRequest* request, const KillEnv& env);

}  // namespace santa

#endif  // SANTA_SANTAD_KILLINGMACHINE_H
