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
// `signal` field is not used by this path. When nothing was actually sent a
// signal, there is nothing to escalate, so the grace period is skipped and the
// calling thread is not held at all.
//
// A convenience wrapper over the multi-request form below, which is what santad
// itself calls; the answer for one request is identical either way.
SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace);
SNTKillResponse* KillingMachineTermThenKill(SNTKillRequest* request, NSTimeInterval grace,
                                            const KillEnv& env);

// The same for several requests at once: every request's SIGTERM goes out, the
// calling thread blocks once for `grace`, and then the SIGKILL re-matches run.
// Requests that come due together therefore cost one grace period rather than
// one each. One response per request, in the order they were given. A request
// whose SIGTERM pass matched nothing is not re-matched, and when nothing at all
// was actually sent a signal, there is nothing to escalate, so the grace period
// is skipped and the calling thread is not held at all.
//
// A process group is signaled once per pass, however many of the requests reach
// it: the group signal is not repeated for the second request, whose response is
// then empty of that delivery. Being covered by another request's signal is not
// the same as having matched nothing, though, so such a request is still
// re-matched and escalated at SIGKILL. It has to be: the request that signaled
// the group may have stopped matching by then, which is what happens whenever
// its own process honors SIGTERM, and the survivor in the group would otherwise
// escape the escalation entirely. Only a group signal that actually landed
// suppresses another attempt at it.
NSArray<SNTKillResponse*>* KillingMachineTermThenKill(NSArray<SNTKillRequest*>* requests,
                                                      NSTimeInterval grace);
NSArray<SNTKillResponse*>* KillingMachineTermThenKill(NSArray<SNTKillRequest*>* requests,
                                                      NSTimeInterval grace, const KillEnv& env);

// The pid of one process the request matches, or nullopt when nothing does.
// Signals nothing: this is the match pass on its own, so a caller can find out
// whether a kill would hit anything before the kill is due. Which of several
// matches comes back is unspecified, and the answer is a snapshot: the process
// may be gone by the time the caller looks at it. Running-process requests are
// not supported here, as they already name the process the caller wants.
std::optional<pid_t> KillingMachineAnyMatch(SNTKillRequest* request);
std::optional<pid_t> KillingMachineAnyMatch(SNTKillRequest* request, const KillEnv& env);

}  // namespace santa

#endif  // SANTA_SANTAD_KILLINGMACHINE_H
