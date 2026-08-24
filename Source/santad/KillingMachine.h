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

// Default for KillEnv::signal_group. Defined in KillingMachine.mm.
int SignalProcessGroup(pid_t pgid, int sig);

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
  std::function<int(audit_token_t*, int)> signal_token =
      proc_signal_with_audittoken;

  // Signal every process in a group. Returns 0 or errno.
  std::function<int(pid_t, int)> signal_group = SignalProcessGroup;
};

SNTKillResponse* KillingMachine(SNTKillRequest* request);
SNTKillResponse* KillingMachine(SNTKillRequest* request, const KillEnv& env);

}  // namespace santa

#endif  // SANTA_SANTAD_KILLINGMACHINE_H
