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

#include "Source/santad/ProcessControl.h"

#import <AvailabilityMacros.h>
#include <libproc.h>
#include <signal.h>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTLogging.h"

extern "C" int pid_suspend(pid_t pid) WEAK_IMPORT_ATTRIBUTE;
extern "C" int pid_resume(pid_t pid) WEAK_IMPORT_ATTRIBUTE;

namespace santa {

// The kernel delivers the signal only if the process still has the token's pid
// and pidversion.
static bool KillProcess(audit_token_t token) {
  int error = proc_signal_with_audittoken(&token, SIGKILL);
  if (error != 0) {
    LOGW(@"Unable to kill process %d (pidversion %d): %d", Pid(token), Pidversion(token), error);
  }
  return error == 0;
}

// Wrapper around the pid_suspend() / pid_resume() / proc_signal_with_audittoken() functions
// that can be easily mocked out in tests. Returns true if the process was suspended, resumed,
// or killed as asked.
ProcessControlBlock ProdSuspendResumeBlock() {
  return ^bool(audit_token_t token, ProcessControl control) {
    pid_t pid = Pid(token);
    switch (control) {
      case ProcessControl::Suspend:
        if (pid_suspend == nullptr) {
          LOGW(@"pid_suspend() is not available, killing the target process %d", pid);
          KillProcess(token);
          return false;
        }
        // pid_suspend() returns 0 on success. If it fails the target is not
        // actually suspended, so kill it and report failure to keep the hold
        // fail-closed rather than letting an unheld process keep running.
        if (pid_suspend(pid) != 0) {
          LOGW(@"pid_suspend() failed, killing the target process %d", pid);
          KillProcess(token);
          return false;
        }
        return true;
      case ProcessControl::Resume: {
        if (pid_resume == nullptr) {
          LOGW(@"pid_resume() is not available, killing the target process %d", pid);
          KillProcess(token);
          return false;
        }
        // pid_resume() takes only a pid, so confirm it still names the process
        // that was suspended.
        audit_token_t live;
        if (!AuditTokenForPid(pid, &live) ||
            !(ProcessID::FromToken(live) == ProcessID::FromToken(token))) {
          LOGW(@"Not resuming process %d (pidversion %d): it no longer exists", pid,
               Pidversion(token));
          return false;
        }
        return pid_resume(pid) == 0;
      }
      case ProcessControl::Kill: return KillProcess(token);
    }
    return false;
  };
};

}  // namespace santa
