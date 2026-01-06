/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "src/santad/ProcessControl.h"

#import <AvailabilityMacros.h>
#include <signal.h>

#import "src/common/SNTLogging.h"

extern "C" int pid_suspend(pid_t pid) WEAK_IMPORT_ATTRIBUTE;
extern "C" int pid_resume(pid_t pid) WEAK_IMPORT_ATTRIBUTE;

namespace santa {

// Wrapper around the pid_suspend() / pid_resume() / kill() functions that uses signal numbers
// to determine which to use and which can be easily mocked out in tests;
// Returns true if pid_suspend/pid_resume was used for Suspend/Resume and false if they weren't
// available.
ProcessControlBlock ProdSuspendResumeBlock() {
  return ^bool(pid_t pid, ProcessControl control) {
    switch (control) {
      case ProcessControl::Suspend:
        if (pid_suspend == nullptr) {
          LOGW(@"pid_suspend() is not available, killing the target process %d", pid);
          kill(pid, SIGKILL);
          return false;
        }
        pid_suspend(pid);
        return true;
      case ProcessControl::Resume:
        if (pid_resume == nullptr) {
          LOGW(@"pid_resume() is not available, killing the target process %d", pid);
          kill(pid, SIGKILL);
          return false;
        }
        pid_resume(pid);
        return true;
      case ProcessControl::Kill: kill(pid, SIGKILL); break;
    }
    return true;
  };
};

}  // namespace santa
