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

#include "Source/common/AuditUtilities.h"

#include <mach/mach.h>

namespace santa {

std::optional<audit_token_t> GetMyAuditToken() {
  audit_token_t tok;
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&tok, &count) != KERN_SUCCESS) {
    return std::nullopt;
  }
  return std::make_optional(tok);
}

bool AuditTokenForPid(pid_t pid, audit_token_t *token) {
  task_name_t task;
  mach_msg_type_number_t size = TASK_AUDIT_TOKEN_COUNT;

  if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) {
    return false;
  }

  kern_return_t result = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)token, &size);
  mach_port_deallocate(mach_task_self(), task);
  return result == KERN_SUCCESS;
}

}  // namespace santa
