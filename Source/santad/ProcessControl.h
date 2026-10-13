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

#ifndef SANTA_SANTAD_PROCESSCONTROL_H
#define SANTA_SANTAD_PROCESSCONTROL_H

#include <bsm/libbsm.h>

namespace santa {

enum class ProcessControl { Suspend, Resume, Kill };

// Acts on the process identified by `token`. Resume and Kill act only on the
// process with the token's pid and pidversion, so a process that reused the pid
// is never signaled.
using ProcessControlBlock = bool (^)(audit_token_t token, ProcessControl);

ProcessControlBlock ProdSuspendResumeBlock();

}  // namespace santa

#endif  // SANTA_SANTAD_PROCESSCONTROL_H
