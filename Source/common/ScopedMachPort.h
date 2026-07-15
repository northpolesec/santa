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

#ifndef SANTA_COMMON_SCOPEDMACHPORT_H
#define SANTA_COMMON_SCOPEDMACHPORT_H

#include <mach/mach.h>

#include "Source/common/ScopedTypeRef.h"

namespace santa {

namespace scoped_mach_port_internal {

// mach_port_deallocate and mach_port_mod_refs take the owning task as their
// first argument, so they can't be passed to ScopedTypeRef directly. These
// adapt them to the single-argument retain/release signature it expects.
inline kern_return_t RetainSendRight(mach_port_t port) {
  return mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_SEND, 1);
}

inline kern_return_t ReleasePort(mach_port_t port) {
  return mach_port_deallocate(mach_task_self(), port);
}

}  // namespace scoped_mach_port_internal

// Scoped wrapper for a Mach port right held in the current task's IPC space,
// e.g. a task port returned by task_name_for_pid. The reference is released
// with mach_port_deallocate when the wrapper goes out of scope.
using ScopedMachPort = ScopedTypeRef<mach_port_t, MACH_PORT_NULL,
                                     scoped_mach_port_internal::RetainSendRight,
                                     scoped_mach_port_internal::ReleasePort>;

}  // namespace santa

#endif  // SANTA_COMMON_SCOPEDMACHPORT_H
