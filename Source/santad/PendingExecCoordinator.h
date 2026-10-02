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

#ifndef SANTA_SANTAD_PENDINGEXECCOORDINATOR_H
#define SANTA_SANTAD_PENDINGEXECCOORDINATOR_H

#include <dispatch/dispatch.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#import "Source/common/SantaVnode.h"

namespace santa {

// Coordinates the race between a compiler writing an executable (which creates
// a transitive rule asynchronously on NOTIFY_CLOSE) and that executable being
// immediately exec'd (a blocking AUTH_EXEC). The authorizer registers a waiter
// keyed by the target file's vnode; the compiler controller signals when it
// commits a transitive rule for that vnode. Each waiter is resolved exactly
// once: true if a rule arrived in time, false on timeout.
class PendingExecCoordinator {
 public:
  using ResolveBlock = void (^)(bool rule_created);

  // Default window during which a recent compiler mark/clear keeps
  // CompilerActiveRecently() true. Overridable via the constructor for tests;
  // production always uses this value.
  static constexpr uint64_t kDefaultCompilerActivityWindowMs = 10000;

  explicit PendingExecCoordinator(
      uint64_t compiler_activity_window_ms = kDefaultCompilerActivityWindowMs);
  ~PendingExecCoordinator();

  PendingExecCoordinator(const PendingExecCoordinator&) = delete;
  PendingExecCoordinator& operator=(const PendingExecCoordinator&) = delete;

  // Registers a waiter for `vnode`. `resolve` is invoked exactly once on a
  // private queue. If a rule for `vnode` was created within the recent window
  // just before this call, resolves immediately with true.
  void Wait(SantaVnode vnode, uint64_t timeout_ms, ResolveBlock resolve);

  // Signals that a transitive rule was committed for `vnode`. Resolves pending
  // waiters with true and records the vnode as recently-resolved so a
  // slightly-late Wait() still resolves true.
  void NotifyRuleCreated(SantaVnode vnode);

  // Refreshes the compiler-activity timestamp. Called on every compiler
  // mark/clear transition. Timestamp-only so a dropped EXIT cannot wedge the
  // activity gate permanently (invariant I5).
  void RecordCompilerActivity();

  // True if a compiler is currently marked, or was marked/cleared within the
  // activity window.
  bool CompilerActiveRecently();

 private:
  struct Key {
    dev_t dev;
    ino_t ino;
    bool operator<(const Key& o) const { return dev < o.dev || (dev == o.dev && ino < o.ino); }
  };
  struct Waiter {
    ResolveBlock resolve;
    std::shared_ptr<std::atomic<bool>> resolved;
  };

  static Key KeyFor(SantaVnode v) { return Key{v.fsid, v.fileid}; }
  uint64_t NowMs();

  dispatch_queue_t q_;
  std::mutex mu_;
  std::map<Key, std::vector<Waiter>> waiters_;   // guarded by mu_
  std::map<Key, uint64_t> recently_created_ms_;  // guarded by mu_
  uint64_t compiler_activity_window_ms_;
  std::atomic<uint64_t> last_compiler_activity_ms_;
};

}  // namespace santa

#endif
