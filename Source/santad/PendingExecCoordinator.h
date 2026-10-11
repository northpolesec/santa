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
#include <string>
#include <vector>

namespace santa {

// Coordinates the race between a compiler writing an executable (which creates
// a transitive rule asynchronously on NOTIFY_CLOSE, NOTIFY_RENAME, or
// NOTIFY_CLONE) and that executable being immediately exec'd (a blocking
// AUTH_EXEC). The authorizer registers a waiter keyed by the SHA-256 of the
// content it evaluated; the compiler controller signals when it commits a
// transitive rule for a SHA-256. A waiter therefore resolves true only when a
// rule now allows exactly the content that was evaluated. Each waiter is
// resolved exactly once: true if a rule arrived in time, false on timeout.
//
// Must be owned by a std::shared_ptr: a pending timeout keeps the coordinator
// alive until it fires.
class PendingExecCoordinator : public std::enable_shared_from_this<PendingExecCoordinator> {
 public:
  using ResolveBlock = void (^)(bool rule_created);

  // Default window during which a recent compiler mark or clear keeps
  // CompilerActiveRecently() true. Overridable via the constructor for tests;
  // production always uses this value.
  static constexpr uint64_t kDefaultCompilerActivityWindowMs = 10000;

  explicit PendingExecCoordinator(
      uint64_t compiler_activity_window_ms = kDefaultCompilerActivityWindowMs);
  ~PendingExecCoordinator();

  PendingExecCoordinator(const PendingExecCoordinator&) = delete;
  PendingExecCoordinator& operator=(const PendingExecCoordinator&) = delete;

  // Registers a waiter for `sha256`. `resolve` is invoked exactly once on a
  // private queue. If a rule for `sha256` was created within the recent window
  // just before this call, resolves true without waiting.
  void Wait(const std::string& sha256, uint64_t timeout_ms, ResolveBlock resolve);

  // Signals that a transitive rule was committed for `sha256`. Resolves pending
  // waiters whose timeout has not passed with true, and records the hash as
  // recently created so a slightly-late Wait() still resolves true. A waiter
  // whose timeout has passed is left to its timeout, which resolves it false
  // even when the queue it runs on is behind.
  void NotifyRuleCreated(const std::string& sha256);

  // Records a change of `delta` in the number of processes marked as compilers
  // (+1 marked, -1 cleared, 0 a mark replaced), which is compiler activity.
  void UpdateCompilerMarks(int64_t delta);

  // True while any process is marked as a compiler, or if one was marked or
  // cleared within the activity window. A mark is cleared when its process
  // exits, so the clear of a compiler that ran a long time is processed only
  // after its NOTIFY_CLOSEs; the count covers that gap.
  bool CompilerActiveRecently();

 private:
  struct Waiter {
    ResolveBlock resolve;
    std::shared_ptr<std::atomic<bool>> resolved;
    uint64_t deadline_uptime_ms;
  };

  uint64_t NowMs();
  // Excludes time asleep, like the dispatch_time() clock the timeout runs on.
  static uint64_t UptimeMs();

  dispatch_queue_t q_;
  std::mutex mu_;
  std::map<std::string, std::vector<Waiter>> waiters_;   // guarded by mu_
  std::map<std::string, uint64_t> recently_created_ms_;  // guarded by mu_
  uint64_t compiler_activity_window_ms_;
  std::atomic<uint64_t> last_compiler_activity_ms_;
  std::atomic<int64_t> marked_compilers_;
};

}  // namespace santa

#endif
