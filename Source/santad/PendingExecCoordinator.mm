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

#import "Source/santad/PendingExecCoordinator.h"

#include <time.h>

namespace santa {

// Recently-created entries are pruned once older than this, bounding the map.
static constexpr uint64_t kRecentlyCreatedTTLMs = 30000;

PendingExecCoordinator::PendingExecCoordinator(uint64_t compiler_activity_window_ms)
    : compiler_activity_window_ms_(compiler_activity_window_ms),
      last_compiler_activity_ms_(0),
      marked_compilers_(0) {
  q_ = dispatch_queue_create("com.northpolesec.santa.daemon.pending_exec", DISPATCH_QUEUE_SERIAL);
}

PendingExecCoordinator::~PendingExecCoordinator() {}

uint64_t PendingExecCoordinator::NowMs() {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) / 1000000ULL;
}

uint64_t PendingExecCoordinator::UptimeMs() {
  return clock_gettime_nsec_np(CLOCK_UPTIME_RAW) / 1000000ULL;
}

void PendingExecCoordinator::Wait(const std::string& sha256, uint64_t timeout_ms,
                                  ResolveBlock resolve) {
  // A copy, not the reference: the timeout block below captures it.
  std::string key = sha256;
  auto resolved = std::make_shared<std::atomic<bool>>(false);
  bool ruleAlreadyCreated = false;
  uint64_t now = NowMs();
  uint64_t deadline = UptimeMs() + timeout_ms;

  {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = recently_created_ms_.find(key);
    // `now` is sampled before the lock, so a concurrent NotifyRuleCreated may
    // record a timestamp at or after `now`. Treat an at-or-after stamp as a
    // just-created rule (it was signaled with no waiter yet registered). The
    // aged arm is only evaluated when it->second < now, so no unsigned underflow.
    if (it != recently_created_ms_.end() &&
        (it->second >= now || now - it->second <= kRecentlyCreatedTTLMs)) {
      ruleAlreadyCreated = true;
    } else {
      waiters_[key].push_back(Waiter{resolve, resolved, deadline});
    }
  }

  // Resolution is always asynchronous on q_, never inline, so a caller that
  // responds Hold to ES before calling Wait() has responded before any resolve
  // (which posts HoldAllowed or HoldDenied) runs.
  if (ruleAlreadyCreated) {
    dispatch_async(q_, ^{
      if (!resolved->exchange(true)) {
        resolve(true);
      }
    });
    return;
  }

  // Arm the timeout. The shared `resolved` makes whichever of timeout /
  // NotifyRuleCreated runs first win; the loser is a no-op. The timeout also
  // removes its own waiter so a never-notified waiter does not leak.
  std::shared_ptr<PendingExecCoordinator> self = shared_from_this();
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(timeout_ms * 1000000ULL)), q_, ^{
    ResolveBlock toCall = nil;
    {
      std::lock_guard<std::mutex> lock(self->mu_);
      auto it = self->waiters_.find(key);
      if (it != self->waiters_.end()) {
        auto& vec = it->second;
        for (auto i = vec.begin(); i != vec.end(); ++i) {
          if (i->resolved == resolved) {
            if (!resolved->exchange(true)) toCall = i->resolve;
            vec.erase(i);
            break;
          }
        }
        if (vec.empty()) self->waiters_.erase(it);
      }
    }
    if (toCall) {
      toCall(false);  // Invoked outside mu_
    }
  });
}

void PendingExecCoordinator::NotifyRuleCreated(const std::string& sha256) {
  std::vector<Waiter> woken;
  uint64_t now = NowMs();
  uint64_t uptime = UptimeMs();

  {
    std::lock_guard<std::mutex> lock(mu_);
    recently_created_ms_[sha256] = now;

    // A waiter past its deadline stays for its timeout, which may be queued
    // behind other resolutions, so a rule created too late never resumes it.
    auto it = waiters_.find(sha256);
    if (it != waiters_.end()) {
      auto& vec = it->second;
      for (auto w = vec.begin(); w != vec.end();) {
        if (uptime < w->deadline_uptime_ms) {
          woken.push_back(std::move(*w));
          w = vec.erase(w);
        } else {
          ++w;
        }
      }
      if (vec.empty()) waiters_.erase(it);
    }

    // Opportunistic prune of stale recently-created entries.
    for (auto pit = recently_created_ms_.begin(); pit != recently_created_ms_.end();) {
      if (now >= pit->second && now - pit->second > kRecentlyCreatedTTLMs) {
        pit = recently_created_ms_.erase(pit);
      } else {
        ++pit;
      }
    }
  }

  // Resolves run outside mu_, on q_, so a resolve block never executes while
  // the lock is held and all resolutions share one serial context. Capture the
  // block + atomic by value (not the Waiter struct) to avoid a dangling
  // reference after the loop.
  for (auto& w : woken) {
    ResolveBlock rb = w.resolve;
    std::shared_ptr<std::atomic<bool>> rv = w.resolved;
    dispatch_async(q_, ^{
      if (!rv->exchange(true)) {
        rb(true);
      }
    });
  }
}

void PendingExecCoordinator::UpdateCompilerMarks(int64_t delta) {
  marked_compilers_.fetch_add(delta, std::memory_order_relaxed);
  last_compiler_activity_ms_.store(NowMs(), std::memory_order_relaxed);
}

bool PendingExecCoordinator::CompilerActiveRecently() {
  if (marked_compilers_.load(std::memory_order_relaxed) > 0) return true;
  uint64_t last = last_compiler_activity_ms_.load(std::memory_order_relaxed);
  if (last == 0) return false;
  uint64_t now = NowMs();
  return now >= last && now - last <= compiler_activity_window_ms_;
}

}  // namespace santa
