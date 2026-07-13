/// Copyright 2023 Google LLC
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

#include "Source/common/processtree/process_tree.h"

#include <mach/mach_time.h>
#include <sys/types.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <typeindex>
#include <utility>
#include <vector>

#include "Source/common/processtree/annotations/annotator.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.pb.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"

namespace santa::santad::process_tree {

namespace {
// Convert nanoseconds to mach_time ticks (inverse of mach_time's numer/denom).
uint64_t MachTicksFromNanos(uint64_t nanos) {
  static const mach_timebase_info_data_t timebase = [] {
    mach_timebase_info_data_t tb;
    mach_timebase_info(&tb);
    return tb;
  }();
  // Safe from overflow for the grace-scale magnitudes used here.
  return nanos * timebase.denom / timebase.numer;
}
}  // namespace

void ProcessTree::BackfillInsertChildren(
    absl::flat_hash_map<pid_t, std::vector<BackfilledProcess>>& parent_map,
    std::shared_ptr<Process> parent, const BackfilledProcess& backfilled_proc) {
  auto proc = std::make_shared<Process>(
      backfilled_proc.pid, backfilled_proc.cred,
      // Re-use shared pointers from parent if value equivalent
      (parent && *(backfilled_proc.program) == *(parent->program_))
          ? parent->program_
          : backfilled_proc.program,
      parent);
  {
    absl::MutexLock lock(mtx_);
    map_.emplace(backfilled_proc.pid, proc);
  }

  // The only case where we should not have a parent is the root processes
  // (e.g. init, kthreadd).
  if (parent) {
    for (auto& annotator : annotators_) {
      annotator->AnnotateFork(*this, *(proc->parent_), *proc);
      if (proc->program_ != proc->parent_->program_) {
        annotator->AnnotateExec(*this, *(proc->parent_), *proc);
      }
    }
  }

  for (const BackfilledProcess& child : parent_map[backfilled_proc.pid.pid]) {
    BackfillInsertChildren(parent_map, proc, child);
  }
}

void ProcessTree::HandleFork(uint64_t timestamp, const Process& parent,
                             const Pid new_pid) {
  std::shared_ptr<Process> child;
  {
    // Dedup and the map insert are one critical section: if we released the
    // lock between them, another client could see this event as a duplicate
    // (skip it) and then read the tree before the child was inserted.
    absl::MutexLock lock(mtx_);
    if (!StepLocked({timestamp, EventKind::kFork, parent.pid_, new_pid})) {
      return;
    }
    // Test seam (no-op in production): the claim just succeeded and mtx_ is
    // still held; fire here, BEFORE the insert, so the concurrency test can
    // verify a reader blocks at this boundary — i.e. claim and insert are a
    // single lock hold. Placed in the handler (not StepLocked) on purpose: if
    // the insert were ever moved to a separate critical section, this point
    // would fall in the unlocked gap and the test would deterministically fail.
    if (on_event_claimed_for_test_) {
      on_event_claimed_for_test_();
    }
    // Look up the parent rather than using map_[]: operator[] would insert a
    // null entry (and orphan the child) if the parent were ever absent.
    auto parent_proc = GetLocked(parent.pid_);
    child = std::make_shared<Process>(new_pid, parent.effective_cred_,
                                      parent.program_,
                                      parent_proc ? *parent_proc : nullptr);
    map_.emplace(new_pid, child);
    // Reap AFTER applying, so a late event can never reap the actor it needs.
    DrainRemovals();
  }
  // Annotators run outside the lock (they re-enter the tree). Annotation
  // propagation is therefore NOT atomic with the structural insert above; that
  // is intentional and does not affect CEL ancestry (see StepLocked).
  for (const auto& annotator : annotators_) {
    annotator->AnnotateFork(*this, parent, *child);
  }
}

void ProcessTree::HandleExec(uint64_t timestamp, const Process& p,
                             const Pid new_pid, const Program prog,
                             const Cred c) {
  // TODO(nickmg): should struct pid be reworked and only pid_version be passed?
  assert(new_pid.pid == p.pid_.pid);

  // Expected double-apply: a tree-aware auth client (the Authorizer) subscribes
  // to both AUTH_EXEC and NOTIFY_EXEC, so an uncached exec reaches here twice.
  // The two ES messages carry different mach_time, so they form distinct
  // EventKeys and both pass dedup; the second is a first-wins no-op (the
  // map_.emplace below). This is intentional and benign — it costs one extra
  // emplace/remove_at_/drain on the auth path per uncached exec (accepted).

  // Construct the new process (copies program/args/signing) OUTSIDE the lock to
  // keep the shared tree lock short on the serial ES handler path. A duplicate
  // wastes this allocation, which is cheaper than lengthening the lock hold.
  auto new_proc = std::make_shared<Process>(
      new_pid, c, std::make_shared<const Program>(prog), p.parent_);
  {
    absl::MutexLock lock(mtx_);
    if (!StepLocked({timestamp, EventKind::kExec, p.pid_, new_pid})) {
      return;
    }
    remove_at_.push_back({timestamp, p.pid_});
    map_.emplace(new_proc->pid_, new_proc);
    DrainRemovals();
  }
  for (const auto& annotator : annotators_) {
    annotator->AnnotateExec(*this, p, *new_proc);
  }
}

void ProcessTree::HandleExit(uint64_t timestamp, const Process& p) {
  absl::MutexLock lock(mtx_);
  if (!StepLocked({timestamp, EventKind::kExit, p.pid_, Pid{}})) {
    return;
  }
  remove_at_.push_back({timestamp, p.pid_});
  DrainRemovals();
}

bool ProcessTree::StepLocked(const EventKey& key) {
  latest_ts_ = std::max(latest_ts_, key.mach_time);

  // Dedup on the event's identity: the same kernel event is delivered to every
  // tree-aware client, and each informs the tree, so apply it exactly once. A
  // genuinely-novel event that arrives out of mach_time order is NEVER dropped
  // (this is the fix for the "too-old" drop that lost reordered fork/exec
  // events under load); only an exact duplicate is skipped. The key carries the
  // event's identity, not just mach_time, so two distinct events sharing a
  // coarse mach_time stamp are not mistaken for one and dropped.
  if (seen_.contains(key)) {
    return false;
  }
  seen_.insert(key);
  seen_order_.push_back(key);
  if (seen_order_.size() > kSeenCap) {
    // seen_/seen_order_ are bounded ONLY here — DrainRemovals never touches
    // them. So the dedup window is exactly the last kSeenCap events: steady
    // state is kSeenCap and this evicts on every insert after warmup. A client
    // lagging more than kSeenCap events behind the newest event finds its
    // duplicates already evicted and re-applies them. That is self-healing in
    // the common case (map_.emplace is first-wins, and a laggard replays a
    // whole lifecycle so re-created nodes are re-reaped by its own replayed
    // exec/exit), with one accepted edge: if a fork duplicate has aged out
    // while its matching exec duplicate has not, the re-inserted pre-exec node
    // never gets a removal scheduled and leaks (pidversion-distinct, bounded;
    // NOT wrong ancestry). The proper fix is the deferred delivery watermark;
    // kSeenCap (16384) is sized so lag beyond it is rare under real load.
    seen_.erase(seen_order_.front());
    seen_order_.pop_front();
  }
  return true;
}

void ProcessTree::DrainRemovals() {
  // Reap deferred removals once `grace` mach_time ticks have elapsed past the
  // scheduling event (measured against the newest timestamp seen). The grace
  // must comfortably exceed worst-case cross-thread/-client delivery reordering
  // so a straggler cannot reference a process after it is reaped.
  static const uint64_t kDefaultGrace = MachTicksFromNanos(5 * NSEC_PER_SEC);
  const uint64_t grace =
      removal_grace_ticks_ ? removal_grace_ticks_ : kDefaultGrace;
  const uint64_t cutoff = latest_ts_ > grace ? latest_ts_ - grace : 0;

  for (auto it = remove_at_.begin(); it != remove_at_.end();) {
    if (it->first < cutoff) {
      if (auto target = GetLocked(it->second);
          target && (*target)->refcnt_.load(std::memory_order_relaxed) > 0) {
        (*target)->tombstoned_ = true;
      } else {
        map_.erase(it->second);
      }
      it = remove_at_.erase(it);
    } else {
      it++;
    }
  }
}

void ProcessTree::RetainProcess(const PidList& pids) {
  // Reader lock suffices: we only need the map to be stable for lookup.
  // relaxed is safe because the increment has no dependent memory operations —
  // we are only bumping a counter.
  absl::ReaderMutexLock lock(mtx_);
  for (const struct Pid& p : pids) {
    auto proc = GetLocked(p);
    if (proc) {
      (*proc)->refcnt_.fetch_add(1, std::memory_order_relaxed);
    }
  }
}

void ProcessTree::ReleaseProcess(const PidList& pids) {
  absl::MutexLock lock(mtx_);
  for (const struct Pid& p : pids) {
    auto proc = GetLocked(p);
    if (proc) {
      // relaxed is safe: the exclusive lock provides ordering for
      // tombstoned_ and map_.erase().
      if ((*proc)->refcnt_.fetch_sub(1, std::memory_order_relaxed) == 1 &&
          (*proc)->tombstoned_) {
        map_.erase(p);
      }
    }
  }
}

/*
---
Annotation get/set
---
*/

void ProcessTree::AnnotateProcess(const Process& p,
                                  std::shared_ptr<const Annotator> a) {
  absl::MutexLock lock(mtx_);
  const Annotator& x = *a;
  map_[p.pid_]->annotations_.emplace(std::type_index(typeid(x)), std::move(a));
}

std::optional<::santa::pb::v1::process_tree::Annotations>
ProcessTree::ExportAnnotations(const Pid p) {
  auto proc = Get(p);
  if (!proc || (*proc)->annotations_.empty()) {
    return std::nullopt;
  }
  ::santa::pb::v1::process_tree::Annotations a;
  for (const auto& [_, annotation] : (*proc)->annotations_) {
    if (auto x = annotation->Proto(); x) a.MergeFrom(*x);
  }
  return a;
}

/*
---
Tree inspection methods
---
*/

std::vector<std::shared_ptr<const Process>> ProcessTree::RootSlice(
    std::shared_ptr<const Process> p) const {
  std::vector<std::shared_ptr<const Process>> slice;
  while (p) {
    slice.push_back(p);
    p = p->parent_;
  }
  return slice;
}

void ProcessTree::Iterate(
    std::function<void(std::shared_ptr<const Process> p)> f) const {
  std::vector<std::shared_ptr<const Process>> procs;
  {
    absl::ReaderMutexLock lock(mtx_);
    procs.reserve(map_.size());
    for (auto& [_, proc] : map_) {
      procs.push_back(proc);
    }
  }

  for (auto& p : procs) {
    f(p);
  }
}

std::optional<std::shared_ptr<const Process>> ProcessTree::Get(
    const Pid target) const {
  absl::ReaderMutexLock lock(mtx_);
  return GetLocked(target);
}

std::optional<std::shared_ptr<Process>> ProcessTree::GetLocked(
    const Pid target) const {
  auto it = map_.find(target);
  if (it == map_.end()) {
    return std::nullopt;
  }
  return it->second;
}

std::shared_ptr<const Process> ProcessTree::GetParent(const Process& p) const {
  return p.parent_;
}

#if SANTA_PROCESS_TREE_DEBUG
void ProcessTree::DebugDump(std::ostream& stream) const {
  absl::ReaderMutexLock lock(mtx_);
  stream << map_.size() << " processes" << std::endl;
  DebugDumpLocked(stream, 0, 0);
}

void ProcessTree::DebugDumpLocked(std::ostream& stream, int depth,
                                  pid_t ppid) const
    ABSL_SHARED_LOCKS_REQUIRED(mtx_) {
  for (auto& [_, process] : map_) {
    if ((ppid == 0 && !process->parent_) ||
        (process->parent_ && process->parent_->pid_.pid == ppid)) {
      stream << std::string(2 * depth, ' ') << process->pid_.pid
             << process->program_->executable << std::endl;
      DebugDumpLocked(stream, depth + 1, process->pid_.pid);
    }
  }
}
#endif

absl::StatusOr<std::shared_ptr<ProcessTree>> CreateTree(
    std::vector<std::unique_ptr<Annotator>> annotations) {
  absl::flat_hash_set<std::type_index> seen;
  for (const auto& annotator : annotations) {
    if (seen.count(std::type_index(typeid(annotator)))) {
      return absl::InvalidArgumentError(
          "Multiple annotators of the same class");
    }
    seen.emplace(std::type_index(typeid(annotator)));
  }

  auto tree = std::make_shared<ProcessTree>(std::move(annotations));
  if (auto status = tree->Backfill(); !status.ok()) {
    return status;
  }
  return tree;
}

/*
----
Tokens
----
*/

ProcessToken::ProcessToken(std::shared_ptr<ProcessTree> tree, PidList pids)
    : state_(std::make_shared<State>(std::move(tree), std::move(pids))) {
  if (state_->tree) {
    state_->tree->RetainProcess(state_->pids);
  }
}

ProcessToken::State::~State() {
  if (tree) {
    tree->ReleaseProcess(pids);
  }
}

}  // namespace santa::santad::process_tree
