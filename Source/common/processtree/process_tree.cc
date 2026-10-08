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
#include <string>
#include <string_view>
#include <typeindex>
#include <utility>
#include <vector>

#include "Source/common/processtree/annotations/annotator.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.pb.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/inlined_vector.h"
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
    if (parent) {
      // Nothing is annotated during backfill (the tree is brand new and no rule
      // has run yet), but keep the invariant in one place rather than three.
      PropagateAnnotationsLocked(*parent, *proc, /*across_exec=*/false);
    }
    if (map_.emplace(backfilled_proc.pid, proc).second) {
      IndexProcessLocked(*proc);
    }
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

void ProcessTree::HandleFork(uint64_t timestamp,
                             const std::shared_ptr<const Process>& parent,
                             const Pid new_pid) {
  // Allocate the child OUTSIDE the write lock (as HandleExec does): the caller
  // supplies the parent handle, so no lock-held lookup is needed to build it.
  auto child = std::make_shared<Process>(new_pid, parent->effective_cred_,
                                         parent->program_, parent);
  {
    // Dedup and the map insert are one critical section: if we released the
    // lock between them, another client could see this event as a duplicate
    // (skip it) and then read the tree before the child was inserted.
    absl::MutexLock lock(mtx_);
    if (!StepLocked({timestamp, EventKind::kFork, parent->pid_, new_pid})) {
      return;
    }
    // Test seam (no-op in production): the claim just succeeded and mtx_ is
    // still held; fire here, BEFORE the insert, so the concurrency test can
    // verify a reader blocks at this boundary — i.e. claim and insert are a
    // single lock hold.
    if (on_event_claimed_for_test_) {
      on_event_claimed_for_test_();
    }
    // Inside the same hold as the insert, deliberately: a client that skips
    // this event as a duplicate must never see the child without the
    // annotations it inherits. See Annotator::Propagate.
    PropagateAnnotationsLocked(*parent, *child, /*across_exec=*/false);
    // Index only the winner of the first-wins insert: a loser's names are
    // already contributed by the entry that won.
    if (map_.emplace(new_pid, child).second) {
      IndexProcessLocked(*child);
    }
    // Reap AFTER applying, so a late event can never reap the actor it needs.
    DrainRemovals();
  }
  // Registered annotators run outside the lock (they re-enter the tree), so
  // what they add is NOT atomic with the structural insert above. That is why
  // anything an authorization decision reads inherits via Propagate() instead.
  for (const auto& annotator : annotators_) {
    annotator->AnnotateFork(*this, *parent, *child);
  }
}

void ProcessTree::HandleExec(uint64_t timestamp, const Process& p,
                             const Pid new_pid, Program prog, const Cred c) {
  // TODO(nickmg): should struct pid be reworked and only pid_version be passed?
  assert(new_pid.pid == p.pid_.pid);

  // The same exec is delivered to every tree-aware client, and the Authorizer
  // sees it as both AUTH_EXEC and NOTIFY_EXEC, so HandleExec may run more than
  // once per exec. StepLocked is the authoritative dedup gate: an
  // exact-duplicate delivery is rejected, while distinct deliveries that share
  // a pid but carry a different mach_time both pass and the later one is a
  // first-wins map_.emplace no-op. Callers building the Program eagerly can
  // skip known duplicates up front via GetExecActor (see InformFromESEvent).

  // Allocate the new process OUTSIDE the write lock to keep the shared tree
  // lock short on the serial ES handler path; prog is moved in, not copied.
  auto new_proc = std::make_shared<Process>(
      new_pid, c, std::make_shared<const Program>(std::move(prog)), p.parent_);
  {
    absl::MutexLock lock(mtx_);
    if (!StepLocked({timestamp, EventKind::kExec, p.pid_, new_pid})) {
      return;
    }
    remove_at_.push({timestamp, p.pid_});
    // The pre-exec process is gone as of this event. Retire it from the index
    // now rather than when it is finally reaped, or the program it used to be
    // would keep answering annotation_exists() for the whole removal grace.
    if (auto old = GetLocked(p.pid_)) {
      UnindexProcessLocked(**old);
    }
    PropagateAnnotationsLocked(p, *new_proc, /*across_exec=*/true);
    if (map_.emplace(new_proc->pid_, new_proc).second) {
      IndexProcessLocked(*new_proc);
    }
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
  remove_at_.push({timestamp, p.pid_});
  // As in HandleExec: retire now, not at reap. The process is gone even though
  // it lingers in map_ for the removal grace.
  if (auto exiting = GetLocked(p.pid_)) {
    UnindexProcessLocked(**exiting);
  }
  DrainRemovals();
}

ProcessTree::ExecActor ProcessTree::GetExecActor(uint64_t timestamp,
                                                 const Pid actor,
                                                 const Pid target) const {
  absl::ReaderMutexLock lock(mtx_);
  if (seen_.contains({timestamp, EventKind::kExec, actor, target})) {
    return {std::nullopt, /*already_seen=*/true};
  }
  return {GetLocked(actor), /*already_seen=*/false};
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

  // remove_at_ is a min-heap on the scheduling timestamp, so the earliest
  // deadline is always on top. Reap only the entries that have expired and stop
  // at the first that has not — every deeper entry is newer. This is O(K log R)
  // in the number reaped, not O(R) in the number pending.
  while (!remove_at_.empty() && remove_at_.top().first < cutoff) {
    const struct Pid pid = remove_at_.top().second;
    remove_at_.pop();
    auto target = GetLocked(pid);
    if (!target) {
      continue;
    }
    if ((*target)->refcnt_.load(std::memory_order_relaxed) > 0) {
      (*target)->tombstoned_ = true;
    } else {
      // Belt and braces: whatever scheduled this removal already retired the
      // process. Unindexing here too makes "nothing outside map_ is in the
      // index" hold unconditionally, and the indexed_ flag makes it free.
      UnindexProcessLocked(**target);
      map_.erase(pid);
    }
  }
}

PidList ProcessTree::RetainProcess(const PidList& pids) {
  // Reader lock suffices: we only need the map to be stable for lookup.
  // relaxed is safe because the increment has no dependent memory operations —
  // we are only bumping a counter.
  PidList retained;
  absl::ReaderMutexLock lock(mtx_);
  for (const struct Pid& p : pids) {
    auto proc = GetLocked(p);
    if (proc) {
      (*proc)->refcnt_.fetch_add(1, std::memory_order_relaxed);
      retained.push_back(p);
    }
  }
  return retained;
}

void ProcessTree::ReleaseProcess(const PidList& pids) {
  // Fast path under the reader lock: the decrement is atomic, and tombstoned_
  // is stable here (written only in DrainRemovals under the exclusive lock).
  // Only the rare erase of a tombstoned process needs the exclusive lock.
  PidList to_erase;
  {
    absl::ReaderMutexLock lock(mtx_);
    for (const struct Pid& p : pids) {
      auto proc = GetLocked(p);
      if (proc &&
          (*proc)->refcnt_.fetch_sub(1, std::memory_order_relaxed) == 1 &&
          (*proc)->tombstoned_) {
        to_erase.push_back(p);
      }
    }
  }
  if (to_erase.empty()) {
    return;
  }
  if (on_release_collected_for_test_) {
    on_release_collected_for_test_();
  }

  absl::MutexLock lock(mtx_);
  for (const struct Pid& p : to_erase) {
    // Re-verify: between the two lock holds the process may have been
    // retained again, already erased by a concurrent releaser, or erased
    // and a fresh process re-inserted under the same pid.
    auto proc = GetLocked(p);
    if (proc && (*proc)->refcnt_.load(std::memory_order_relaxed) == 0 &&
        (*proc)->tombstoned_) {
      UnindexProcessLocked(**proc);
      map_.erase(p);
    }
  }
}

/*
---
Annotation get/set
---
*/

void ProcessTree::IndexProcessLocked(Process& p) {
  if (p.indexed_) {
    return;
  }
  p.indexed_ = true;
  for (const auto& [_, annotation] : p.annotations_) {
    IndexAnnotationLocked(*annotation);
  }
}

void ProcessTree::UnindexProcessLocked(Process& p) {
  if (!p.indexed_) {
    return;
  }
  p.indexed_ = false;
  for (const auto& [_, annotation] : p.annotations_) {
    UnindexAnnotationLocked(*annotation);
  }
}

void ProcessTree::IndexAnnotationLocked(const Annotator& a) {
  // ForEachIndexedName's callback is a type-erased absl::FunctionRef, so the
  // thread-safety analyzer cannot see that it only ever runs here,
  // synchronously, with mtx_ already held. Collect the names into a plain
  // local first -- untouched by the analysis -- so the actual
  // annotation_index_ mutation below happens directly in this function's
  // body, where the ABSL_EXCLUSIVE_LOCKS_REQUIRED on the declaration covers it.
  absl::InlinedVector<std::string_view, 4> names;
  a.ForEachIndexedName(
      [&names](std::string_view name) { names.push_back(name); });

  for (std::string_view name : names) {
    // The common case is a name already present (every descendant inheriting
    // it), so look up by view first and only allocate a key on a real insert.
    if (auto it = annotation_index_.find(name); it != annotation_index_.end()) {
      it->second++;
    } else {
      annotation_index_.emplace(std::string(name), 1);
    }
  }
}

void ProcessTree::UnindexAnnotationLocked(const Annotator& a) {
  // See IndexAnnotationLocked for why the names are collected before
  // annotation_index_ is touched.
  absl::InlinedVector<std::string_view, 4> names;
  a.ForEachIndexedName(
      [&names](std::string_view name) { names.push_back(name); });

  for (std::string_view name : names) {
    auto it = annotation_index_.find(name);
    if (it == annotation_index_.end()) {
      continue;
    }
    if (--it->second == 0) {
      annotation_index_.erase(it);
    }
  }
}

bool ProcessTree::AnnotationExists(std::string_view name) const {
  absl::ReaderMutexLock lock(mtx_);
  return annotation_index_.contains(name);
}

void ProcessTree::PropagateAnnotationsLocked(const Process& from, Process& to,
                                             bool across_exec) {
  if (from.annotations_.empty()) {
    return;
  }

  for (const auto& [key, annotation] : from.annotations_) {
    if (annotation->PropagatesWholly(across_exec)) {
      // Share the ancestor's object. The descendant inherits it unchanged, and
      // annotations are immutable, so copying it would allocate inside this
      // critical section to produce something equal. See
      // Annotator::PropagatesWholly.
      to.annotations_.insert_or_assign(key, annotation);
    } else if (auto next = annotation->Propagate(across_exec)) {
      to.annotations_.insert_or_assign(key, std::move(next));
    }
  }
}

void ProcessTree::AnnotateProcess(const Process& p,
                                  std::shared_ptr<const Annotator> a) {
  absl::MutexLock lock(mtx_);
  auto it = map_.find(p.pid_);
  if (it == map_.end()) {
    return;
  }
  const Annotator& x = *a;
  // emplace is first-wins; count the names only if this annotation is the one
  // that landed, and only while the process is itself counted.
  auto [entry, inserted] = it->second->annotations_.emplace(
      std::type_index(typeid(x)), std::move(a));
  if (inserted && it->second->indexed_) {
    IndexAnnotationLocked(*entry->second);
  }
}

std::optional<::santa::pb::v1::process_tree::Annotations>
ProcessTree::ExportAnnotations(const Pid p) {
  // Copy the handles out under the lock, then build the proto after releasing
  // it. Proto() is virtual, allocates, and runs once per process per logged
  // event; leaving it inside the critical section would block fork/exec ingest
  // on telemetry serialization.
  absl::InlinedVector<std::shared_ptr<const Annotator>, 2> annotations;
  {
    absl::ReaderMutexLock lock(mtx_);
    auto proc = GetLocked(p);
    // Already under the lock, so read the map directly rather than the flag.
    if (!proc || (*proc)->annotations_.empty()) {
      return std::nullopt;
    }
    annotations.reserve((*proc)->annotations_.size());
    for (const auto& [_, annotation] : (*proc)->annotations_) {
      annotations.push_back(annotation);
    }
  }

  ::santa::pb::v1::process_tree::Annotations a;
  for (const auto& annotation : annotations) {
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
    // Dereference: typeid on the unique_ptr itself is the same static type for
    // every element, so every pair of annotators would collide.
    const Annotator& x = *annotator;
    if (!seen.emplace(std::type_index(typeid(x))).second) {
      return absl::InvalidArgumentError(
          "Multiple annotators of the same class");
    }
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
    : state_(std::make_shared<State>(std::move(tree), PidList{})) {
  if (state_->tree) {
    // Remember what was retained, not what was asked for. A pid missing now can
    // be inserted by another client before this token dies, and releasing it
    // then would decrement a count this token never incremented -- enough to
    // erase a process a different, valid token is still holding.
    state_->pids = state_->tree->RetainProcess(pids);
  }
}

ProcessToken::State::~State() {
  if (tree) {
    tree->ReleaseProcess(pids);
  }
}

}  // namespace santa::santad::process_tree
