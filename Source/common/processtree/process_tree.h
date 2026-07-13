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

#ifndef SANTA_COMMON_PROCESSTREE_PROCESSTREE_H
#define SANTA_COMMON_PROCESSTREE_PROCESSTREE_H

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <typeinfo>
#include <vector>

#include "Source/common/processtree/process.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/inlined_vector.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"

namespace santa::santad::process_tree {

absl::StatusOr<BackfilledProcess> LoadPID(pid_t pid);

// Events reference 1-2 pids (the process + optional child/target for
// fork/exec). InlinedVector avoids a heap allocation for these.
using PidList = absl::InlinedVector<struct Pid, 2>;

// Fwd decl for test peer.
class ProcessTreeTestPeer;

class ProcessTree {
 public:
  explicit ProcessTree(std::vector<std::unique_ptr<Annotator>>&& annotators,
                       uint64_t removal_grace_ticks = 0)
      : annotators_(std::move(annotators)),
        removal_grace_ticks_(removal_grace_ticks) {}
  ProcessTree(const ProcessTree&) = delete;
  ProcessTree& operator=(const ProcessTree&) = delete;
  ProcessTree(ProcessTree&&) = delete;
  ProcessTree& operator=(ProcessTree&&) = delete;

  // Initialize the tree with the processes currently running on the system.
  absl::Status Backfill();

  // Inform the tree of a fork event, in which the parent process spawns a child
  // with the only difference between the two being the pid.
  void HandleFork(uint64_t timestamp, const Process& parent,
                  struct Pid new_pid);

  // Inform the tree of an exec event, in which the program and potentially cred
  // of a Process change.
  // p is the process performing the exec (running the "old" program),
  // and new_pid, prog, and cred are the new pid, program, and credentials
  // after the exec.
  // N.B. new_pid is required as the "pid version" will have changed.
  // It is a programming error to pass a new_pid such that
  // p.pid_.pid != new_pid.pid.
  void HandleExec(uint64_t timestamp, const Process& p, struct Pid new_pid,
                  struct Program prog, struct Cred c);

  // Inform the tree of a process exit.
  void HandleExit(uint64_t timestamp, const Process& p);

  // Mark the given pids as needing to be retained in the tree's map for future
  // access. Normally, Processes are removed once all clients process past the
  // event which would remove the Process (e.g. exit), however in cases where
  // async processing occurs, the Process may need to be accessed after the
  // exit.
  void RetainProcess(const PidList& pids);

  // Release previously retained processes, signaling that the client is done
  // processing the event that retained them.
  void ReleaseProcess(const PidList& pids);

  // Annotate the given process with an Annotator (state).
  void AnnotateProcess(const Process& p, std::shared_ptr<const Annotator> a);

  // Get the given annotation on the given process if it exists, or nullopt if
  // the annotation is not set.
  template <typename T>
  std::optional<std::shared_ptr<const T>> GetAnnotation(const Process& p) const;

  // Get the fully merged proto form of all annotations on the given process.
  std::optional<::santa::pb::v1::process_tree::Annotations> ExportAnnotations(
      struct Pid p);

  // Atomically get the slice of Processes going from the given process "up"
  // to the root. The root process has no parent. N.B. There may be more than
  // one root process. E.g. on Linux, both init (PID 1) and kthread (PID 2)
  // are considered roots, as they are reported to have PPID=0.
  std::vector<std::shared_ptr<const Process>> RootSlice(
      std::shared_ptr<const Process> p) const;

  // Call f for all processes in the tree. The list of processes is captured
  // before invoking f, so it is safe to mutate the tree in f.
  void Iterate(std::function<void(std::shared_ptr<const Process>)> f) const;

  // Get the Process for the given pid in the tree if it exists.
  std::optional<std::shared_ptr<const Process>> Get(struct Pid target) const;

  // Traverse the tree from the given Process to its parent.
  std::shared_ptr<const Process> GetParent(const Process& p) const;

#if SANTA_PROCESS_TREE_DEBUG
  // Dump the tree in a human readable form to the given ostream.
  void DebugDump(std::ostream& stream) const;
#endif

 private:
  friend class ProcessTreeTestPeer;
  void BackfillInsertChildren(
      absl::flat_hash_map<pid_t, std::vector<BackfilledProcess>>& parent_map,
      std::shared_ptr<Process> parent,
      const BackfilledProcess& backfilled_proc);

  // Record that the event identified by `key` is being processed and report
  // whether it is "novel" (caller should apply it). A novel event is applied
  // even if it arrives out of mach_time order (ES does not guarantee global
  // ordering); only an exact duplicate (the same event redelivered to another
  // client) is skipped. The key includes the event's identity (not just
  // mach_time) so two distinct events sharing a coarse mach_time stamp are not
  // mistaken for one.
  //
  // MUST be called with mtx_ held, and the caller MUST perform the resulting
  // map_/remove_at_ mutation before releasing mtx_. Dedup and mutation are one
  // atomic step on purpose: the same kernel event is delivered to multiple
  // clients, and once one client records it as seen, another client will skip
  // it as a duplicate — so the tree mutation must already be visible when that
  // skip happens, or the second client (and its subsequent causal reads) would
  // observe a missing node. "Applied" here means the tree *structure* (the
  // map_ entry and parent_ chain that CEL ancestry walks); annotation
  // propagation runs outside the lock and is NOT part of this atomicity
  // guarantee (see HandleFork/HandleExec).
  bool StepLocked(const struct EventKey& key)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Reap deferred removals whose grace has elapsed. Caller must hold mtx_.
  void DrainRemovals() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  std::optional<std::shared_ptr<Process>> GetLocked(struct Pid target) const
      ABSL_SHARED_LOCKS_REQUIRED(mtx_);

  void DebugDumpLocked(std::ostream& stream, int depth, pid_t ppid) const;

  std::vector<std::unique_ptr<Annotator>> annotators_;

  mutable absl::Mutex mtx_;
  absl::flat_hash_map<const struct Pid, std::shared_ptr<Process>> map_
      ABSL_GUARDED_BY(mtx_);
  // List of pids which should be removed from map_, and the timestamp (the
  // originating exit/exec event's mach_time) at which the removal was
  // scheduled. An entry is reaped once removal_grace_ticks_ have elapsed past
  // its timestamp (measured against latest_ts_), so a reordered straggler
  // cannot reference a process after it is reaped. See DrainRemovals().
  std::vector<std::pair<uint64_t, struct Pid>> remove_at_ ABSL_GUARDED_BY(mtx_);

  // Dedup of processed events. The same kernel event is delivered to every
  // tree-aware client; each informs the tree, so an event must be applied
  // exactly once. seen_ answers "already applied?" in O(1); seen_order_ ages
  // entries out in insertion order once seen_ exceeds kSeenCap. Unlike the
  // previous fixed rolling window, an out-of-order novel event is NEVER
  // dropped. Keyed on the full EventKey so distinct events sharing a coarse
  // mach_time stamp do not collide (see EventKey).
  static constexpr size_t kSeenCap = 16384;
  absl::flat_hash_set<struct EventKey> seen_ ABSL_GUARDED_BY(mtx_);
  std::deque<struct EventKey> seen_order_ ABSL_GUARDED_BY(mtx_);
  // Newest event timestamp seen (monotone); drives the removal grace cutoff.
  uint64_t latest_ts_ ABSL_GUARDED_BY(mtx_) = 0;
  // Mach-time ticks an exited process is retained after its removal is
  // scheduled. 0 => production default (~5 s), computed lazily in
  // DrainRemovals. Injectable so tests can exercise reaping with small
  // synthetic timestamps.
  uint64_t removal_grace_ticks_;

  // Test-only seam (empty in production): invoked by HandleFork at the
  // claim->apply boundary — after StepLocked reports the event novel and while
  // mtx_ is still held, just before the map insert. Lets the concurrency
  // regression test interpose there. Set via ProcessTreeTestPeer (a friend).
  // The per-event null check is negligible.
  std::function<void()> on_event_claimed_for_test_;
};

template <typename T>
std::optional<std::shared_ptr<const T>> ProcessTree::GetAnnotation(
    const Process& p) const {
  auto it = p.annotations_.find(std::type_index(typeid(T)));
  if (it == p.annotations_.end()) {
    return std::nullopt;
  }
  return std::dynamic_pointer_cast<const T>(it->second);
}

// Create a new tree, ensuring the provided annotations are valid and that
// backfill is successful.
absl::StatusOr<std::shared_ptr<ProcessTree>> CreateTree(
    std::vector<std::unique_ptr<Annotator>> annotations);

// ProcessTokens provide a lifetime based approach to retaining processes
// in a ProcessTree. When a token is created with a list of pids that may need
// to be referenced during processing of a given event, the ProcessToken informs
// the tree to retain those pids in its map so any call to ProcessTree::Get()
// during event processing succeeds. When the token is destroyed, it signals the
// tree to release the pids, which removes them from the tree if they would have
// fallen out otherwise due to a destruction event (e.g. exit).
class ProcessToken {
 public:
  explicit ProcessToken(std::shared_ptr<ProcessTree> tree, PidList pids);

  // Default copy/move/destructor — shared_ptr<State> handles lifetime.
  ProcessToken(const ProcessToken&) = default;
  ProcessToken(ProcessToken&&) noexcept = default;
  ProcessToken& operator=(const ProcessToken&) = default;
  ProcessToken& operator=(ProcessToken&&) noexcept = default;
  ~ProcessToken() = default;

 private:
  struct State {
    std::shared_ptr<ProcessTree> tree;
    PidList pids;
    State(std::shared_ptr<ProcessTree> tree, PidList pids)
        : tree(std::move(tree)), pids(std::move(pids)) {}
    ~State();
  };
  std::shared_ptr<State> state_;
};

}  // namespace santa::santad::process_tree

#endif  // SANTA_COMMON_PROCESSTREE_PROCESSTREE_H
