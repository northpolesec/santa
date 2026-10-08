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
#include <queue>
#include <string>
#include <string_view>
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
  // with the only difference between the two being the pid. `parent` is the
  // handle to the forking process (e.g. from Get); it becomes the child's
  // parent link directly, so no lookup is needed under the write lock.
  void HandleFork(uint64_t timestamp,
                  const std::shared_ptr<const Process>& parent,
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

  // Undo the tree effects of an exec that Santa decided to DENY. Unlike the
  // Handle* methods above this is driven by the authorization decision, not by
  // an ES event; `timestamp` is the mach_time of the AUTH_EXEC being answered,
  // and `actor`/`target` are the same two pids HandleExec was given.
  //
  // It exists because the tree learns of an exec at AUTH time, BEFORE the
  // decision: the tree-aware client informs the tree from its context handler,
  // which runs HandleExec for ES_EVENT_TYPE_AUTH_EXEC as well as for
  // ES_EVENT_TYPE_NOTIFY_EXEC (see InformFromESEvent). So by the time Santa
  // answers, HandleExec has already published `target` and already retired
  // `actor`. A DENY makes both of those wrong, in opposite directions:
  //
  //  - `target` never comes into existence. No NOTIFY_EXEC or NOTIFY_EXIT will
  //    ever arrive for it, so nothing else would ever retire it: the node
  //    would sit in map_ forever and pin every annotation name it inherited in
  //    annotation_index_, making AnnotationExists() answer true for the life
  //    of the process. Each denied exec inside an annotated subtree adds
  //    another. So the target is retired here, deferred through remove_at_
  //    exactly as HandleExit's removal is, rather than erased outright, so a
  //    straggling delivery of the same exec to another client cannot reference
  //    a node that has already been reaped.
  //
  //  - `actor` is still running. A denied execve(2) returns EPERM and the
  //    process carries on with its old image, so retiring it was premature:
  //    its annotations stop counting and, once the grace elapses, it is
  //    evicted from map_ entirely. If the annotated process is the one that
  //    attempted the blocked exec, AnnotationExists() goes FALSE while it is
  //    still alive -- a false negative in an authorization gate -- and the
  //    live process disappears from the tree. So the actor is revived:
  //    re-indexed, un-tombstoned, and its pending removal cancelled. Simply
  //    re-indexing would not do, because DrainRemovals unindexes again at the
  //    erase site; the removal itself has to be called off.
  //
  // Both halves happen in one write-lock hold: they are one event and must not
  // be observable half-applied.
  //
  // The actor is revived only if the removal still pending on it is the one
  // HandleExec scheduled for THIS exec (same timestamp). The actor cannot have
  // exited voluntarily -- it is blocked in the kernel inside execve(2) waiting
  // for this very response -- but it can be killed from outside while it
  // waits, and that exit may reach the tree, through another client, before
  // this denial does. The timestamp match is what tells the two apart; see the
  // definition.
  //
  // Each half is a no-op if its pid is not in the tree, and the whole call is
  // idempotent. Takes mtx_ itself, so it must not be called from anywhere
  // already holding it.
  void HandleExecDenied(uint64_t timestamp, struct Pid actor,
                        struct Pid target);

  // Result of GetExecActor. `proc` is the execing (actor) process; it is
  // populated only when `already_seen` is false (and may still be empty then if
  // the actor is unknown to the tree), so callers must check `already_seen`
  // first.
  struct ExecActor {
    std::optional<std::shared_ptr<const Process>> proc;
    bool already_seen;
  };

  // Single reader-lock lookup for the exec ingest path: reports whether this
  // exact exec (timestamp+actor+target identity) was already recorded and, if
  // not, returns the execing (actor) process. Checks the dedup set first and
  // short-circuits, so a duplicate delivery does no map lookup. Lets a caller
  // skip building the (expensive) Program for a duplicate delivery.
  // Best-effort: HandleExec re-checks under the write lock, so a racing novel
  // exec is never dropped.
  ExecActor GetExecActor(uint64_t timestamp, struct Pid actor,
                         struct Pid target) const;

  // Mark the given pids as needing to be retained in the tree's map for future
  // access. Normally, Processes are removed once all clients process past the
  // event which would remove the Process (e.g. exit), however in cases where
  // async processing occurs, the Process may need to be accessed after the
  // exit.
  //
  // Returns the subset actually retained. A pid absent from the tree cannot be
  // retained, and the caller must not release it later: another client may
  // insert that pid in the meantime, and the release would then decrement a
  // count this caller never incremented. Pass this return value to
  // ReleaseProcess, not the request (see ProcessToken).
  [[nodiscard]] PidList RetainProcess(const PidList& pids);

  // Release processes previously retained. `pids` must be what RetainProcess
  // returned, so that every decrement pairs with an increment this caller made.
  void ReleaseProcess(const PidList& pids);

  // Annotate the given process with an Annotator (state). If an annotation of
  // the same type is already set on the process, it is left untouched; use
  // UpdateAnnotation to replace one.
  void AnnotateProcess(const Process& p, std::shared_ptr<const Annotator> a);

  // Replace the annotation of type T on the given process with the result of
  // `update`, which is passed the annotation currently set (nullptr if there is
  // none). Returning nullptr leaves the existing annotation in place.
  //
  // The read and the write are one critical section, so concurrent
  // read-modify-writes of the same annotation cannot lose an update. `update`
  // therefore runs with the write lock held. It is handed only the current
  // annotation, never the tree, so it cannot re-enter and self-deadlock on the
  // (non-recursive) mutex; keep it that way, and keep it short.
  //
  // Takes a pid rather than a handle so resolving the process and updating it
  // are one acquisition.
  template <typename T>
  void UpdateAnnotation(
      struct Pid p,
      const std::function<std::shared_ptr<const T>(const T*)>& update);

  // Get the given annotation on the given process if it exists, or nullopt if
  // the annotation is not set.
  template <typename T>
  std::optional<std::shared_ptr<const T>> GetAnnotation(const Process& p) const;

  // As above, for a process named by pid. Resolving the process and reading its
  // annotation share one acquisition, which is what the CEL has_annotation()
  // path wants: it starts from an audit token, not a handle, and runs once per
  // exec of an annotated subtree.
  template <typename T>
  std::optional<std::shared_ptr<const T>> GetAnnotation(struct Pid p) const;

  // Get the fully merged proto form of all annotations on the given process.
  std::optional<::santa::pb::v1::process_tree::Annotations> ExportAnnotations(
      struct Pid p);

  // True if any live process in the tree carries the named annotation. Backs
  // the CEL annotation_exists(). O(1): the alternative is an O(tree) scan on
  // the authorization path, once per exec.
  //
  // "Live" means still running: a process is counted from the insert that
  // publishes it until the exit (or the exec that replaces it) is processed,
  // NOT until it is finally reaped, so a dead process cannot keep answering
  // true through the removal grace.
  bool AnnotationExists(std::string_view name) const;

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

  // Copy the annotations on `from` that survive this transition onto `to`,
  // asking each one via Annotator::Propagate. Runs inside the same critical
  // section that publishes `to`, so a client that skipped this event as a
  // duplicate can never observe the new process without its inherited
  // annotations. See Annotator::Propagate.
  void PropagateAnnotationsLocked(const Process& from, Process& to,
                                  bool across_exec)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Count `p`'s annotation names into annotation_index_, once. No-op if `p` is
  // already indexed. Call only when the map_ insert that publishes `p`
  // actually happened: the inserts are first-wins, and indexing the loser of
  // that race would double-count names the winner already contributes.
  void IndexProcessLocked(Process& p) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Drop `p`'s contribution, erasing any name whose count reaches zero. No-op
  // if `p` is not indexed.
  void UnindexProcessLocked(Process& p) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Add/remove the names of one annotation, for the paths that add or replace
  // a single annotation on an already-indexed process.
  void IndexAnnotationLocked(const Annotator& a)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);
  void UnindexAnnotationLocked(const Annotator& a)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Queue `p` for removal at `timestamp` and record the schedule on the
  // process, so DrainRemovals can tell a live entry from a cancelled or
  // superseded one. Only processes in map_ may be scheduled: an entry nothing
  // recorded could otherwise reap a node re-inserted under the same pid by a
  // lagging client.
  void ScheduleRemovalLocked(uint64_t timestamp, Process& p)
      ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Cancel `p`'s pending removal and put it back in the annotation index. The
  // inverse of "unindex + ScheduleRemovalLocked", for the one case where the
  // tree is told a process is gone and then learns it is not: the actor of a
  // denied exec. Clears tombstoned_ too, since DrainRemovals may already have
  // tombstoned the process while the decision was outstanding and
  // ReleaseProcess would otherwise erase it when the event's ProcessToken
  // dies.
  void ReviveProcessLocked(Process& p) ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  // Reap deferred removals whose grace has elapsed. Caller must hold mtx_.
  void DrainRemovals() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mtx_);

  std::optional<std::shared_ptr<Process>> GetLocked(struct Pid target) const
      ABSL_SHARED_LOCKS_REQUIRED(mtx_);

  void DebugDumpLocked(std::ostream& stream, int depth, pid_t ppid) const;

  std::vector<std::unique_ptr<Annotator>> annotators_;

  mutable absl::Mutex mtx_;
  absl::flat_hash_map<const struct Pid, std::shared_ptr<Process>> map_
      ABSL_GUARDED_BY(mtx_);
  // Annotation names carried by at least one live process, each with the
  // number of processes carrying it. The count is of PROCESSES, not of
  // Annotator objects: PropagatesWholly lets one object be shared by a whole
  // inherited subtree, and each process carrying it counts once -- strictly,
  // once per annotator TYPE on that process, since annotations_ is keyed by
  // type and each entry is counted separately, so a process would be counted
  // twice for a name two different annotator types both contributed. That is
  // moot while CELAnnotator is the only contributor, but an author adding a
  // second indexing annotator must keep the name spaces disjoint (or make
  // this index dedup per process). A name is erased when its last carrier
  // retires, so a lookup answers AnnotationExists() without touching map_.
  absl::flat_hash_map<std::string, uint32_t> annotation_index_
      ABSL_GUARDED_BY(mtx_);
  // Pending removals: pids to erase from map_, each paired with the mach_time
  // of the exit/exec event that scheduled it. Entries are advisory, not
  // authoritative: a priority_queue cannot have an entry extracted, so the
  // decision to reap lives on the Process (pending_removal_/removal_ts_) and
  // an entry that does not match it is discarded on pop. That is what lets a
  // removal be cancelled (HandleExecDenied) and what keeps several entries for
  // one pid from reaping it early. An entry is reaped once
  // removal_grace_ticks_ have elapsed past that timestamp (measured against
  // latest_ts_), so a reordered straggler cannot reference a process after it
  // is reaped. Held as a MIN-heap on the timestamp so DrainRemovals reaps only
  // the entries that have expired (smallest timestamps) rather than scanning
  // every pending one — ES delivers events out of order, so timestamps are not
  // appended monotonically and the earliest deadline is not necessarily the
  // oldest insertion. See DrainRemovals().
  struct ReapEarliestFirst {
    bool operator()(const std::pair<uint64_t, struct Pid>& a,
                    const std::pair<uint64_t, struct Pid>& b) const {
      return a.first > b.first;  // priority_queue is a max-heap; invert for min
    }
  };
  std::priority_queue<std::pair<uint64_t, struct Pid>,
                      std::vector<std::pair<uint64_t, struct Pid>>,
                      ReapEarliestFirst>
      remove_at_ ABSL_GUARDED_BY(mtx_);

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

  // Test-only seam (empty in production): invoked by ReleaseProcess between
  // the reader-lock collect and the exclusive-lock erase — the window the
  // erase re-verify guards. Set via ProcessTreeTestPeer.
  std::function<void()> on_release_collected_for_test_;
};

// Annotations are read from the ES auth path (CEL) while the annotators write
// them from the ingest path, so both sides take mtx_. It guards every process's
// annotation map, not just map_ itself.
template <typename T>
std::optional<std::shared_ptr<const T>> ProcessTree::GetAnnotation(
    const Process& p) const {
  absl::ReaderMutexLock lock(mtx_);
  auto it = p.annotations_.find(std::type_index(typeid(T)));
  if (it == p.annotations_.end()) {
    return std::nullopt;
  }
  return std::dynamic_pointer_cast<const T>(it->second);
}

template <typename T>
std::optional<std::shared_ptr<const T>> ProcessTree::GetAnnotation(
    const struct Pid p) const {
  absl::ReaderMutexLock lock(mtx_);
  auto proc = map_.find(p);
  if (proc == map_.end()) {
    return std::nullopt;
  }
  const auto& annotations = proc->second->annotations_;
  auto it = annotations.find(std::type_index(typeid(T)));
  if (it == annotations.end()) {
    return std::nullopt;
  }
  return std::dynamic_pointer_cast<const T>(it->second);
}

template <typename T>
void ProcessTree::UpdateAnnotation(
    const struct Pid p,
    const std::function<std::shared_ptr<const T>(const T*)>& update) {
  absl::MutexLock lock(mtx_);
  auto it = map_.find(p);
  if (it == map_.end()) {
    return;
  }

  Process& proc = *it->second;
  auto& annotations = proc.annotations_;
  const std::type_index key(typeid(T));
  auto found = annotations.find(key);
  const T* current = found != annotations.end()
                         ? dynamic_cast<const T*>(found->second.get())
                         : nullptr;

  std::shared_ptr<const T> next = update(current);
  if (next == nullptr) {
    return;
  }

  // The replacement may carry a different set of names, so swap the old set's
  // contribution for the new one's. Only for a process that is counted at all:
  // one already retired must not re-enter the index. Unindex the STORED
  // annotation (found->second), not `current`: if the dynamic_cast above ever
  // returned nullptr while the map entry existed, unindexing `current` would
  // silently skip the decrement while insert_or_assign below still replaces
  // the entry -- leaking an increment with no matching decrement.
  if (proc.indexed_) {
    if (found != annotations.end()) {
      UnindexAnnotationLocked(*found->second);
    }
    IndexAnnotationLocked(*next);
  }
  annotations.insert_or_assign(key, std::move(next));
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
