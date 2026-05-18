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

#ifndef SANTA_SANTAD_SANDBOXEDLINEAGE_H
#define SANTA_SANTAD_SANDBOXEDLINEAGE_H

#import <Foundation/Foundation.h>
#include <bsm/libbsm.h>

#include <cstddef>
#include <cstdint>

#include "absl/container/flat_hash_set.h"
#include "absl/synchronization/mutex.h"

namespace santa {

// Tracks (pid, pidversion) tuples of processes known to be running inside a
// santad-issued seatbelt sandbox. Entry into the set requires a successful
// SEATBELT expectation match (see SandboxExpectations); from there, the set
// follows the process tree via NOTIFY_FORK and AUTH_EXEC so descendants —
// which inherit the kernel-enforced seatbelt — can be authorized without
// another `santactl sandbox` round-trip.
//
// Thread-safe; methods may be called from any ES delivery queue.
class SandboxedLineage {
 public:
  // The set is bounded to avoid unbounded growth under abuse or leaks (no
  // TTL: real entries live for the lifetime of a process, cleaned up by
  // NOTIFY_EXIT). The ceiling is generous compared to the per-host process
  // count under any realistic workload; Mark refuses entries past the cap
  // so AUTH_EXEC simply falls back to deny rather than evicting an entry
  // that may belong to a still-running sandboxed process.
  static constexpr size_t kMaxEntries = 4096;

  SandboxedLineage() = default;

  SandboxedLineage(const SandboxedLineage&) = delete;
  SandboxedLineage& operator=(const SandboxedLineage&) = delete;

  // Records |token| as a sandboxed-lineage member. Idempotent. Returns false
  // if the set is at capacity and the entry was not added.
  bool Mark(const audit_token_t& token);

  // Returns true if |token| is in the set.
  bool Contains(const audit_token_t& token) const;

  // Removes |token| from the set. No-op if absent. Call from NOTIFY_EXIT.
  void Forget(const audit_token_t& token);

  // If |parent| is in the set, marks |child| as well. Call from NOTIFY_FORK
  // to propagate sandboxed-lineage membership to forked children, which
  // inherit the kernel-enforced seatbelt automatically. Returns true iff
  // the child was added.
  bool PropagateOnFork(const audit_token_t& parent, const audit_token_t& child);

  // Exec membership shift. If |pre| is in the set, removes it and adds
  // |post|. Call from NOTIFY_EXEC: the kernel preserves the pid across
  // exec but bumps pidversion, so a stale (pid, pre-pidversion) entry
  // would otherwise sit until the process exits. This also propagates
  // lineage across non-SEATBELT-ruled execs by a sandboxed process, since
  // the kernel-enforced seatbelt follows the process regardless of which
  // Santa rule (if any) governed the exec. Returns true iff a transition
  // occurred.
  bool OnExec(const audit_token_t& pre, const audit_token_t& post);

  // Test/debug helper.
  size_t CountForTesting() const;

 private:
  static uint64_t KeyFromToken(const audit_token_t& token);

  mutable absl::Mutex mu_;
  absl::flat_hash_set<uint64_t> entries_ ABSL_GUARDED_BY(mu_);
};

}  // namespace santa

#endif  // SANTA_SANTAD_SANDBOXEDLINEAGE_H
