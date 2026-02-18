/// Copyright 2023 Google LLC
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.
#ifndef SANTA__SANTAD_PROCESSTREE_PROCESS_H
#define SANTA__SANTAD_PROCESSTREE_PROCESS_H

#include <sys/types.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <typeindex>
#include <vector>

#include "Source/santad/ProcessTree/annotations/annotator.h"
#include "absl/container/flat_hash_map.h"

namespace santa::santad::process_tree {

struct Pid {
  pid_t pid;
  uint64_t pidversion;

  friend bool operator==(const struct Pid &lhs, const struct Pid &rhs) {
    return lhs.pid == rhs.pid && lhs.pidversion == rhs.pidversion;
  }
  friend bool operator!=(const struct Pid &lhs, const struct Pid &rhs) {
    return !(lhs == rhs);
  }
};

template <typename H>
H AbslHashValue(H h, const struct Pid &p) {
  return H::combine(std::move(h), p.pid, p.pidversion);
}

struct Cred {
  uid_t uid;
  gid_t gid;

  friend bool operator==(const struct Cred &lhs, const struct Cred &rhs) {
    return lhs.uid == rhs.uid && lhs.gid == rhs.gid;
  }
  friend bool operator!=(const struct Cred &lhs, const struct Cred &rhs) {
    return !(lhs == rhs);
  }
};

struct CodeSigningInfo {
  std::string signing_id;
  std::string team_id;
  std::string cdhash;  // hex string
  bool is_platform_binary;

  friend bool operator==(const struct CodeSigningInfo &lhs,
                         const struct CodeSigningInfo &rhs) {
    return lhs.signing_id == rhs.signing_id && lhs.team_id == rhs.team_id &&
           lhs.cdhash == rhs.cdhash &&
           lhs.is_platform_binary == rhs.is_platform_binary;
  }
};

struct Program {
  std::string executable;
  std::vector<std::string> arguments;
  std::optional<CodeSigningInfo> code_signing;

  friend bool operator==(const struct Program &lhs, const struct Program &rhs) {
    return lhs.executable == rhs.executable && lhs.arguments == rhs.arguments &&
           lhs.code_signing == rhs.code_signing;
  }
};

// Fwd decls
class ProcessTree;

class Process {
 public:
  explicit Process(const Pid pid, const Cred cred,
                   std::shared_ptr<const Program> program,
                   std::shared_ptr<const Process> parent)
      : pid_(pid),
        effective_cred_(cred),
        program_(program),
        annotations_(),
        parent_(parent),
        refcnt_(0),
        tombstoned_(false) {}
  Process(const Process &) = default;
  Process &operator=(const Process &) = delete;
  Process(Process &&) = default;
  Process &operator=(Process &&) = delete;

  // Const "attributes" are public
  const struct Pid pid_;
  const struct Cred effective_cred_;
  const std::shared_ptr<const Program> program_;

 private:
  // This is not API.
  // The tree helper methods are the API, and we just happen to implement
  // annotation storage and the parent relation in memory on the process right
  // now.
  friend class ProcessTree;
  absl::flat_hash_map<std::type_index, std::shared_ptr<const Annotator>>
      annotations_;
  std::shared_ptr<const Process> parent_;
  // TODO(nickmg): atomic here breaks the build.
  int refcnt_;
  // If the process is tombstoned, the event removing it from the tree has been
  // processed, but refcnt>0 keeps it alive.
  bool tombstoned_;
};

}  // namespace santa::santad::process_tree

#endif
