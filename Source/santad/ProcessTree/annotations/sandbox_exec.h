/// Copyright 2026 North Pole Security, Inc.
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
#ifndef SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_SANDBOX_EXEC_H
#define SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_SANDBOX_EXEC_H

#include <optional>
#include <string>

#include "Source/santad/ProcessTree/annotations/annotator.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"

namespace santa::santad::process_tree {

enum class SandboxPolicyStatus {
  kPending,
  kConfirmed,
};

struct SandboxPolicyInfo {
  std::string profile_path;
  SandboxPolicyStatus status;
};

// Parse sandbox-exec argv to extract the sandbox profile info.
// Returns nullopt if argv is malformed or doesn't contain -f.
std::optional<SandboxPolicyInfo> ParseSandboxExecArgv(
    const std::vector<std::string> &argv);

class SandboxExecAnnotator : public Annotator {
 public:
  SandboxExecAnnotator() : info_(std::nullopt) {};
  explicit SandboxExecAnnotator(SandboxPolicyInfo info)
      : info_(std::move(info)) {};

  void AnnotateFork(ProcessTree &tree, const Process &parent,
                    const Process &child) override;
  void AnnotateExec(ProcessTree &tree, const Process &orig_process,
                    const Process &new_process) override;

  std::optional<::santa::pb::v1::process_tree::Annotations> Proto()
      const override;

  const std::optional<SandboxPolicyInfo> &info() const { return info_; }

 private:
  std::optional<SandboxPolicyInfo> info_;
};

}  // namespace santa::santad::process_tree

#endif
