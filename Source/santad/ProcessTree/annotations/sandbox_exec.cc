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
#include "Source/santad/ProcessTree/annotations/sandbox_exec.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"

namespace ptpb = ::santa::pb::v1::process_tree;

namespace santa::santad::process_tree {

namespace {

bool IsSandboxExec(const Process &p) {
  // Path is sufficient — /usr/bin/sandbox-exec is SIP-protected.
  return p.program_->executable == "/usr/bin/sandbox-exec";
}

}  // namespace

std::optional<SandboxPolicyInfo> ParseSandboxExecArgv(
    const std::vector<std::string> &argv) {
  // argv: ["sandbox-exec", "-f", "<path>", ...]
  // Scan for the -f flag.
  for (size_t i = 0; i < argv.size(); i++) {
    if (argv[i] == "-f" && i + 1 < argv.size()) {
      return SandboxPolicyInfo{
          .profile_path = argv[i + 1],
          .status = SandboxPolicyStatus::kPending,
      };
    }
  }
  return std::nullopt;
}

void SandboxExecAnnotator::AnnotateFork(ProcessTree &tree,
                                        const Process &parent,
                                        const Process &child) {
  auto annotation = tree.GetAnnotation<SandboxExecAnnotator>(parent);
  if (!annotation) return;

  // Only propagate confirmed annotations.
  if ((*annotation)->info_ &&
      (*annotation)->info_->status == SandboxPolicyStatus::kConfirmed) {
    tree.AnnotateProcess(child, std::move(*annotation));
  }
}

void SandboxExecAnnotator::AnnotateExec(ProcessTree &tree,
                                        const Process &orig_process,
                                        const Process &new_process) {
  // If the new image is sandbox-exec, always parse its argv for a new pending
  // policy. This must come first so nested sandbox-exec invocations pick up the
  // new profile rather than retaining a stale one from the parent.
  if (IsSandboxExec(new_process)) {
    if (auto info = ParseSandboxExecArgv(new_process.program_->arguments)) {
      tree.AnnotateProcess(new_process, std::make_shared<SandboxExecAnnotator>(
                                            std::move(*info)));
      return;
    }
  }

  // Check if the previous process had a pending annotation to confirm.
  if (auto annotation =
          tree.GetAnnotation<SandboxExecAnnotator>(orig_process)) {
    if ((*annotation)->info_ &&
        (*annotation)->info_->status == SandboxPolicyStatus::kPending) {
      // Promote pending to confirmed on the new process.
      auto confirmed_info = (*annotation)->info_.value();
      confirmed_info.status = SandboxPolicyStatus::kConfirmed;
      tree.AnnotateProcess(new_process, std::make_shared<SandboxExecAnnotator>(
                                            std::move(confirmed_info)));
      return;
    }
    // Propagate confirmed annotations through exec.
    tree.AnnotateProcess(new_process, std::move(*annotation));
    return;
  }
}

std::optional<ptpb::Annotations> SandboxExecAnnotator::Proto() const {
  if (!info_ || info_->status != SandboxPolicyStatus::kConfirmed) {
    return std::nullopt;
  }
  ptpb::Annotations annotations;
  auto *sp = annotations.mutable_sandbox_policy();
  sp->set_profile_path(info_->profile_path);
  return annotations;
}

}  // namespace santa::santad::process_tree
