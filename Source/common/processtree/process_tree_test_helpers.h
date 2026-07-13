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

#ifndef SANTA_COMMON_PROCESSTREE_PROCESSTREETESTHELPERS_H
#define SANTA_COMMON_PROCESSTREE_PROCESSTREETESTHELPERS_H

#include <functional>
#include <memory>
#include <utility>

#include "Source/common/processtree/process_tree.h"

namespace santa::santad::process_tree {

class ProcessTreeTestPeer : public ProcessTree {
 public:
  explicit ProcessTreeTestPeer(
      std::vector<std::unique_ptr<Annotator>>&& annotators,
      uint64_t removal_grace_ticks = 0)
      : ProcessTree(std::move(annotators), removal_grace_ticks) {}
  std::shared_ptr<const Process> InsertInit();

  // Install the StepLocked test seam (ProcessTreeTestPeer is a friend of
  // ProcessTree, so it can reach the private member).
  void SetOnEventClaimedForTest(std::function<void()> hook) {
    on_event_claimed_for_test_ = std::move(hook);
  }
};

}  // namespace santa::santad::process_tree

#endif  // SANTA_COMMON_PROCESSTREE_PROCESSTREETESTHELPERS_H
