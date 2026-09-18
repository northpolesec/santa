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

#ifndef SANTA_COMMON_PROCESSTREE_ANNOTATIONS_ANNOTATOR_H
#define SANTA_COMMON_PROCESSTREE_ANNOTATIONS_ANNOTATOR_H

#include <memory>
#include <optional>

#include "Source/common/processtree/process_tree.pb.h"

namespace santa::santad::process_tree {

class ProcessTree;
class Process;

class Annotator {
 public:
  virtual ~Annotator() = default;

  // Hooks for annotators registered on the tree. They run OUTSIDE the tree
  // lock, after the descendant is already visible, because they re-enter the
  // tree (to look the parent's annotation up and to write the child's). A
  // consumer on another ES client can therefore observe the descendant before
  // these have run. That is tolerable for an annotation only used in telemetry;
  // it is not tolerable for one an authorization decision reads, which is what
  // Propagate() below is for.
  virtual void AnnotateFork(ProcessTree& tree, const Process& parent,
                            const Process& child) = 0;
  virtual void AnnotateExec(ProcessTree& tree, const Process& orig_process,
                            const Process& new_process) = 0;

  // What this annotation becomes on the descendant created by a fork
  // (across_exec false) or an exec (true), or nullptr if it does not survive
  // that transition.
  //
  // Unlike the hooks above this is driven by the annotation already on the
  // ancestor rather than by the tree's annotator list, and the tree calls it
  // while holding the write lock that publishes the descendant. Propagation is
  // therefore atomic with the structural insert: any client that can see the
  // new process can see its inherited annotations. Because the lock is held,
  // an implementation MUST NOT touch the tree.
  //
  // The default is "does not propagate", so an annotator that only implements
  // the hooks above is unaffected.
  virtual std::shared_ptr<const Annotator> Propagate(bool across_exec) const {
    return nullptr;
  }

  // True when Propagate(across_exec) would return something equal to this
  // annotation, so the tree can hand the descendant this very object instead of
  // paying for an identical copy. Answer without allocating; the whole point is
  // to keep an allocation out of the critical section that publishes the
  // descendant.
  //
  // Returning true makes one object reachable from several processes at once,
  // so an annotation that does it MUST be immutable: every update has to build
  // a new object and swap the pointer (which is what UpdateAnnotation does),
  // never write through the shared one, or the write lands on every ancestor
  // and sibling sharing it.
  //
  // The default is false, which is always safe: the tree falls back to
  // Propagate().
  virtual bool PropagatesWholly(bool across_exec) const { return false; }

  virtual std::optional<::santa::pb::v1::process_tree::Annotations> Proto()
      const = 0;
};

}  // namespace santa::santad::process_tree

#endif  // SANTA_COMMON_PROCESSTREE_ANNOTATIONS_ANNOTATOR_H
