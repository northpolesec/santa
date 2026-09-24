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

#ifndef SANTA_COMMON_PROCESSTREE_ANNOTATIONS_CEL_H
#define SANTA_COMMON_PROCESSTREE_ANNOTATIONS_CEL_H

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "Source/common/processtree/annotations/annotator.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.pb.h"
#include "absl/container/flat_hash_map.h"

namespace santa::santad::process_tree {

// Annotations added by CELv2 rules through add_annotation(). Unlike the other
// annotators, which decide for themselves what to mark, this one is a bag of
// rule-supplied names, each carrying its own propagation: an entry survives a
// fork only if its `fork` flag is set, and an exec only if `exec` is set.
//
// Because the propagating subset differs per entry, a descendant gets a NEW
// CELAnnotator holding the filtered entries rather than sharing the ancestor's
// (which is what OriginatorAnnotator does).
//
// This is NOT registered as a tree annotator. An authorization decision reads
// these (has_annotation()), so propagation has to be atomic with the insert
// that publishes the process; the registered-annotator hooks run after it, and
// another ES client can authorize an exec in between. Inheritance is therefore
// driven by Propagate(), which the tree calls under its write lock, and the
// AnnotateFork/AnnotateExec overrides below are unreachable no-ops.
//
// IMMUTABLE, and must stay that way: PropagatesWholly() lets the tree share one
// instance with every descendant that inherits it unchanged, so a write through
// a shared instance would land on the whole subtree. Adding an entry builds a
// new CELAnnotator and swaps the pointer (see AddCELAnnotation); nothing ever
// mutates entries_ in place.
class CELAnnotator : public Annotator {
 public:
  struct Entry {
    bool fork = false;
    bool exec = false;

    bool operator==(const Entry& other) const {
      return fork == other.fork && exec == other.exec;
    }
  };
  using EntryMap = absl::flat_hash_map<std::string, Entry>;

  // Annotation names come from rules, which propagate to every descendant, so
  // a runaway expression would otherwise grow the tree's memory without bound.
  static constexpr size_t kMaxNameLength = 128;
  static constexpr size_t kMaxEntries = 32;

  CELAnnotator() = default;
  explicit CELAnnotator(EntryMap entries) : entries_(std::move(entries)) {}

  // Never called: this type is not registered on the tree. See the class
  // comment.
  void AnnotateFork(ProcessTree&, const Process&, const Process&) override {}
  void AnnotateExec(ProcessTree&, const Process&, const Process&) override {}

  std::shared_ptr<const Annotator> Propagate(bool across_exec) const override;
  bool PropagatesWholly(bool across_exec) const override;

  std::optional<::santa::pb::v1::process_tree::Annotations> Proto()
      const override;

  bool Has(std::string_view name) const { return entries_.contains(name); }
  const EntryMap& entries() const { return entries_; }

 private:
  EntryMap entries_;
};

// Add `name` to the CEL annotations on `p`, replacing that process's
// CELAnnotator with one that also carries the new entry. A name longer than
// kMaxNameLength, an empty name, or an add past kMaxEntries is dropped.
// Re-adding an existing name updates its propagation.
void AddCELAnnotation(ProcessTree& tree, struct Pid p, std::string_view name,
                      CELAnnotator::Entry entry);

}  // namespace santa::santad::process_tree

#endif  // SANTA_COMMON_PROCESSTREE_ANNOTATIONS_CEL_H
