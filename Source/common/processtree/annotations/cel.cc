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

#include "Source/common/processtree/annotations/cel.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.h"
#include "Source/common/processtree/process_tree.pb.h"
#include "internal/utf8.h"

namespace ptpb = ::santa::pb::v1::process_tree;

namespace santa::santad::process_tree {

bool CELAnnotator::PropagatesWholly(bool across_exec) const {
  // An empty set is not worth sharing, and Propagate() would drop it anyway.
  if (entries_.empty()) {
    return false;
  }
  for (const auto& [name, entry] : entries_) {
    if (!(across_exec ? entry.exec : entry.fork)) {
      return false;
    }
  }
  return true;
}

std::shared_ptr<const Annotator> CELAnnotator::Propagate(
    bool across_exec) const {
  CELAnnotator::EntryMap surviving;
  for (const auto& [name, entry] : entries_) {
    if (across_exec ? entry.exec : entry.fork) {
      surviving.emplace(name, entry);
    }
  }
  if (surviving.empty()) {
    return nullptr;
  }
  return std::make_shared<const CELAnnotator>(std::move(surviving));
}

std::optional<ptpb::Annotations> CELAnnotator::Proto() const {
  if (entries_.empty()) {
    return std::nullopt;
  }

  // flat_hash_map iteration order is unspecified; telemetry consumers get a
  // stable list.
  std::vector<std::string_view> names;
  names.reserve(entries_.size());
  for (const auto& [name, _] : entries_) {
    names.push_back(name);
  }
  std::sort(names.begin(), names.end());

  ptpb::Annotations annotations;
  for (std::string_view name : names) {
    annotations.add_cel(std::string(name));
  }
  return annotations;
}

void AddCELAnnotation(ProcessTree& tree, const struct Pid p,
                      std::string_view name, CELAnnotator::Entry entry) {
  // CEL only checks string validity in debug builds, so a name built from
  // argv or a path can carry arbitrary bytes. Every consumer (telemetry, sync,
  // NSString) needs UTF-8.
  if (name.empty() || name.size() > CELAnnotator::kMaxNameLength ||
      !::cel::internal::Utf8IsValid(name)) {
    return;
  }

  tree.UpdateAnnotation<CELAnnotator>(
      p,
      [&](const CELAnnotator* current) -> std::shared_ptr<const CELAnnotator> {
        CELAnnotator::EntryMap entries;
        if (current) {
          auto it = current->entries().find(name);
          if (it != current->entries().end()) {
            if (it->second == entry) {
              // Already set with this propagation; leave the annotation (and
              // the shared_ptr any descendant may hold) alone.
              return nullptr;
            }
          } else if (current->entries().size() >= CELAnnotator::kMaxEntries) {
            return nullptr;
          }
          entries = current->entries();
        }

        entries.insert_or_assign(std::string(name), entry);
        return std::make_shared<const CELAnnotator>(std::move(entries));
      });
}

}  // namespace santa::santad::process_tree
