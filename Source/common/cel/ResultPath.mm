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

#include "Source/common/cel/ResultPath.h"

#include "absl/strings/string_view.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/expr.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

namespace {

bool IsCall(const ::cel::Expr& expr, absl::string_view function) {
  return expr.has_call_expr() && expr.call_expr().function() == function;
}

// A parent that hands this child's value straight back out.
bool PassesChildThrough(const ::cel::Expr& parent, int childIndex) {
  // A ternary yields whichever branch it took, never the condition.
  if (IsCall(parent, "_?_:_")) {
    return childIndex != 0;
  }
  // add_annotation() returns its policy argument, which is always the last one.
  if (IsCall(parent, "add_annotation")) {
    return childIndex == static_cast<int>(parent.call_expr().args().size()) - 1;
  }
  return false;
}

}  // namespace

bool IsOnResultPath(const ::cel::NavigableAstNode& node) {
  for (const ::cel::NavigableAstNode* n = &node; n->parent() != nullptr; n = n->parent()) {
    if (n->child_index() < 0 || !PassesChildThrough(*n->parent()->expr(), n->child_index())) {
      return false;
    }
  }
  return true;
}

}  // namespace cel
}  // namespace santa
