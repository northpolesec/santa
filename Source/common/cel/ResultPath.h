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

#ifndef SANTA_COMMON_CEL_RESULTPATH_H
#define SANTA_COMMON_CEL_RESULTPATH_H

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/navigable_ast.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// True when `node` is one of the values the expression can actually return,
// i.e. every step from it to the root passes a Result through unchanged.
//
// Two constructs do that: a ternary branch (not its condition), and
// add_annotation() in its policy slot, which returns that argument untouched.
// Anything else -- a policy_for_range() argument, a comparison operand, a list
// element -- is evaluated for its own sake and may well be discarded, so a node
// sitting there is not the rule's answer.
//
// Two placement rules depend on this, for related reasons. kill_on_expiry()
// must produce the rule's decision, or it would schedule a kill for a policy
// that was never applied. add_annotation() writes to the process tree, so off
// the result path it would stamp an annotation for a policy the rule did not
// choose: CEL evaluates call arguments eagerly, so
// policy_for_range(start, end, add_annotation('X', ALLOWLIST), BLOCKLIST)
// stamps X even when the window is shut.
bool IsOnResultPath(const ::cel::NavigableAstNode& node);

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_RESULTPATH_H
