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

#ifndef SANTA_COMMON_CEL_ANNOTATIONFUNCTION_H
#define SANTA_COMMON_CEL_ANNOTATIONFUNCTION_H

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "compiler/compiler.h"
#include "eval/public/cel_function.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_options.h"
#include "eval/public/cel_value.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// Process-tree annotations for CELv2 rules. An annotation is a rule-chosen name
// stamped on the process being executed; it propagates to that process's
// descendants and can be tested by a later rule or fallback expression.
//
//   add_annotation(string name, int propagation, policy) -> policy
//   add_annotation(string name, policy) -> policy
//   add_annotation(list<string> names, int propagation, policy) -> policy
//   add_annotation(list<string> names, policy) -> policy
//     Stamps the name (or every name in the list) on the process being executed
//     and returns `policy` unchanged, so the call is a drop-in wrapper around
//     whatever the rule was going to return. The forms without a propagation
//     argument use FORK_AND_EXEC. Every name in a list gets the same
//     propagation; use separate calls to mix them. An empty list stamps
//     nothing and still returns the policy.
//
//   has_annotation(string name) -> bool
//     True if `name` is on the process being executed.
//
// Together they replace an ancestor walk with a hash lookup. Instead of every
// descendant re-matching the ancestor it cares about:
//
//     # rule on the tool
//     <expensive match>
//       ? add_annotation("BAZEL-CALL", FORK_AND_EXEC, ALLOWLIST)
//       : UNSPECIFIED
//     # fallback
//     has_annotation("BAZEL-CALL") ? ALLOWLIST_COMPILER : UNSPECIFIED
//
// Both are lazy functions: their implementations are vended by the Activation
// (see Activation::FindFunctionOverloads) rather than registered eagerly, which
// keeps add_annotation()'s side effect out of constant folding and lets either
// call flag the evaluation as non-cacheable. Non-cacheable is required, not an
// optimization: a cached decision skips evaluation entirely on the next exec,
// which would silently stop stamping the annotation.
//
// Only available in CELv2.

// How far an annotation follows a process's descendants. The names are the
// identifiers rules write; the values are an interface only in that a rule may
// name them, so they are never sent over the wire as numbers.
enum class AnnotationPropagation : int64_t {
  // Stays on this process only. Not observable by has_annotation() (which runs
  // against the post-exec process); exported to telemetry.
  kNone = 0,
  // Follows forks but not execs. As above, telemetry only in practice: a
  // fork+exec child loses it before any rule can see it.
  kForkOnly = 1,
  // Follows execs but not forks, i.e. it stays with this process across its own
  // re-exec but does not reach anything it spawns.
  kExecOnly = 2,
  // Follows both. The useful default, and what the two-argument
  // add_annotation() uses.
  kForkAndExec = 3,
};

inline constexpr std::pair<absl::string_view, AnnotationPropagation>
    kAnnotationPropagationNames[] = {
        {"NONE", AnnotationPropagation::kNone},
        {"FORK_ONLY", AnnotationPropagation::kForkOnly},
        {"EXEC_ONLY", AnnotationPropagation::kExecOnly},
        {"FORK_AND_EXEC", AnnotationPropagation::kForkAndExec},
};

// How the CEL layer reaches the process tree. Supplied by santad (see
// CreateCELActivationBlock); empty hooks mean there is no tree, in which case
// has_annotation() is false and add_annotation() only passes its policy
// through.
struct AnnotationHooks {
  std::function<bool(const std::string& name)> has;
  std::function<void(const std::string& name,
                     AnnotationPropagation propagation)>
      add;
};

// Annotations an evaluation has asked for but not yet applied. add_annotation()
// appends here instead of writing straight through, and the Activation applies
// the list only once the whole expression has produced a usable result (see
// Activation::FlushStagedAnnotations). Without that, an expression that fails
// *after* a successful add_annotation -- CEL evaluates call arguments eagerly,
// so the inner call of add_annotation('A', 99, add_annotation('B', ALLOWLIST))
// completes before the outer one rejects 99 -- would leave the annotation
// behind, and with fail-closed off the fallbacks would then read it.
//
// Consequence worth knowing: has_annotation() reports the process as it was
// when evaluation began, and does not observe an add_annotation() made by the
// same expression.
using StagedAnnotations =
    std::vector<std::pair<std::string, AnnotationPropagation>>;

// Descriptors for has_annotation() and the add_annotation() overloads. Both are
// returned as vectors because the Activation vends whole overload sets.
std::vector<::google::api::expr::runtime::CelFunctionDescriptor>
HasAnnotationDescriptors();
std::vector<::google::api::expr::runtime::CelFunctionDescriptor>
AddAnnotationDescriptors();

// Lazy CEL function backing has_annotation(). Sets the supplied flag to mark
// the evaluation non-cacheable. The sink pointer must outlive every evaluation.
class HasAnnotationFunction : public ::google::api::expr::runtime::CelFunction {
 public:
  HasAnnotationFunction(
      ::google::api::expr::runtime::CelFunctionDescriptor descriptor,
      bool* used_sink, AnnotationHooks hooks)
      : ::google::api::expr::runtime::CelFunction(std::move(descriptor)),
        used_sink_(used_sink),
        hooks_(hooks) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
  AnnotationHooks hooks_;
};

// Lazy CEL function backing every add_annotation() overload: the argument count
// says whether a propagation was given, and the first argument's kind says
// whether it is one name or a list of them. Sets the supplied flag to mark the
// evaluation non-cacheable. The sink pointer must outlive every evaluation.
class AddAnnotationFunction : public ::google::api::expr::runtime::CelFunction {
 public:
  AddAnnotationFunction(
      ::google::api::expr::runtime::CelFunctionDescriptor descriptor,
      bool* used_sink, StagedAnnotations* staged)
      : ::google::api::expr::runtime::CelFunction(std::move(descriptor)),
        used_sink_(used_sink),
        staged_(staged) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
  StagedAnnotations* staged_;
};

// Register the add_annotation() and has_annotation() decls with the type
// checker at compile time. Only available in CELv2.
absl::Status AddAnnotationCompilerLibrary(::cel::CompilerBuilder& builder);

// Register the annotation functions at runtime. Both are lazy; the Activation
// provides the implementations. Only available in CELv2.
absl::Status RegisterAnnotationFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry* registry,
    const ::google::api::expr::runtime::InterpreterOptions& options);

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_ANNOTATIONFUNCTION_H
