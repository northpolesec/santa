/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA_COMMON_CEL_EVALUATOR_H
#define SANTA_COMMON_CEL_EVALUATOR_H

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/PolicyForRangeFunction.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "cel/expr/checked.pb.h"
#include "compiler/compiler.h"
#include "eval/public/cel_expression.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// Result of evaluating a CEL expression
template <bool IsV2>
struct EvaluationResult {
  using Traits = CELProtoTraits<IsV2>;
  using ReturnValue = typename Traits::ReturnValue;

  ReturnValue value;
  bool cacheable;
  std::optional<uint64_t>
      touchIDCooldownMinutes;  // nullopt = no caching (prompt every time)
  // Set when policy_for_range() matched an open window with a kill_on_expiry()
  // policy. The deadline is only recorded if the execution is allowed to run.
  std::optional<PendingKill> pendingKill;

  EvaluationResult(ReturnValue v, bool c,
                   std::optional<uint64_t> cooldown = std::nullopt,
                   std::optional<PendingKill> kill = std::nullopt)
      : value(v),
        cacheable(c),
        touchIDCooldownMinutes(cooldown),
        pendingKill(std::move(kill)) {}
};

template <bool IsV2>
class Evaluator {
 public:
  using Traits = CELProtoTraits<IsV2>;
  using ReturnValue = typename Traits::ReturnValue;
  using ActivationT = Activation<IsV2>;
  using EvaluationResultT = EvaluationResult<IsV2>;

  // allowUnspecified permits the expression to return UNSPECIFIED (fall through
  // to the next rule). Only fallback expressions should set this; regular rules
  // leave it false so a UNSPECIFIED return fails to compile. It also decides
  // whether policy_for_range() is declared, which is the other way around: a
  // fallback expression carries no rule identity for a time window to attach
  // to, so only rules get the function. No-op for V1.
  static absl::StatusOr<std::unique_ptr<Evaluator>> Create(
      bool allowUnspecified = false);

  Evaluator(std::unique_ptr<::cel::Compiler> compiler,
            std::unique_ptr<google::protobuf::Arena> arena,
            bool allowUnspecified)
      : compiler_(std::move(compiler)),
        compiler_arena_(std::move(arena)),
        allowUnspecified_(allowUnspecified) {};
  ~Evaluator() = default;

  Evaluator(Evaluator&& other) = default;
  Evaluator& operator=(Evaluator&& rhs) = default;

  // Could be safe to implement these, but not currently needed
  Evaluator(const Evaluator& other) = delete;
  Evaluator& operator=(const Evaluator& other) = delete;

  // Compile a CEL expression from a string into an expression plan
  // ready for evaluation. The caller-provided arena is used for constant
  // folding and must outlive the returned expression plan.
  absl::StatusOr<std::unique_ptr<::google::api::expr::runtime::CelExpression>>
  Compile(absl::string_view cel_expr, google::protobuf::Arena* arena);

  // Evaluate an expression plan with a SantaActivation object. The
  // caller-provided arena is used for evaluation temporaries.
  absl::StatusOr<EvaluationResultT> Evaluate(
      ::google::api::expr::runtime::CelExpression const* expression_plan,
      const ActivationT& activation, google::protobuf::Arena* arena);

  // Compile and evaluate a CEL expression in a single call. Uses a
  // stack-local arena internally so no allocations persist after return.
  absl::StatusOr<EvaluationResultT> CompileAndEvaluate(
      absl::string_view cel_expr, const ActivationT& activation);

 private:
  std::unique_ptr<::cel::Compiler> compiler_;
  std::unique_ptr<google::protobuf::Arena>
      compiler_arena_;  // Kept alive for compiler type refs
  // Kept so Compile() registers the same set of functions the compiler
  // declared.
  bool allowUnspecified_ = false;
};

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_EVALUATOR_H
