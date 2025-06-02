/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__COMMON__CEL_H
#define SANTA__COMMON__CEL_H

#include <memory>

#include "Source/common/cel/cel.pb.h"
#include "Source/common/cel/context.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "cel/expr/checked.pb.h"
#include "compiler/compiler.h"
#include "eval/public/cel_expression.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

class Evaluator {
 public:
  static absl::StatusOr<std::unique_ptr<Evaluator>> Create();

  Evaluator(std::unique_ptr<::cel::Compiler> compiler,
            std::unique_ptr<google::protobuf::Arena> arena)
      : arena_(std::move(arena)), compiler_(std::move(compiler)) {};
  ~Evaluator() = default;

  Evaluator(Evaluator &&other) = default;
  Evaluator &operator=(Evaluator &&rhs) = default;

  // Could be safe to implement these, but not currently needed
  Evaluator(const Evaluator &other) = delete;
  Evaluator &operator=(const Evaluator &other) = delete;

  // Compile a CEL expression from a string into an expression plan
  // ready for evaluation. These expression plans could be cached.
  absl::StatusOr<std::unique_ptr<::google::api::expr::runtime::CelExpression>>
  Compile(absl::string_view cel_expr);

  // Evaluate an expression plan with a SantaActivation object.
  absl::StatusOr<::santa::cel::v1::ReturnValue> Evaluate(
      ::google::api::expr::runtime::CelExpression const *expression_plan,
      const SantaActivation &activation);

  // Convenience method that combines Compile() and Evaluate() into a single
  // call.
  absl::StatusOr<::santa::cel::v1::ReturnValue> CompileAndEvaluate(
      absl::string_view cel_expr, const SantaActivation &activation);

 private:
  std::unique_ptr<google::protobuf::Arena> arena_;
  std::unique_ptr<::cel::Compiler> compiler_;
};

}  // namespace cel
}  // namespace santa

#endif  // SANTA__COMMON__CEL_H
