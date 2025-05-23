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

#include "Source/common/CEL.pb.h"

#include <memory>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "sync/v1.pb.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "cel/expr/checked.pb.h"
#include "compiler/compiler.h"
#include "eval/public/cel_expression.h"
#pragma clang diagnostic pop

namespace santa {

class CELEvaluator {
 public:
  // Initialize the evaluator. This must be called before any other methods as
  // it initializes the CEL compiler.
  absl::Status Initialize();

  // Compile a CEL expression from a string into an expression plan
  // ready for evaluation. These expression plans could be cached.
  absl::StatusOr<std::unique_ptr<::google::api::expr::runtime::CelExpression>> Compile(
      absl::string_view cel_expr);

  // Evaluate an expression plan against a static and dynamic context.
  //
  // The static context is all of the fields that will not change between
  // executions of a given binary and can safely be cached.
  //
  // If the optional `dynamicBlock` block is provided and the expression uses
  // uses the `getDynamic` function, the block will be called to retireve the
  // dynamic context. Evaluations that make use of this dynamic context should
  // not be cached.
  absl::StatusOr<::santa::sync::v1::Policy> Evaluate(
      ::google::api::expr::runtime::CelExpression const *expression_plan,
      ::santa::cel::v1::CELStaticContext *static_context,
      ::santa::cel::v1::CELDynamicContext * (^dynamicBlock)(::google::protobuf::Arena *arena));

  // Convenience method that combines Compile() and Evaluate() into a single call.
  absl::StatusOr<::santa::sync::v1::Policy> CompileAndEvaluate(
      absl::string_view cel_expr, ::santa::cel::v1::CELStaticContext *static_context,
      ::santa::cel::v1::CELDynamicContext * (^dynamicBlock)(::google::protobuf::Arena *arena));

  CELEvaluator() = default;
  ~CELEvaluator() = default;

  CELEvaluator(CELEvaluator &&other) = default;
  CELEvaluator &operator=(CELEvaluator &&rhs) = default;

  // Could be safe to implement these, but not currently needed
  CELEvaluator(const CELEvaluator &other) = delete;
  CELEvaluator &operator=(const CELEvaluator &other) = delete;

 private:
  std::unique_ptr<::cel::Compiler> compiler_;
};

}  // namespace santa

#endif  // SANTA__COMMON__CEL_H
