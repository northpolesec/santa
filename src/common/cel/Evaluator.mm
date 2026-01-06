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

#include "src/common/cel/Evaluator.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "cel/expr/checked.pb.h"
#include "cel/expr/syntax.pb.h"
#include "common/ast_proto.h"
#include "compiler/compiler_factory.h"
#include "compiler/standard_library.h"
#include "eval/public/activation_bind_helper.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/cel_function_adapter.h"
#include "eval/public/transform_utility.h"
#include "extensions/strings.h"
#include "parser/parser.h"

#include "src/common/cel/Activation.h"

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

template <bool IsV2>
static absl::StatusOr<std::unique_ptr<::cel::Compiler>> CreateCompiler(
    google::protobuf::Arena *arena) {
  // Create a compiler builder with the generated descriptor pool for protos.
  absl::StatusOr<std::unique_ptr<::cel::CompilerBuilder>> builderStatus =
      ::cel::NewCompilerBuilder(google::protobuf::DescriptorPool::generated_pool());
  if (!builderStatus.ok()) {
    return builderStatus.status();
  }
  auto builder = std::move(*builderStatus);

  // Add the standard library.
  if (auto result = builder->AddLibrary(::cel::StandardCompilerLibrary()); !result.ok()) {
    return result;
  }

  // Add the extensions for string operations like list join
  if (auto result = builder->AddLibrary(::cel::extensions::StringsCompilerLibrary());
      !result.ok()) {
    return result;
  }

  // Link the reflection for needed messages so that the CEL compiler can
  // recognize them.
  using ExecutionContextT = typename CELProtoTraits<IsV2>::ExecutionContextT;
  google::protobuf::LinkMessageReflection<ExecutionContextT>();

  // Add all the possible variables to the type checker.
  ::cel::TypeCheckerBuilder &checker_builder = builder->GetCheckerBuilder();
  for (const auto &variable : Activation<IsV2>::GetVariables(arena)) {
    if (auto result =
            checker_builder.AddVariable(::cel::MakeVariableDecl(variable.first, variable.second));
        !result.ok()) {
      return result;
    }
  }

  // Build and store the compiler.
  return builder->Build();
}

template <bool IsV2>
absl::StatusOr<std::unique_ptr<Evaluator<IsV2>>> Evaluator<IsV2>::Create() {
  std::unique_ptr<google::protobuf::Arena> arena = std::make_unique<google::protobuf::Arena>();

  auto compiler = CreateCompiler<IsV2>(arena.get());
  if (!compiler.ok()) {
    return compiler.status();
  }
  return std::make_unique<Evaluator<IsV2>>(std::move(*compiler), std::move(arena));
}

template <bool IsV2>
absl::StatusOr<std::unique_ptr<::cel_runtime::CelExpression>> Evaluator<IsV2>::Compile(
    absl::string_view expr) {
  if (!compiler_) {
    return absl::InvalidArgumentError("Evaluator not properly initialized");
  }

  // Compile the expression.
  absl::StatusOr<::cel::ValidationResult> result = compiler_->Compile(expr);
  if (!result.ok()) {
    return result.status();
  }
  if (!result->IsValid()) {
    return absl::InvalidArgumentError(result->FormatError());
  }

  // Check the AST for correctness.
  ::cel::expr::CheckedExpr cel_expr;
  if (absl::Status status = ::cel::AstToCheckedExpr(*result->GetAst(), &cel_expr); !status.ok()) {
    return status;
  }

  // Setup a default environment for building expressions.
  cel_runtime::InterpreterOptions options;
  options.constant_folding = true;
  options.constant_arena = arena_.get();
  options.enable_regex_precompilation = true;

  std::unique_ptr<cel_runtime::CelExpressionBuilder> builder =
      CreateCelExpressionBuilder(google::protobuf::DescriptorPool::generated_pool(),
                                 google::protobuf::MessageFactory::generated_factory(), options);

  // Register the builtin functions.
  if (auto result = RegisterBuiltinFunctions(builder->GetRegistry(), options); !result.ok()) {
    return result;
  }

  // Register string extension functions for runtime
  if (auto result = ::cel::extensions::RegisterStringsFunctions(builder->GetRegistry(), options);
      !result.ok()) {
    return result;
  }

  // Create an expression plan with the checked expression.
  absl::StatusOr<std::unique_ptr<cel_runtime::CelExpression>> expression_plan =
      builder->CreateExpression(&cel_expr);

  return expression_plan;
};

template <bool IsV2>
absl::StatusOr<std::pair<typename Evaluator<IsV2>::ReturnValue, bool>> Evaluator<IsV2>::Evaluate(
    const ::cel_runtime::CelExpression *expression_plan, const ActivationT &activation) {
  // Evaluate the parsed expression.
  absl::StatusOr<cel_runtime::CelValue> result =
      expression_plan->Evaluate(activation, arena_.get());
  if (!result.ok()) {
    return result.status();
  }

  // Check the result type.
  // A bool value will return ALLOWLIST for true and BLOCKLIST for false.
  // A Policy value will be returned as-is
  // Everything else is an error.
  if (bool value; result->GetValue(&value)) {
    if (value) {
      return {{Traits::ALLOWLIST, activation.IsResultCacheable()}};
    }
    return {{Traits::BLOCKLIST, activation.IsResultCacheable()}};
  } else if (int64_t value; result->GetValue(&value)) {
    // Check if the value is a valid ReturnValue enum
    auto descriptor = Traits::ReturnValue_descriptor();
    if (descriptor->FindValueByNumber((int)value) != nullptr) {
      return {{static_cast<ReturnValue>(value), activation.IsResultCacheable()}};
    }
  } else if (const cel_runtime::CelError * value; result->GetValue(&value)) {
    return absl::InvalidArgumentError(value->message());
  }

  return absl::InvalidArgumentError(
      absl::StrCat("expected 'ReturnValue' result got '", result->DebugString(), "'"));
}

template <bool IsV2>
absl::StatusOr<std::pair<typename Evaluator<IsV2>::ReturnValue, bool>>
Evaluator<IsV2>::CompileAndEvaluate(absl::string_view cel_expr, const ActivationT &activation) {
  absl::StatusOr<std::unique_ptr<::cel_runtime::CelExpression>> expr = Compile(cel_expr);
  if (!expr.ok()) {
    return expr.status();
  }
  return Evaluate(expr->get(), activation);
}

// Explicit template instantiations
template class Evaluator<false>;  // v1
template class Evaluator<true>;   // v2

}  // namespace cel
}  // namespace santa
