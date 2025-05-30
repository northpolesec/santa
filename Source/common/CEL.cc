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

#include "Source/common/CEL.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "cel/expr/checked.pb.h"
#include "common/ast_proto.h"
#include "compiler/compiler_factory.h"
#include "compiler/standard_library.h"
#include "eval/public/activation_bind_helper.h"
#include "eval/public/builtin_func_registrar.h"
#include "eval/public/cel_expr_builder_factory.h"
#include "eval/public/cel_function_adapter.h"

namespace cel_runtime = ::google::api::expr::runtime;
namespace syncv1 = ::santa::sync::v1;
namespace pbv1 = ::santa::cel::v1;

namespace santa {

// Creates a CEL Activation with the static and dynamic contexts attached
// appropriately.
absl::StatusOr<cel_runtime::Activation> CreateActivation(
    ::pbv1::CELStaticContext *static_context,
    ::pbv1::CELDynamicContext * (^dynamicBlock)(
        ::google::protobuf::Arena *arena)) {
  cel_runtime::Activation activation;

  if (dynamicBlock) {
    absl::StatusOr<std::unique_ptr<cel_runtime::CelFunction>> getArgsFunction =
        cel_runtime::FunctionAdapter<::pbv1::CELDynamicContext *>::Create(
            "getDynamic", false,
            std::function<::pbv1::CELDynamicContext *(
                ::google::protobuf::Arena *)>(
                [dynamicBlock](::google::protobuf::Arena *arena)
                    -> ::pbv1::CELDynamicContext * {
                  return dynamicBlock(arena);
                }));
    if (!getArgsFunction.ok()) {
      return getArgsFunction.status();
    }

    if (auto result =
            activation.InsertFunction(std::move(getArgsFunction.value()));
        !result.ok()) {
      return result;
    }
  }

  google::protobuf::Arena arena;
  if (auto result = BindProtoToActivation(
          static_context, &arena, &activation,
          cel_runtime::ProtoUnsetFieldOptions::kBindDefault);
      !result.ok()) {
    return result;
  }

  return activation;
}

absl::Status CELEvaluator::Initialize() {
  // Link the reflection for needed messages to that the CEL compiler can
  // recognize them.
  google::protobuf::LinkMessageReflection<::pbv1::CELStaticContext>();
  google::protobuf::LinkMessageReflection<::pbv1::CELDynamicContext>();
  // We need the Policy enum to be linked in and the library doesn't seem to
  // have a way to force enum reflection to be linked, so we're using the Rule
  // message as that contains a field that uses Policy.
  google::protobuf::LinkMessageReflection<::syncv1::Rule>();

  // Create a compiler builder with the generated descriptor pool for protos.
  absl::StatusOr<std::unique_ptr<::cel::CompilerBuilder>> builderStatus =
      ::cel::NewCompilerBuilder(
          google::protobuf::DescriptorPool::generated_pool());
  if (!builderStatus.ok()) {
    return builderStatus.status();
  }
  auto builder = std::move(builderStatus.value());

  // Add the standard library.
  if (auto result = builder->AddLibrary(::cel::StandardCompilerLibrary());
      !result.ok()) {
    return result;
  }

  ::cel::TypeCheckerBuilder &checker_builder = builder->GetCheckerBuilder();

  // Add the static context type. The value will be bound during activation.
  if (auto result = checker_builder.AddContextDeclaration(
          ::pbv1::CELStaticContext::descriptor()->full_name());
      !result.ok()) {
    return result;
  }

  // Add the single getDynamic function overload.
  // The implementation will be bound during activation.
  absl::StatusOr<::cel::FunctionDecl> decl = ::cel::MakeFunctionDecl(
      "getDynamic",
      ::cel::MakeOverloadDecl(
          "getDynamic",
          ::cel::MessageType(::pbv1::CELDynamicContext::descriptor())));
  if (!decl.ok()) {
    return decl.status();
  }
  if (absl::Status result = checker_builder.MergeFunction(decl.value());
      !result.ok()) {
    return result;
  }

  // Build and store the compiler.
  absl::StatusOr<std::unique_ptr<::cel::Compiler>> compiler = builder->Build();
  if (!compiler.ok()) {
    return compiler.status();
  }
  compiler_ = std::move(compiler.value());
  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<::cel_runtime::CelExpression>>
CELEvaluator::Compile(absl::string_view expr) {
  if (!compiler_) {
    return absl::InvalidArgumentError(
        "CELEvaluator::Initialize() must be called before Compile()");
  }

  // Compile the expression.
  absl::StatusOr<::cel::ValidationResult> result = compiler_->Compile(expr);
  if (!result.ok()) {
    return absl::Status(std::move(result.status()));
  }
  if (!result.value().IsValid() || result.value().GetAst() == nullptr) {
    return absl::InvalidArgumentError(result.value().FormatError());
  }

  // Check the AST for correctness.
  ::cel::expr::CheckedExpr cel_expr;
  if (absl::Status status =
          ::cel::AstToCheckedExpr(*result.value().GetAst(), &cel_expr);
      !status.ok()) {
    return status;
  }

  // Setup a default environment for building expressions.
  cel_runtime::InterpreterOptions options;
  std::unique_ptr<cel_runtime::CelExpressionBuilder> builder =
      CreateCelExpressionBuilder(
          google::protobuf::DescriptorPool::generated_pool(),
          google::protobuf::MessageFactory::generated_factory(), options);

  // Register the builtin functions.
  if (auto result = RegisterBuiltinFunctions(builder->GetRegistry(), options);
      !result.ok()) {
    return result;
  }

  // Register the getDynamic function.
  if (auto result = builder->GetRegistry()->RegisterLazyFunction(
          ::cel::FunctionDescriptor("getDynamic", false, {}));
      !result.ok()) {
    return result;
  }

  // Create an expression plan with the checked expression.
  absl::StatusOr<std::unique_ptr<cel_runtime::CelExpression>> expression_plan =
      builder->CreateExpression(&cel_expr);
  return expression_plan;
};

absl::StatusOr<::santa::sync::v1::Policy> CELEvaluator::Evaluate(
    const ::cel_runtime::CelExpression *expression_plan,
    ::pbv1::CELStaticContext *static_context,
    ::pbv1::CELDynamicContext * (^dynamicBlock)(
        ::google::protobuf::Arena *arena)) {
  // Create an activation with the static and dynamic contexts.
  absl::StatusOr<cel_runtime::Activation> activation =
      CreateActivation(static_context, dynamicBlock);
  if (!activation.ok()) {
    return activation.status();
  }
  // Evaluate the parsed expression.
  google::protobuf::Arena arena;
  absl::StatusOr<cel_runtime::CelValue> result =
      expression_plan->Evaluate(std::move(activation.value()), &arena);
  if (!result.ok()) {
    return result.status();
  }

  // Check the result type.
  // A bool value will return ALLOWLIST for true and BLOCKLIST for false.
  // A Policy value will be returned as-is
  // Everything else is an error.
  if (bool value; result.value().GetValue(&value)) {
    if (value) {
      return syncv1::ALLOWLIST;
    }
    return syncv1::BLOCKLIST;
  } else if (int64_t value; result.value().GetValue(&value) &&
                            syncv1::Policy_IsValid((int)value)) {
    auto policy = static_cast<syncv1::Policy>(value);
    return policy;
  } else if (const cel_runtime::CelError * value;
             result.value().GetValue(&value)) {
    return *value;
  } else {
    return absl::InvalidArgumentError(
        absl::StrCat("expected 'santa.sync.v1.Policy' result got '",
                     result.value().DebugString(), "'"));
  }
}

absl::StatusOr<::santa::sync::v1::Policy> CELEvaluator::CompileAndEvaluate(
    absl::string_view cel_expr, ::pbv1::CELStaticContext *static_context,
    ::pbv1::CELDynamicContext * (^dynamicBlock)(
        ::google::protobuf::Arena *arena)) {
  absl::StatusOr<std::unique_ptr<::cel_runtime::CelExpression>> expr =
      Compile(cel_expr);
  if (!expr.ok()) {
    return expr.status();
  }
  return Evaluate(expr.value().get(), static_context, dynamicBlock);
}

}  // namespace santa
