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

#include "Source/common/cel/AnnotationFunction.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "Source/common/cel/result.pb.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/decl.h"
#include "common/type.h"
#include "internal/status_macros.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

namespace {

// add_annotation() with a propagation argument; the short form drops it.
constexpr size_t kAddAnnotationFullArgCount = 3;
constexpr size_t kAddAnnotationShortArgCount = 2;
constexpr size_t kPropagationIndex = 1;

absl::Status RegisterAnnotationDecls(::cel::TypeCheckerBuilder& builder) {
  // The policy argument and the return value are santa.cel.Result, which is
  // what the policy names (ALLOWLIST and friends) bind as in V2, so
  // add_annotation() can wrap a composite policy such as
  // require_touchid_with_cooldown_minutes(30) and hand it back untouched.
  auto resultType = ::cel::MessageType(::santa::cel::Result::descriptor());

  auto nameList = ::cel::ListType(builder.arena(), ::cel::StringType());

  // The overload ids are matched by the sync server's version gate, so they are
  // part of the interface and must not be renamed.
  CEL_ASSIGN_OR_RETURN(
      auto addDecl,
      ::cel::MakeFunctionDecl(
          "add_annotation",
          ::cel::MakeOverloadDecl("add_annotation_string_int_result", resultType,
                                  ::cel::StringType(), ::cel::IntType(), resultType),
          ::cel::MakeOverloadDecl("add_annotation_string_result", resultType, ::cel::StringType(),
                                  resultType),
          ::cel::MakeOverloadDecl("add_annotation_list_int_result", resultType, nameList,
                                  ::cel::IntType(), resultType),
          ::cel::MakeOverloadDecl("add_annotation_list_result", resultType, nameList, resultType)));
  CEL_ASSIGN_OR_RETURN(
      auto hasDecl,
      ::cel::MakeFunctionDecl("has_annotation",
                              ::cel::MakeOverloadDecl("has_annotation_string", ::cel::BoolType(),
                                                      ::cel::StringType())));

  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(addDecl)));
  return builder.AddFunction(std::move(hasDecl));
}

}  // namespace

std::vector<cel_runtime::CelFunctionDescriptor> HasAnnotationDescriptors() {
  using Type = cel_runtime::CelValue::Type;
  return {
      cel_runtime::CelFunctionDescriptor("has_annotation", /*receiver_style=*/false,
                                         /*types=*/{Type::kString},
                                         /*is_strict=*/true),
  };
}

std::vector<cel_runtime::CelFunctionDescriptor> AddAnnotationDescriptors() {
  using Type = cel_runtime::CelValue::Type;
  // The policy argument is a message, which is kStruct in the runtime's kinds.
  // Dispatch is unambiguous: the two arities separate the forms that name a
  // propagation from the ones that default it, and kString vs kList separates
  // one name from a list of them.
  return {
      cel_runtime::CelFunctionDescriptor("add_annotation", /*receiver_style=*/false,
                                         /*types=*/{Type::kString, Type::kInt64, Type::kStruct},
                                         /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("add_annotation", /*receiver_style=*/false,
                                         /*types=*/{Type::kString, Type::kStruct},
                                         /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("add_annotation", /*receiver_style=*/false,
                                         /*types=*/{Type::kList, Type::kInt64, Type::kStruct},
                                         /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("add_annotation", /*receiver_style=*/false,
                                         /*types=*/{Type::kList, Type::kStruct},
                                         /*is_strict=*/true),
  };
}

absl::Status HasAnnotationFunction::Evaluate(absl::Span<const cel_runtime::CelValue> args,
                                             cel_runtime::CelValue* result,
                                             google::protobuf::Arena*) const {
  if (args.size() != 1) {
    return absl::InvalidArgumentError("has_annotation() expects a single name argument");
  }

  // The answer is a property of this process, not of the binary, so a cached
  // decision would leak one process's annotations onto another.
  *used_sink_ = true;

  bool present = false;
  if (hooks_.has) {
    present = hooks_.has(std::string(args[0].StringOrDie().value()));
  }
  *result = cel_runtime::CelValue::CreateBool(present);
  return absl::OkStatus();
}

absl::Status AddAnnotationFunction::Evaluate(absl::Span<const cel_runtime::CelValue> args,
                                             cel_runtime::CelValue* result,
                                             google::protobuf::Arena* arena) const {
  if (args.size() != kAddAnnotationFullArgCount && args.size() != kAddAnnotationShortArgCount) {
    return absl::InvalidArgumentError("add_annotation() expects 2 or 3 arguments");
  }

  // The declared parameter is santa.cel.Result, but CEL lets a dyn expression
  // satisfy it, and any message is kStruct at runtime, so
  // add_annotation('X', [target, ALLOWLIST][0]) both type-checks and dispatches
  // here with an ExecutableFile as the policy. Evaluator rejects that, but only
  // after this function has returned, and with fail-closed off the failed
  // evaluation falls through to the fallback expressions -- where
  // has_annotation('X') would see a stamp left behind by an expression that
  // errored. Check before touching the tree.
  const cel_runtime::CelValue& policy = args.back();
  if (!policy.IsMessage() || policy.MessageOrDie() == nullptr ||
      policy.MessageOrDie()->GetDescriptor()->full_name() != "santa.cel.Result") {
    return absl::InvalidArgumentError("add_annotation() policy argument must be a return value");
  }

  // Annotating is a side effect on the process tree. A cached decision skips
  // evaluation on the next exec, which would silently stop stamping.
  *used_sink_ = true;

  AnnotationPropagation propagation = AnnotationPropagation::kForkAndExec;
  if (args.size() == kAddAnnotationFullArgCount) {
    int64_t raw = args[kPropagationIndex].Int64OrDie();
    bool known = false;
    for (const auto& [_, value] : kAnnotationPropagationNames) {
      if (static_cast<int64_t>(value) == raw) {
        propagation = value;
        known = true;
        break;
      }
    }
    if (!known) {
      return absl::InvalidArgumentError(
          absl::StrCat("add_annotation() got an unknown propagation value ", raw,
                       "; expected one of NONE, FORK_ONLY, EXEC_ONLY, FORK_AND_EXEC"));
    }
  }

  // Collect every name before stamping any, so a malformed list errors without
  // leaving a partial set of annotations behind. Held as strings rather than
  // views: the hook takes a string anyway, and this does not depend on how long
  // the list's own storage stays valid.
  std::vector<std::string> names;
  if (const cel_runtime::CelList* list; args[0].GetValue(&list)) {
    names.reserve(list->size());
    for (int i = 0; i < list->size(); i++) {
      cel_runtime::CelValue::StringHolder name;
      if (!list->Get(arena, i).GetValue(&name)) {
        return absl::InvalidArgumentError("add_annotation() name list must contain only strings");
      }
      names.emplace_back(name.value());
    }
  } else {
    names.emplace_back(args[0].StringOrDie().value());
  }

  if (hooks_.add) {
    for (const std::string& name : names) {
      hooks_.add(name, propagation);
    }
  }

  // Pass the policy through untouched so a composite policy keeps its fields.
  *result = policy;
  return absl::OkStatus();
}

absl::Status AddAnnotationCompilerLibrary(::cel::CompilerBuilder& builder) {
  return builder.AddLibrary(
      ::cel::CompilerLibrary::FromCheckerLibrary({"annotations", &RegisterAnnotationDecls}));
}

absl::Status RegisterAnnotationFunctions(cel_runtime::CelFunctionRegistry* registry,
                                         const cel_runtime::InterpreterOptions&) {
  // Lazy, like today(): the Activation vends the implementations, which is both
  // how they reach the process tree and how they mark the evaluation
  // non-cacheable.
  for (const auto& descriptor : HasAnnotationDescriptors()) {
    CEL_RETURN_IF_ERROR(registry->RegisterLazyFunction(descriptor));
  }
  for (const auto& descriptor : AddAnnotationDescriptors()) {
    CEL_RETURN_IF_ERROR(registry->RegisterLazyFunction(descriptor));
  }
  return absl::OkStatus();
}

}  // namespace cel
}  // namespace santa
