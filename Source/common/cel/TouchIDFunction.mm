/// Copyright 2026 North Pole Security, Inc.
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

#include "Source/common/cel/TouchIDFunction.h"

#include <cstdint>

#include "Source/common/cel/result.pb.h"
#include "absl/status/status.h"
#include "celv2/v2.pb.h"
#include "google/protobuf/arena.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/decl.h"
#include "common/type.h"
#include "common/value.h"
#include "common/values/parsed_message_value.h"
#include "internal/status_macros.h"
#include "runtime/function_adapter.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

namespace {

using ::cel::FunctionDecl;
using ::cel::IntType;
using ::cel::MakeFunctionDecl;
using ::cel::MakeOverloadDecl;
using ::cel::MessageType;
using ::cel::ParsedMessageValue;
using ::cel::StructValue;

// Implementation of require_touchid_with_cooldown_minutes(int)
// Returns a Result message with REQUIRE_TOUCHID and the specified cooldown.
StructValue RequireTouchIDWithCooldownImpl(int64_t minutes,
                                           const google::protobuf::DescriptorPool *,
                                           google::protobuf::MessageFactory *,
                                           google::protobuf::Arena *arena) {
  auto *result = google::protobuf::Arena::Create<::santa::cel::Result>(arena);
  result->set_value(::santa::cel::v2::REQUIRE_TOUCHID);
  result->set_cooldown_minutes(minutes >= 0 ? static_cast<uint64_t>(minutes) : 0);
  return StructValue(ParsedMessageValue(result, arena));
}

// Implementation of require_touchid_only_with_cooldown_minutes(int)
// Returns a Result message with REQUIRE_TOUCHID_ONLY and the specified cooldown.
StructValue RequireTouchIDOnlyWithCooldownImpl(int64_t minutes,
                                               const google::protobuf::DescriptorPool *,
                                               google::protobuf::MessageFactory *,
                                               google::protobuf::Arena *arena) {
  auto *result = google::protobuf::Arena::Create<::santa::cel::Result>(arena);
  result->set_value(::santa::cel::v2::REQUIRE_TOUCHID_ONLY);
  result->set_cooldown_minutes(minutes >= 0 ? static_cast<uint64_t>(minutes) : 0);
  return StructValue(ParsedMessageValue(result, arena));
}

absl::Status RegisterTouchIDCooldownDecls(::cel::TypeCheckerBuilder &builder) {
  // Get the Result message type from the descriptor
  auto result_type = MessageType(::santa::cel::Result::descriptor());

  // require_touchid_with_cooldown_minutes(int) -> Result
  CEL_ASSIGN_OR_RETURN(
      auto require_touchid_decl,
      MakeFunctionDecl(
          "require_touchid_with_cooldown_minutes",
          MakeOverloadDecl("require_touchid_with_cooldown_minutes_int", result_type, IntType())));

  // require_touchid_only_with_cooldown_minutes(int) -> Result
  CEL_ASSIGN_OR_RETURN(
      auto require_touchid_only_decl,
      MakeFunctionDecl("require_touchid_only_with_cooldown_minutes",
                       MakeOverloadDecl("require_touchid_only_with_cooldown_minutes_int",
                                        result_type, IntType())));

  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(require_touchid_decl)));
  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(require_touchid_only_decl)));

  return absl::OkStatus();
}

}  // namespace

absl::Status AddTouchIDCooldownCompilerLibrary(::cel::CompilerBuilder &builder) {
  return builder.AddLibrary(::cel::CompilerLibrary::FromCheckerLibrary(
      {"touchid_cooldown", &RegisterTouchIDCooldownDecls}));
}

absl::Status RegisterTouchIDCooldownFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry *registry,
    const ::google::api::expr::runtime::InterpreterOptions &options) {
  auto &func_registry = registry->InternalGetRegistry();

  // Register require_touchid_with_cooldown_minutes(int) -> StructValue
  CEL_RETURN_IF_ERROR((::cel::UnaryFunctionAdapter<StructValue, int64_t>::RegisterGlobalOverload(
      "require_touchid_with_cooldown_minutes", &RequireTouchIDWithCooldownImpl, func_registry)));

  // Register require_touchid_only_with_cooldown_minutes(int) -> StructValue
  CEL_RETURN_IF_ERROR((::cel::UnaryFunctionAdapter<StructValue, int64_t>::RegisterGlobalOverload(
      "require_touchid_only_with_cooldown_minutes", &RequireTouchIDOnlyWithCooldownImpl,
      func_registry)));

  return absl::OkStatus();
}

}  // namespace cel
}  // namespace santa
