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

#include "Source/common/cel/AuthCooldownFunction.h"

#include <cstdint>
#include <string>
#include <utility>

#include "Source/common/cel/result.pb.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
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

// The authorization policies that take a cooldown argument. Each has a plain
// enum constant of the same name (e.g. REQUIRE_TOUCHID), which CEL exposes
// automatically; these functions exist only to attach a cooldown to it.
constexpr struct {
  const char* name;
  ::santa::cel::v2::ReturnValue value;
} kAuthCooldownPolicies[] = {
    {"require_touchid", ::santa::cel::v2::REQUIRE_TOUCHID},
    {"require_touchid_only", ::santa::cel::v2::REQUIRE_TOUCHID_ONLY},
    {"require_security_key", ::santa::cel::v2::REQUIRE_SECURITY_KEY},
    {"require_security_key_only", ::santa::cel::v2::REQUIRE_SECURITY_KEY_ONLY},
    {"require_presence", ::santa::cel::v2::REQUIRE_PRESENCE},
    {"require_presence_only", ::santa::cel::v2::REQUIRE_PRESENCE_ONLY},
};

// The CEL function name and overload id for a policy, e.g.
// "require_presence_with_cooldown_minutes" and
// "require_presence_with_cooldown_minutes_int".
std::string CooldownFunctionName(const char* policy) {
  return absl::StrCat(policy, "_with_cooldown_minutes");
}

std::string CooldownOverloadID(const char* policy) {
  return absl::StrCat(CooldownFunctionName(policy), "_int");
}

absl::Status RegisterAuthCooldownDecls(::cel::TypeCheckerBuilder& builder) {
  // Get the Result message type from the descriptor
  auto result_type = MessageType(::santa::cel::Result::descriptor());

  for (const auto& policy : kAuthCooldownPolicies) {
    CEL_ASSIGN_OR_RETURN(
        auto decl, MakeFunctionDecl(
                       CooldownFunctionName(policy.name),
                       MakeOverloadDecl(CooldownOverloadID(policy.name), result_type, IntType())));
    CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(decl)));
  }

  return absl::OkStatus();
}

}  // namespace

absl::Status AddAuthCooldownCompilerLibrary(::cel::CompilerBuilder& builder) {
  return builder.AddLibrary(
      ::cel::CompilerLibrary::FromCheckerLibrary({"auth_cooldown", &RegisterAuthCooldownDecls}));
}

absl::Status RegisterAuthCooldownFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry* registry,
    const ::google::api::expr::runtime::InterpreterOptions& options) {
  auto& func_registry = registry->InternalGetRegistry();

  for (const auto& policy : kAuthCooldownPolicies) {
    auto impl = [value = policy.value](int64_t minutes, const google::protobuf::DescriptorPool*,
                                       google::protobuf::MessageFactory*,
                                       google::protobuf::Arena* arena) {
      auto* result = google::protobuf::Arena::Create<::santa::cel::Result>(arena);
      result->set_value(value);
      result->set_cooldown_minutes(minutes >= 0 ? static_cast<uint64_t>(minutes) : 0);
      return StructValue(ParsedMessageValue(result, arena));
    };
    CEL_RETURN_IF_ERROR((::cel::UnaryFunctionAdapter<StructValue, int64_t>::RegisterGlobalOverload(
        CooldownFunctionName(policy.name), std::move(impl), func_registry)));
  }

  return absl::OkStatus();
}

}  // namespace cel
}  // namespace santa
