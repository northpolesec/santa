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

#include "Source/common/cel/context.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "eval/public/containers/container_backed_list_impl.h"
#include "eval/public/containers/container_backed_map_impl.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#pragma clang diagnostic pop

#include <vector>

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

absl::optional<cel_runtime::CelValue> Activation::FindValue(absl::string_view name,
                                                            google::protobuf::Arena *arena) const {
  // Handle the ReturnValue values.
  auto retDescriptor = pbv1::ReturnValue_descriptor();
  auto retValue = retDescriptor->FindValueByName(name);
  if (retValue != nullptr) {
    return cel_runtime::CelValue::CreateInt64(retValue->number());
  }

  // Handle the fields from the CELContext message.
  if (name == "file" && file_ != nullptr) {
    return cel_runtime::CelProtoWrapper::CreateMessage(file_, arena);
  } else if (name == "args") {
    return CELValueFromVector(args_(), arena);
  } else if (name == "envs") {
    return CELValueFromVector(envs_(), arena);
  }

  return {};
}

std::vector<std::pair<absl::string_view, ::cel::Type>> Activation::GetVariables(
    google::protobuf::Arena *arena) {
  std::vector<std::pair<absl::string_view, ::cel::Type>> v;

  // Add variables for all of the return values so that users can use names like
  // ALLOWLIST or BLOCKLIST in their CEL expressions without having to use the
  // proto package name prefix. Start from value number 1 to avoid the
  // UNSPECIFIED value.
  auto retDescriptor = pbv1::ReturnValue_descriptor();
  for (int i = 1; i < retDescriptor->value_count(); i++) {
    auto value = retDescriptor->value(i);
    v.push_back({value->name(), ::cel::IntType()});
  }

  // Now add all the fields from the CELContext message.
  auto ctxDescriptor = pbv1::ExecutionContext::descriptor();
  for (int i = 0; i < ctxDescriptor->field_count(); i++) {
    auto field = ctxDescriptor->field(i);

    ::cel::Type type;
    switch (field->cpp_type()) {
      case ::google::protobuf::FieldDescriptor::CPPTYPE_STRING: type = ::cel::StringType(); break;
      case ::google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
        type = ::cel::MessageType(field->message_type());
        break;
      case ::google::protobuf::FieldDescriptor::CPPTYPE_INT64: [[fallthrough]];
      case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT64: [[fallthrough]];
      case ::google::protobuf::FieldDescriptor::CPPTYPE_INT32: [[fallthrough]];
      case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT32: [[fallthrough]];
      case ::google::protobuf::FieldDescriptor::CPPTYPE_ENUM: type = ::cel::IntType(); break;
      case ::google::protobuf::FieldDescriptor::CPPTYPE_BOOL: type = ::cel::BoolType(); break;
      case ::google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: [[fallthrough]];
      case ::google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: type = ::cel::DoubleType(); break;
    }

    if (field->is_repeated()) {
      type = ::cel::ListType(arena, type);
    }

    v.push_back({field->name(), type});
  }

  return v;
}

cel_runtime::CelValue Activation::CELValueFromVector(const std::vector<std::string> &v,
                                                     google::protobuf::Arena *arena) {
  std::vector<cel_runtime::CelValue> values;
  for (const auto &value : v) {
    values.push_back(cel_runtime::CelValue::CreateString(
        cel_runtime::CelValue::StringHolder(arena->Create<std::string>(arena, value))));
  }

  return cel_runtime::CelValue::CreateList(
      arena->Create<cel_runtime::ContainerBackedListImpl>(arena, values));
}

}  // namespace cel
}  // namespace santa
