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

#include "Source/common/cel/Activation.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "eval/public/containers/container_backed_list_impl.h"
#include "eval/public/containers/container_backed_map_impl.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

template <>
cel_runtime::CelValue Activation::CELValue(const int &v, google::protobuf::Arena *unused_arena) {
  return cel_runtime::CelValue::CreateInt64(v);
}

template <>
cel_runtime::CelValue Activation::CELValue(const int64_t &v,
                                           google::protobuf::Arena *unused_arena) {
  return cel_runtime::CelValue::CreateInt64(v);
}

template <>
cel_runtime::CelValue Activation::CELValue(const bool &v, google::protobuf::Arena *unused_arena) {
  return cel_runtime::CelValue::CreateBool(v);
}

template <>
cel_runtime::CelValue Activation::CELValue(const double &v, google::protobuf::Arena *unused_arena) {
  return cel_runtime::CelValue::CreateDouble(v);
}

template <>
cel_runtime::CelValue Activation::CELValue(const std::string &v, google::protobuf::Arena *arena) {
  return cel_runtime::CelValue::CreateString(
      cel_runtime::CelValue::StringHolder(arena->Create<std::string>(arena, v)));
}

template <typename T>
cel_runtime::CelValue Activation::CELValue(const std::vector<T> &v,
                                           google::protobuf::Arena *arena) {
  std::vector<cel_runtime::CelValue> values;
  for (const auto &value : v) {
    values.push_back(CELValue(value, arena));
  }

  return cel_runtime::CelValue::CreateList(
      arena->Create<cel_runtime::ContainerBackedListImpl>(arena, values));
}

template <typename K, typename V>
cel_runtime::CelValue Activation::CELValue(const std::map<K, V> &v,
                                           google::protobuf::Arena *arena) {
  cel_runtime::CelMapBuilder *builder = arena->Create<cel_runtime::CelMapBuilder>(arena);
  for (const auto &pair : v) {
    (void)builder->Add(CELValue(pair.first, arena), CELValue(pair.second, arena));
  }
  return cel_runtime::CelValue::CreateMap(builder);
}

std::optional<cel_runtime::CelValue> Activation::FindValue(absl::string_view name,
                                                           google::protobuf::Arena *arena) const {
  // Handle the ReturnValue values.
  auto retDescriptor = pbv1::ReturnValue_descriptor();
  auto retValue = retDescriptor->FindValueByName(name);
  if (retValue != nullptr) {
    return CELValue(retValue->number(), arena);
  }

  // Handle the fields from the CELContext message.
  if (name == "target" && file_ != nullptr) {
    return cel_runtime::CelProtoWrapper::CreateMessage(file_, arena);
  } else if (name == "args") {
    return CELValue(args_(), arena);
  } else if (name == "envs") {
    return CELValue(envs_(), arena);
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
    if (field->is_map()) {
      auto msgType = field->message_type();
      auto key = msgType->field(0);
      auto value = msgType->field(1);
      type = ::cel::MapType(arena, CELType(key->cpp_type(), key->message_type()),
                            CELType(value->cpp_type(), value->message_type()));
    } else if (field->is_repeated()) {
      type = ::cel::ListType(arena, CELType(field->cpp_type(), field->message_type()));
    } else {
      type = CELType(field->cpp_type(), field->message_type());
    }

    v.push_back({field->name(), type});
  }

  return v;
}

bool Activation::IsResultCacheable() const {
  return !args_.HasValue() && !envs_.HasValue();
}

::cel::Type Activation::CELType(google::protobuf::internal::FieldDescriptorLite::CppType type,
                                const google::protobuf::Descriptor *messageType) {
  switch (type) {
    case ::google::protobuf::FieldDescriptor::CPPTYPE_STRING: return ::cel::StringType();
    case ::google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
      return ::cel::MessageType(messageType);
    case ::google::protobuf::FieldDescriptor::CPPTYPE_INT64: [[fallthrough]];
    case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT64: [[fallthrough]];
    case ::google::protobuf::FieldDescriptor::CPPTYPE_INT32: [[fallthrough]];
    case ::google::protobuf::FieldDescriptor::CPPTYPE_UINT32: [[fallthrough]];
    case ::google::protobuf::FieldDescriptor::CPPTYPE_ENUM: return ::cel::IntType();
    case ::google::protobuf::FieldDescriptor::CPPTYPE_BOOL: return ::cel::BoolType();
    case ::google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: [[fallthrough]];
    case ::google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: return ::cel::DoubleType();
  }
}

}  // namespace cel
}  // namespace santa
