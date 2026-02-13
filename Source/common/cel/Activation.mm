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

#include "Source/common/cel/result.pb.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/type.h"
#include "eval/public/containers/container_backed_list_impl.h"
#include "eval/public/containers/container_backed_map_impl.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

// Helper functions for CELValue - these need to be specialized before being used in template
// methods

namespace {
template <typename T>
cel_runtime::CelValue CreateCELValue(const T &v, google::protobuf::Arena *arena);

template <>
[[maybe_unused]] cel_runtime::CelValue CreateCELValue<int>(const int &v,
                                                           google::protobuf::Arena *) {
  return cel_runtime::CelValue::CreateInt64(v);
}

template <>
[[maybe_unused]] cel_runtime::CelValue CreateCELValue<int64_t>(const int64_t &v,
                                                               google::protobuf::Arena *) {
  return cel_runtime::CelValue::CreateInt64(v);
}

template <>
[[maybe_unused]] cel_runtime::CelValue CreateCELValue<unsigned int>(const unsigned int &v,
                                                                    google::protobuf::Arena *) {
  return cel_runtime::CelValue::CreateUint64(v);
}

template <>
[[maybe_unused]] cel_runtime::CelValue CreateCELValue<bool>(const bool &v,
                                                            google::protobuf::Arena *) {
  return cel_runtime::CelValue::CreateBool(v);
}

template <>
[[maybe_unused]] cel_runtime::CelValue CreateCELValue<double>(const double &v,
                                                              google::protobuf::Arena *) {
  return cel_runtime::CelValue::CreateDouble(v);
}

template <>
[[maybe_unused]] cel_runtime::CelValue CreateCELValue<std::string>(const std::string &v,
                                                                   google::protobuf::Arena *arena) {
  return cel_runtime::CelValue::CreateString(
      cel_runtime::CelValue::StringHolder(arena->Create<std::string>(arena, v)));
}

template <typename T>
cel_runtime::CelValue CreateCELValue(const std::vector<T> &v, google::protobuf::Arena *arena) {
  std::vector<cel_runtime::CelValue> values;
  for (const auto &value : v) {
    values.push_back(CreateCELValue(value, arena));
  }
  return cel_runtime::CelValue::CreateList(
      arena->Create<cel_runtime::ContainerBackedListImpl>(arena, values));
}

template <typename K, typename V>
cel_runtime::CelValue CreateCELValue(const std::map<K, V> &v, google::protobuf::Arena *arena) {
  cel_runtime::CelMapBuilder *builder = arena->Create<cel_runtime::CelMapBuilder>(arena);
  for (const auto &pair : v) {
    (void)builder->Add(CreateCELValue(pair.first, arena), CreateCELValue(pair.second, arena));
  }
  return cel_runtime::CelValue::CreateMap(builder);
}

}  // namespace

// Template methods that delegate to the helper functions
template <bool IsV2>
template <typename T>
cel_runtime::CelValue Activation<IsV2>::CELValue(const T &v, google::protobuf::Arena *arena) {
  return CreateCELValue(v, arena);
}

template <bool IsV2>
template <typename T>
cel_runtime::CelValue Activation<IsV2>::CELValue(const std::vector<T> &v,
                                                 google::protobuf::Arena *arena) {
  return CreateCELValue(v, arena);
}

template <bool IsV2>
template <typename K, typename V>
cel_runtime::CelValue Activation<IsV2>::CELValue(const std::map<K, V> &v,
                                                 google::protobuf::Arena *arena) {
  return CreateCELValue(v, arena);
}

template <bool IsV2>
std::optional<cel_runtime::CelValue> Activation<IsV2>::FindValue(
    absl::string_view name, google::protobuf::Arena *arena) const {
  // Handle the ReturnValue values.
  auto retDescriptor = Traits::ReturnValue_descriptor();
  auto retValue = retDescriptor->FindValueByName(name);
  if (retValue != nullptr) {
    if constexpr (IsV2) {
      // For V2, return a Result message so that these values can
      // be mixed with composite returns from functions.
      auto *result = google::protobuf::Arena::Create<::santa::cel::Result>(arena);
      result->set_value(static_cast<::santa::cel::v2::ReturnValue>(retValue->number()));
      return cel_runtime::CelProtoWrapper::CreateMessage(result, arena);
    } else {
      return CELValue(retValue->number(), arena);
    }
  }

  // Handle the fields from the CELContext message.
  if (name == "target" && file_ != nullptr) {
    return cel_runtime::CelProtoWrapper::CreateMessage(file_.get(), arena);
  } else if (name == "args") {
    return CELValue(args_(), arena);
  } else if (name == "envs") {
    return CELValue(envs_(), arena);
  } else if (name == "euid") {
    return CELValue(euid_(), arena);
  } else if (name == "cwd") {
    return CELValue(cwd_(), arena);
  }

  // Handle the V2 specific fields
  if constexpr (IsV2) {
    if (name == "ancestors") {
      // Convert ancestors to CEL list of proto messages
      std::vector<cel_runtime::CelValue> ancestorValues;
      for (const auto &ancestor : ancestors_()) {
        // Create a copy of the proto on the arena and wrap it
        auto *proto = arena->Create<AncestorT>(arena);
        proto->CopyFrom(ancestor);
        ancestorValues.push_back(cel_runtime::CelProtoWrapper::CreateMessage(proto, arena));
      }
      return cel_runtime::CelValue::CreateList(
          arena->Create<cel_runtime::ContainerBackedListImpl>(arena, ancestorValues));
    }
  }
  return {};
}

template <bool IsV2>
std::vector<std::pair<absl::string_view, ::cel::Type>> Activation<IsV2>::GetVariables(
    google::protobuf::Arena *arena) {
  std::vector<std::pair<absl::string_view, ::cel::Type>> v;

  // Add variables for all of the return values so that users can use names like
  // ALLOWLIST or BLOCKLIST in their CEL expressions without having to use the
  // proto package name prefix. Start from value number 1 to avoid the
  // UNSPECIFIED value.
  auto retDescriptor = Traits::ReturnValue_descriptor();
  for (int i = 1; i < retDescriptor->value_count(); i++) {
    auto value = retDescriptor->value(i);
    if constexpr (IsV2) {
      // For V2, register as a Result message type so they can be mixed with
      // functions in ternary expressions.
      v.push_back({value->name(), ::cel::MessageType(::santa::cel::Result::descriptor())});
    } else {
      v.push_back({value->name(), ::cel::IntType()});
    }
  }

  // Now add all the fields from the CELContext message.
  auto ctxDescriptor = Traits::ExecutionContext_descriptor();
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

template <bool IsV2>
bool Activation<IsV2>::IsResultCacheable() const {
  if (args_.HasValue() || envs_.HasValue() || euid_.HasValue() || cwd_.HasValue()) {
    return false;
  }

  if constexpr (IsV2) {
    return !ancestors_.HasValue();
  }

  return true;
}

template <bool IsV2>
::cel::Type Activation<IsV2>::CELType(google::protobuf::FieldDescriptor::CppType type,
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

// Explicit template instantiations
template class Activation<false>;  // v1
template class Activation<true>;   // v2

}  // namespace cel
}  // namespace santa
