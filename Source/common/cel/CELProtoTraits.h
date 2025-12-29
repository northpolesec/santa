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

#ifndef SANTA__COMMON__CEL__CELPROTOTRAITS_H
#define SANTA__COMMON__CEL__CELPROTOTRAITS_H

#include <type_traits>

#include "cel/v1.pb.h"
#include "celv2/v2.pb.h"

namespace santa {
namespace cel {

template <bool IsV2>
struct CELProtoTraits;

// V1
template <>
struct CELProtoTraits<false> {
  // Message types
  using ExecutionContextT = ::santa::cel::v1::ExecutionContext;
  using ExecutableFileT = ::santa::cel::v1::ExecutableFile;

  // Enum aliases
  using ReturnValue = ::santa::cel::v1::ReturnValue;
  static constexpr ReturnValue UNSPECIFIED = ::santa::cel::v1::UNSPECIFIED;
  static constexpr ReturnValue ALLOWLIST = ::santa::cel::v1::ALLOWLIST;
  static constexpr ReturnValue ALLOWLIST_COMPILER =
      ::santa::cel::v1::ALLOWLIST_COMPILER;
  static constexpr ReturnValue BLOCKLIST = ::santa::cel::v1::BLOCKLIST;
  static constexpr ReturnValue SILENT_BLOCKLIST =
      ::santa::cel::v1::SILENT_BLOCKLIST;

  // Descriptor accessors
  static const google::protobuf::EnumDescriptor* ReturnValue_descriptor() {
    return ::santa::cel::v1::ReturnValue_descriptor();
  }

  static const google::protobuf::Descriptor* ExecutionContext_descriptor() {
    return ::santa::cel::v1::ExecutionContext::descriptor();
  }
};

// V2
template <>
struct CELProtoTraits<true> {
  // Message types
  using ExecutionContextT = ::santa::cel::v2::ExecutionContext;
  using ExecutableFileT = ::santa::cel::v2::ExecutableFile;

  // Enum aliases
  using ReturnValue = ::santa::cel::v2::ReturnValue;
  static constexpr ReturnValue UNSPECIFIED = ::santa::cel::v2::UNSPECIFIED;
  static constexpr ReturnValue ALLOWLIST = ::santa::cel::v2::ALLOWLIST;
  static constexpr ReturnValue ALLOWLIST_COMPILER =
      ::santa::cel::v2::ALLOWLIST_COMPILER;
  static constexpr ReturnValue BLOCKLIST = ::santa::cel::v2::BLOCKLIST;
  static constexpr ReturnValue SILENT_BLOCKLIST =
      ::santa::cel::v2::SILENT_BLOCKLIST;
  static constexpr ReturnValue REQUIRE_TOUCHID =
      ::santa::cel::v2::REQUIRE_TOUCHID;

  // Descriptor accessors
  static const google::protobuf::EnumDescriptor* ReturnValue_descriptor() {
    return ::santa::cel::v2::ReturnValue_descriptor();
  }

  static const google::protobuf::Descriptor* ExecutionContext_descriptor() {
    return ::santa::cel::v2::ExecutionContext::descriptor();
  }
};

}  // namespace cel
}  // namespace santa

#endif  // SANTA__COMMON__CEL__CELPROTOTRAITS_H
