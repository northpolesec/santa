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

#ifndef SANTA__COMMON__CEL__CONTEXT_H
#define SANTA__COMMON__CEL__CONTEXT_H

#include <map>
#include <vector>

#include "Source/common/Memoizer.h"
#include "cel/v1.pb.h"

#include "absl/strings/string_view.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/type.h"
#include "eval/public/activation.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;
namespace pbv1 = ::santa::cel::v1;

namespace santa {
namespace cel {

// SantaActivation is a CEL activation that provides lookups of values from the
// santa.pb.cel.v1.Context message, and easy access to variables for return values.
class Activation : public ::cel_runtime::BaseActivation {
 public:
  Activation(std::unique_ptr<::pbv1::ExecutableFile> file, std::vector<std::string> (^args)(),
             std::map<std::string, std::string> (^envs)())
      : file_(std::move(file)), args_(args), envs_(envs) {};
  ~Activation() = default;

  std::optional<cel_runtime::CelValue> FindValue(absl::string_view name,
                                                 google::protobuf::Arena *arena) const override;

  // Activation does not support lazy-loaded functions.
  std::vector<const cel_runtime::CelFunction *> FindFunctionOverloads(
      absl::string_view) const override {
    return {};
  }

  static std::vector<std::pair<absl::string_view, ::cel::Type>> GetVariables(
      google::protobuf::Arena *arena);

  friend class Evaluator;

 private:
  std::unique_ptr<::santa::cel::v1::ExecutableFile> file_;
  Memoizer<std::vector<std::string>> args_;
  Memoizer<std::map<std::string, std::string>> envs_;

  bool IsResultCacheable() const;

  static ::cel::Type CELType(google::protobuf::internal::FieldDescriptorLite::CppType type,
                             const google::protobuf::Descriptor *messageType);

  template <typename T>
  static cel_runtime::CelValue CELValue(const T &v, google::protobuf::Arena *arena);
  template <typename T>
  static cel_runtime::CelValue CELValue(const std::vector<T> &v, google::protobuf::Arena *arena);
  template <typename K, typename V>
  static cel_runtime::CelValue CELValue(const std::map<K, V> &v, google::protobuf::Arena *arena);
};

}  // namespace cel
}  // namespace santa

#endif
