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
#include <type_traits>
#include <vector>

#include "Source/common/Memoizer.h"
#include "Source/common/cel/CELProtoTraits.h"

#include "absl/strings/string_view.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/type.h"
#include "eval/public/activation.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// SantaActivation is a CEL activation that provides lookups of values from the
// ExecutionContext message, and easy access to variables for return values.
template <bool IsV2>
class Activation : public ::google::api::expr::runtime::BaseActivation {
 public:
  using Traits = CELProtoTraits<IsV2>;
  using ExecutableFileT = typename Traits::ExecutableFileT;
  using ReturnValue = typename Traits::ReturnValue;
  using AncestorT = typename Traits::AncestorT;

  Activation(std::unique_ptr<ExecutableFileT> file, std::vector<std::string> (^args)(),
             std::map<std::string, std::string> (^envs)(), uid_t (^euid)(), std::string (^cwd)(),
             std::vector<AncestorT> (^ancestors)())
      : file_(std::move(file)),
        args_(args),
        envs_(envs),
        euid_(euid),
        cwd_(cwd),
        ancestors_(ancestors) {};
  ~Activation() = default;

  std::optional<::google::api::expr::runtime::CelValue> FindValue(
      absl::string_view name, google::protobuf::Arena *arena) const override;

  // Activation does not support lazy-loaded functions.
  std::vector<const ::google::api::expr::runtime::CelFunction *> FindFunctionOverloads(
      absl::string_view) const override {
    return {};
  }

  static std::vector<std::pair<absl::string_view, ::cel::Type>> GetVariables(
      google::protobuf::Arena *arena);

  template <bool V2>
  friend class Evaluator;

 private:
  std::unique_ptr<ExecutableFileT> file_;
  Memoizer<std::vector<std::string>> args_;
  Memoizer<std::map<std::string, std::string>> envs_;
  Memoizer<uid_t> euid_;
  Memoizer<std::string> cwd_;
  Memoizer<std::vector<AncestorT>> ancestors_;

  bool IsResultCacheable() const;

  static ::cel::Type CELType(google::protobuf::FieldDescriptor::CppType type,
                             const google::protobuf::Descriptor *messageType);

  template <typename T>
  static ::google::api::expr::runtime::CelValue CELValue(const T &v,
                                                         google::protobuf::Arena *arena);
  template <typename T>
  static ::google::api::expr::runtime::CelValue CELValue(const std::vector<T> &v,
                                                         google::protobuf::Arena *arena);
  template <typename K, typename V>
  static ::google::api::expr::runtime::CelValue CELValue(const std::map<K, V> &v,
                                                         google::protobuf::Arena *arena);
};

}  // namespace cel
}  // namespace santa

#endif
