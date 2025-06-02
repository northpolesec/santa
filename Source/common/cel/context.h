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

#ifndef SANTA__COMMON__CELCONTEXT_H
#define SANTA__COMMON__CELCONTEXT_H

#include "Source/common/cel/cel.pb.h"

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"

// CEL headers have warnings and our config turns them into errors.
// For some reason these can't be disabled with --per_file_copt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#include "common/type.h"
#include "eval/public/activation.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;
namespace pbv1 = ::santa::cel::v1;

namespace santa {
namespace cel {

// SantaActivation is a CEL activation that provides lookups of values from the
// santa.pb.cel.v1.Context message, and easy access to variables for return values.
class SantaActivation : public ::cel_runtime::BaseActivation {
 public:
  SantaActivation(const ::pbv1::FileContext *file, std::vector<std::string> (^args)(),
                  std::vector<std::string> (^envs)())
      : file_(file), args_(args), envs_(envs) {};
  ~SantaActivation() = default;

  absl::optional<cel_runtime::CelValue> FindValue(absl::string_view name,
                                                  google::protobuf::Arena *arena) const override;

  // SantaActivation does not support lazy-loaded functions.
  std::vector<const cel_runtime::CelFunction *> FindFunctionOverloads(
      absl::string_view) const override {
    return {};
  }

  static std::vector<std::pair<absl::string_view, ::cel::Type>> GetVariables(
      google::protobuf::Arena *arena);

 private:
  const ::santa::cel::v1::FileContext *file_;
  std::vector<std::string> (^args_)();
  std::vector<std::string> (^envs_)();

  static cel_runtime::CelValue CELValueFromVector(const std::vector<std::string> &v,
                                                  google::protobuf::Arena *arena);
};

}  // namespace cel
}  // namespace santa

#endif
