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

#ifndef SANTA__COMMON__CEL__TOUCHIDFUNCTION_H
#define SANTA__COMMON__CEL__TOUCHIDFUNCTION_H

#include "absl/status/status.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "compiler/compiler.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_options.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// Register TouchID cooldown functions at compile time (type checking).
// These functions are only available in CELv2.
absl::Status AddTouchIDCooldownCompilerLibrary(::cel::CompilerBuilder &builder);

// Register TouchID cooldown functions at runtime.
absl::Status RegisterTouchIDCooldownFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry *registry,
    const ::google::api::expr::runtime::InterpreterOptions &options);

}  // namespace cel
}  // namespace santa

#endif  // SANTA__COMMON__CEL__TOUCHIDFUNCTION_H
