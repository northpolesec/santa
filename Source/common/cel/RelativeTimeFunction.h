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

#ifndef SANTA_COMMON_CEL_RELATIVETIMEFUNCTION_H
#define SANTA_COMMON_CEL_RELATIVETIMEFUNCTION_H

#include "absl/status/status.h"
#include "absl/types/span.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "compiler/compiler.h"
#include "eval/public/cel_function.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_options.h"
#include "eval/public/cel_value.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// Relative-time helpers for CELv2 rules. Together they let rules compare a
// file's signing time against a sliding window using native CEL timestamp and
// duration arithmetic, e.g.:
//
//     target.secure_signing_time > today() - days(90)
//
//   today() -> google.protobuf.Timestamp
//     The start of the current UTC day (00:00:00Z), truncated to a whole day
//     rather than the literal current instant. Because its value changes at the
//     next UTC midnight, any expression that uses it is marked non-cacheable.
//     Registered as a lazy function so it is never constant-folded (folding
//     would freeze the date at compile time) and so the Activation that vends
//     it can flag the evaluation as non-cacheable.
//
//   days(int) -> google.protobuf.Duration
//     n*24h as a duration. CEL's native duration() only parses up to hours, so
//     this is sugar for the common "N days" window. Pure and foldable.
//
//   now() -> google.protobuf.Timestamp
//     The current instant, with no truncation. Like today() it is lazy and
//     marks the evaluation non-cacheable, e.g. a window relative to the moment
//     of the exec: now() + duration("30m").
//
//   weekdays() -> list<int>
//     The constant [1, 2, 3, 4, 5]: Monday through Friday in the day-of-week
//     numbering 0=Sunday through 6=Saturday. Pure and foldable, so it does not
//     affect cacheability.

// Descriptor for the today() -> Timestamp function (zero args, lazy).
::google::api::expr::runtime::CelFunctionDescriptor TodayDescriptor();

// Descriptor for the now() -> Timestamp function (zero args, lazy).
::google::api::expr::runtime::CelFunctionDescriptor NowDescriptor();

// Lazy CEL function backing today(). On evaluation it returns the start of the
// current UTC day and sets the supplied flag to true to mark the evaluation as
// non-cacheable. The sink pointer must outlive every evaluation.
class TodayFunction : public ::google::api::expr::runtime::CelFunction {
 public:
  explicit TodayFunction(bool* used_sink)
      : ::google::api::expr::runtime::CelFunction(TodayDescriptor()),
        used_sink_(used_sink) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
};

// Lazy CEL function backing now(). On evaluation it returns the current instant
// and sets the supplied flag to true to mark the evaluation as non-cacheable.
// The sink pointer must outlive every evaluation.
class NowFunction : public ::google::api::expr::runtime::CelFunction {
 public:
  explicit NowFunction(bool* used_sink)
      : ::google::api::expr::runtime::CelFunction(NowDescriptor()),
        used_sink_(used_sink) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
};

// Register the today(), days(), now() and weekdays() decls with the type
// checker at compile time. Only available in CELv2.
absl::Status AddRelativeTimeCompilerLibrary(::cel::CompilerBuilder& builder);

// Register relative-time functions at runtime. today() and now() are registered
// as lazy functions (their implementations are provided by the Activation, see
// Activation::FindFunctionOverloads); days() and weekdays() are normal eager
// functions.
// Only available in CELv2.
absl::Status RegisterRelativeTimeFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry* registry,
    const ::google::api::expr::runtime::InterpreterOptions& options);

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_RELATIVETIMEFUNCTION_H
