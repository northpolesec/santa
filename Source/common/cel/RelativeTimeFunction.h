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

#include <functional>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/time/time.h"
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
//     The start of the current day in the host's local time zone by the system
//     clock, truncated to a whole day rather than the literal current instant.
//     Because its value changes at the next local midnight, any expression that
//     uses it is marked non-cacheable. Registered as a lazy function so it is
//     never constant-folded (folding would freeze the date at compile time)
//     and so the Activation that vends it can flag the evaluation as
//     non-cacheable.
//
//     Host local is a behavior change: today() shipped in 2026.6 as the start
//     of the current UTC day, and an already-deployed rule using it now crosses
//     its daily boundary at local midnight instead. The boundary moves by at
//     most the host's UTC offset and a mid-day evaluation still sees the same
//     day. The change makes today() agree with the HH:MM windows in
//     policy_for_range(), which are host local by default, instead of
//     contradicting them. Nothing about the interface moves: the sync server's
//     gate keys on its own today_timestamp overload, which is unchanged and
//     stays at its 2026.6 minimum.
//
//   today(string zone) -> google.protobuf.Timestamp
//     The start of the current civil day in the named zone, for the rules whose
//     calendar must be the same one fleet-wide. The zone string is the one
//     policy_for_range() takes ("local", an IANA name, or a [+-]HH:MM offset),
//     resolved by the same ResolveTimeZone() so the two cannot disagree. The
//     bare form is the "local" case of this same path. Both read this machine's
//     clock: today() is the date the host says it is, in the calendar asked
//     for.
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
//
// The two read different clocks, deliberately. today() is calendar truth and
// reads the system clock, as it has since before any of this existed: rules
// already depend on it meaning "the date this machine says it is", and moving
// it onto santad's believable clock would export that clock's roll-forward
// stickiness onto rules that never asked for a time window. It is therefore not
// rollback protected. now(), like policy_for_range(), reads the clock the
// Activation supplies, so a rule that does ask for a window gets one that a
// clock change cannot re-open.
//
// Mixing them is safe in the direction that matters. A today() edge handed to
// policy_for_range(), as in policy_for_range(weekdays(), today(), today() +
// days(1), ...), is tested for membership on the believable clock, so under
// skew the window reads as out of range and the rule falls to its
// out_of_range_policy: closed, not open. The other direction, a today()
// comparison outside any window, keeps exactly the exposure today() already
// had.

// Descriptors for the today() overloads, the bare form and today(zone), both
// lazy. The runtime picks between them by descriptor shape, so both have to be
// registered and both have to be vended by the Activation.
std::vector<::google::api::expr::runtime::CelFunctionDescriptor>
TodayDescriptors();

// Descriptor for the now() -> Timestamp function (zero args, lazy).
::google::api::expr::runtime::CelFunctionDescriptor NowDescriptor();

// Lazy CEL function backing one today() overload. On evaluation it returns the
// start of the current day by the system clock, in the host's zone or in the
// one its argument names, and sets the supplied flag to true to mark the
// evaluation as non-cacheable. Takes no clock: see above for why this one stays
// on the system clock. The sink pointer must outlive every evaluation.
class TodayFunction : public ::google::api::expr::runtime::CelFunction {
 public:
  TodayFunction(::google::api::expr::runtime::CelFunctionDescriptor descriptor,
                bool* used_sink)
      : ::google::api::expr::runtime::CelFunction(std::move(descriptor)),
        used_sink_(used_sink) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
};

// Lazy CEL function backing now(). On evaluation it returns `now` and sets the
// supplied flag to true to mark the evaluation as non-cacheable. The sink
// pointer must outlive every evaluation.
class NowFunction : public ::google::api::expr::runtime::CelFunction {
 public:
  NowFunction(bool* used_sink, std::function<absl::Time()> now)
      : ::google::api::expr::runtime::CelFunction(NowDescriptor()),
        used_sink_(used_sink),
        now_(std::move(now)) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
  std::function<absl::Time()> now_;
};

// Register the today(), today(zone), days(), now() and weekdays() decls with
// the type checker at compile time. Only available in CELv2.
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
