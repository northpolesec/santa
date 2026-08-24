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

#ifndef SANTA_COMMON_CEL_POLICYFORRANGEFUNCTION_H
#define SANTA_COMMON_CEL_POLICYFORRANGEFUNCTION_H

#include <cstdint>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
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

// policy_for_range() gates a rule on a time window: it returns one policy while
// the window is open and another while it is closed.
//
//   policy_for_range(list<int> days, string start, string end,
//                    bool should_kill, policy, out_of_range_policy)
//   policy_for_range(list<int> days, timestamp start, timestamp end,
//                    bool should_kill, policy, out_of_range_policy)
//   policy_for_range(duration d, bool should_kill, policy)
//
// The bare call is a complete expression, e.g.
//
//     policy_for_range(weekdays(), "09:00", "17:00", false,
//                      ALLOWLIST, BLOCKLIST)
//
// Both policy arguments and the return value are santa.cel.Result, the type the
// policy names (ALLOWLIST and friends) bind as in V2, so a composite policy
// such as require_touchid_with_cooldown_minutes(30) can sit in either position
// and is passed through untouched.
//
// Days are 0=Sunday through 6=Saturday, matching getDayOfWeek(). For the HH:MM
// overload the window is interpreted in the host's local time zone, an `end` at
// or before `start` crosses midnight, and the day list applies to the day the
// window starts. For the timestamp overload the day check applies to the
// evaluation instant. The duration overload is [now, now + d), which always
// holds at evaluation, so it takes no out_of_range_policy.
//
// should_kill asks for anything still running when the window closes to be
// quit. It is type-checked but has no effect yet.
//
// Every evaluation reads the current time, so any use marks the result
// non-cacheable, exactly like today(): the next exec re-evaluates and the
// window edge enforces itself.

// The result of testing a window at one instant.
struct WindowEval {
  bool in_range;
  // End of the current occurrence; meaningful when in_range.
  absl::Time window_end;
  // Length of that occurrence, for the notification lead formula.
  absl::Duration window_length;
};

// The window math, kept separate from the CEL plumbing so the calendar cases
// are testable directly and so the notification lead formula can reuse it.
//
// `days` holds day-of-week numbers, 0=Sunday through 6=Saturday; anything else
// is an error. `now` is the instant being asked about and `zone` the zone the
// civil times are read in.
absl::StatusOr<WindowEval> EvalDaysHHMMWindow(absl::Span<const int64_t> days,
                                              absl::string_view start,
                                              absl::string_view end,
                                              absl::Time now,
                                              absl::TimeZone zone);
absl::StatusOr<WindowEval> EvalDaysTimestampWindow(
    absl::Span<const int64_t> days, absl::Time start, absl::Time end,
    absl::Time now, absl::TimeZone zone);
// A duration window has no error case and is never out of range: [now, now + d)
// always contains now. Callers reject a non-positive d before asking.
WindowEval EvalDurationWindow(absl::Duration d, absl::Time now);

// Descriptors for the three policy_for_range() overloads, all registered
// lazily.
std::vector<::google::api::expr::runtime::CelFunctionDescriptor>
PolicyForRangeDescriptors();

// Lazy CEL function backing one policy_for_range() overload. On evaluation it
// marks the result non-cacheable and returns whichever policy argument the
// window selects. The sink pointer must outlive every evaluation.
class PolicyForRangeFunction
    : public ::google::api::expr::runtime::CelFunction {
 public:
  PolicyForRangeFunction(
      ::google::api::expr::runtime::CelFunctionDescriptor descriptor,
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

// Register the policy_for_range() decls with the type checker at compile time.
// Only available in CELv2, and only for rules: fallback expressions have no
// rule identity for a window to attach to.
absl::Status AddPolicyForRangeCompilerLibrary(::cel::CompilerBuilder& builder);

// Register policy_for_range() at runtime. All three overloads are lazy: their
// implementations are provided by the Activation (see
// Activation::FindFunctionOverloads) so they are never constant-folded and can
// mark the evaluation non-cacheable.
// Only available in CELv2.
absl::Status RegisterPolicyForRangeFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry* registry,
    const ::google::api::expr::runtime::InterpreterOptions& options);

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_POLICYFORRANGEFUNCTION_H
