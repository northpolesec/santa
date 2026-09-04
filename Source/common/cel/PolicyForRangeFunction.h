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
#include <functional>
#include <optional>
#include <string>
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
//                    policy, out_of_range_policy)
//   policy_for_range(list<int> days, string start, string end, string zone,
//                    policy, out_of_range_policy)
//   policy_for_range(timestamp start, timestamp end,
//                    policy, out_of_range_policy)
//   policy_for_range(duration d, kill_on_expiry(policy))
//
// Policies are santa.cel.Result, so the policy names (ALLOWLIST and friends)
// and require_touchid_with_cooldown_minutes(30) fit either slot and pass
// through untouched. Wrapping the in-range policy in kill_on_expiry() asks for
// anything still running when the window closes to be quit; the wrapper only
// accepts policies that let a process start. The duration form is [now, now +
// d), which always holds at evaluation, so it exists only to place a deadline
// and is grant-only. A compile-time validation pass keeps kill_on_expiry() in
// the in-range slot of a call that produces the rule's result.
//
// Days are 0=Sunday through 6=Saturday. For both HH:MM overloads an `end` at or
// before `start` crosses midnight and the day list applies to the day the
// window starts. The timestamp overload takes absolute instants, so no day list
// and no zone. zone is "local" (the default), a [+-]HH:MM offset, or a name the
// platform's zone loader accepts, except names holding a colon or ".." or
// starting with "/", which the loader would open as a file.
//
// Timed kills are rule-scoped and honored for every execution rule type. Every
// evaluation reads the clock, so any use marks the result non-cacheable; that
// is load-bearing, because the kill quits the executions Santa recorded inside
// the window, and a cacheable windowed decision would let a process run
// unrecorded and so unkillable.

// The result of testing a window at one instant.
struct WindowEval {
  bool in_range;
  // End of the current occurrence; meaningful when in_range.
  absl::Time window_end;
  // Length of that occurrence, for the notification lead formula.
  absl::Duration window_length;
};

// Resolves a zone argument to a time zone: "local" is the host's zone,
// [+-]HH:MM is a signed fixed offset from UTC, and anything else goes to the
// platform's zone loader (IANA names, "UTC", and whatever else it takes),
// except that a name holding a colon or ".." or starting with "/" is rejected
// first: those are the loader's spellings that open a caller-named path as a
// tzfile ("file:<path>", "libc:*", absolute paths, traversal out of its
// zoneinfo directory). Anything unresolved is an error naming the string.
// Shared by policy_for_range() and today(zone) so the two cannot drift apart.
absl::StatusOr<absl::TimeZone> ResolveTimeZone(absl::string_view zone);

// Parses a strict 24-hour "HH:MM" into minutes after midnight, nullopt for
// anything else: the width is exact, so no "9:00", no seconds field, and hour
// and minute are in range. Exported for the same reason as ResolveTimeZone():
// santad checks the window shape it read back from its state file, and the
// strings it must accept are exactly the ones a window can be rebuilt from.
std::optional<int> ParseHourMinute(absl::string_view time);

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
// An absolute span has no calendar in it, so nothing to validate and no zone to
// read: it is [start, end) tested against `now`.
WindowEval EvalTimestampWindow(absl::Time start, absl::Time end,
                               absl::Time now);
// A duration window has no error case and is never out of range: [now, now + d)
// always contains now. Callers reject a non-positive d before asking.
WindowEval EvalDurationWindow(absl::Duration d, absl::Time now);

// How far before a window's close the user is warned: 10% of the occurrence's
// length, at least 5 minutes and at most an hour. A window shorter than the
// floor is warned about at launch, since the notify time never precedes the
// evaluation. One definition, so the evaluation that records a kill and the
// re-check that moves one to a later occurrence cannot disagree.
absl::Duration NotificationLead(absl::Duration window_length);

// The kill an in-window kill_on_expiry() asked for: quit what the rule covers
// at `deadline`, having warned at `notify_at`. The window shape is what a
// restart re-checks against: the zone string as written ("local" when the
// overload takes none), and empty for the non-recurring overloads.
struct PendingKill {
  absl::Time deadline;
  absl::Time notify_at;
  std::vector<int64_t> window_days;
  std::string window_start;
  std::string window_end;
  std::string window_zone;
};

// Descriptors for the four policy_for_range() argument counts (2, 4, 5 and 6),
// all registered lazily. The count is what the runtime dispatches on, and it
// covers the plain and grant overloads of a shape together.
std::vector<::google::api::expr::runtime::CelFunctionDescriptor>
PolicyForRangeDescriptors();

// Lazy CEL function backing one policy_for_range() overload. On evaluation it
// marks the result non-cacheable, returns whichever policy argument the window
// selects, and reports a pending kill when the window is open and the in-range
// policy is a Grant (keeping the earlier deadline if the same evaluation asks
// more than once). Both sink pointers must outlive every evaluation.
class PolicyForRangeFunction
    : public ::google::api::expr::runtime::CelFunction {
 public:
  PolicyForRangeFunction(
      ::google::api::expr::runtime::CelFunctionDescriptor descriptor,
      bool* used_sink, std::optional<PendingKill>* pending_kill_sink,
      std::function<absl::Time()> now)
      : ::google::api::expr::runtime::CelFunction(std::move(descriptor)),
        used_sink_(used_sink),
        pending_kill_sink_(pending_kill_sink),
        now_(std::move(now)) {}

  absl::Status Evaluate(
      absl::Span<const ::google::api::expr::runtime::CelValue> args,
      ::google::api::expr::runtime::CelValue* result,
      google::protobuf::Arena* arena) const override;

 private:
  bool* used_sink_;
  std::optional<PendingKill>* pending_kill_sink_;
  std::function<absl::Time()> now_;
};

// Declares policy_for_range() and kill_on_expiry() and installs the validation
// pass that keeps a wrapper in the in-range slot of a call on the rule's result
// path. Only available in CELv2, and only for rules: fallback expressions have
// no rule identity for a window to attach to.
absl::Status AddPolicyForRangeCompilerLibrary(::cel::CompilerBuilder& builder);

// Registers kill_on_expiry() eagerly and the four lazy policy_for_range()
// descriptors, whose implementations are provided by the Activation (see
// Activation::FindFunctionOverloads) so they are never constant-folded and can
// mark the evaluation non-cacheable and report a pending kill back through it.
// Only available in CELv2.
absl::Status RegisterPolicyForRangeFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry* registry,
    const ::google::api::expr::runtime::InterpreterOptions& options);

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_POLICYFORRANGEFUNCTION_H
