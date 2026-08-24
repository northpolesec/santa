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

#include "Source/common/cel/PolicyForRangeFunction.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <utility>
#include <vector>

#include "Source/common/cel/result.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/civil_time.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "google/protobuf/arena.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/decl.h"
#include "common/type.h"
#include "internal/status_macros.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

namespace {

// Argument layouts. The day-checked overloads are
// (days, start, end, should_kill, policy, out_of_range_policy) and the duration
// overload is (d, should_kill, policy). should_kill (index 3 and 1) is
// type-checked but not read: nothing acts on it yet.
constexpr size_t kDaysOverloadArgCount = 6;
constexpr size_t kDaysOverloadPolicyIndex = 4;
constexpr size_t kDaysOverloadOutOfRangePolicyIndex = 5;
constexpr size_t kDurationOverloadArgCount = 3;
constexpr size_t kDurationOverloadPolicyIndex = 2;

// Parses a strict 24-hour "HH:MM" into minutes after local midnight.
std::optional<int> ParseHourMinute(absl::string_view time) {
  if (time.size() != 5 || time[2] != ':') {
    return std::nullopt;
  }
  for (int index : {0, 1, 3, 4}) {
    if (time[index] < '0' || time[index] > '9') {
      return std::nullopt;
    }
  }

  int hour = (time[0] - '0') * 10 + (time[1] - '0');
  int minute = (time[3] - '0') * 10 + (time[4] - '0');
  if (hour > 23 || minute > 59) {
    return std::nullopt;
  }
  return hour * 60 + minute;
}

// 0=Sunday through 6=Saturday, matching getDayOfWeek() in both CEL engines.
int64_t DayOfWeek(absl::CivilDay day) {
  switch (absl::GetWeekday(day)) {
    case absl::Weekday::sunday: return 0;
    case absl::Weekday::monday: return 1;
    case absl::Weekday::tuesday: return 2;
    case absl::Weekday::wednesday: return 3;
    case absl::Weekday::thursday: return 4;
    case absl::Weekday::friday: return 5;
    case absl::Weekday::saturday: return 6;
  }
}

absl::Status ValidateDays(absl::Span<const int64_t> days) {
  for (int64_t day : days) {
    if (day < 0 || day > 6) {
      return absl::InvalidArgumentError(absl::StrCat(
          "policy_for_range() day must be 0 (Sunday) through 6 (Saturday), got ", day));
    }
  }
  return absl::OkStatus();
}

bool ContainsDay(absl::Span<const int64_t> days, absl::CivilDay day) {
  return std::find(days.begin(), days.end(), DayOfWeek(day)) != days.end();
}

// The instant a local civil time falls on. A DST transition makes the requested
// civil time either skipped or repeated; the transition instant is the
// well-defined answer for both. Because a window's closing edge and the next
// occurrence's opening edge are the same civil time, both land on that instant
// and back-to-back 24h occurrences stay exactly contiguous across the
// transition. The trade is that a window with both edges inside the skipped or
// repeated hour collapses to a zero-length range and is empty that day.
absl::Time LocalInstant(absl::CivilDay day, int minutesAfterMidnight, absl::TimeZone zone) {
  absl::TimeZone::TimeInfo info = zone.At(absl::CivilSecond(day) + minutesAfterMidnight * 60);
  return info.kind == absl::TimeZone::TimeInfo::UNIQUE ? info.pre : info.trans;
}

absl::StatusOr<std::vector<int64_t>> DayList(const cel_runtime::CelValue& value,
                                             google::protobuf::Arena* arena) {
  const cel_runtime::CelList* list = value.ListOrDie();

  std::vector<int64_t> days;
  days.reserve(list->size());
  for (int index = 0; index < list->size(); index++) {
    int64_t day;
    if (!list->Get(arena, index).GetValue(&day)) {
      return absl::InvalidArgumentError("policy_for_range() day list must contain only ints");
    }
    days.push_back(day);
  }
  return days;
}

absl::Status RegisterPolicyForRangeDecls(::cel::TypeCheckerBuilder& builder) {
  // Both policy arguments and the return value are santa.cel.Result, which is
  // what the policy names (ALLOWLIST and friends) bind as in V2. That is what
  // lets policy_for_range(..., require_touchid_with_cooldown_minutes(30),
  // BLOCKLIST) type-check.
  auto resultType = ::cel::MessageType(::santa::cel::Result::descriptor());
  auto dayList = ::cel::ListType(builder.arena(), ::cel::IntType());

  // The overload ids are matched by the sync server's version gate, so they are
  // part of the interface and must not be renamed.
  CEL_ASSIGN_OR_RETURN(
      auto decl,
      ::cel::MakeFunctionDecl(
          "policy_for_range",
          ::cel::MakeOverloadDecl("policy_for_range_days_string", resultType, dayList,
                                  ::cel::StringType(), ::cel::StringType(), ::cel::BoolType(),
                                  resultType, resultType),
          ::cel::MakeOverloadDecl("policy_for_range_days_timestamp", resultType, dayList,
                                  ::cel::TimestampType(), ::cel::TimestampType(), ::cel::BoolType(),
                                  resultType, resultType),
          ::cel::MakeOverloadDecl("policy_for_range_duration", resultType, ::cel::DurationType(),
                                  ::cel::BoolType(), resultType)));

  return builder.AddFunction(std::move(decl));
}

}  // namespace

// HH:MM in the given time zone. An end at or before the start crosses midnight,
// so the occurrence containing now may have begun yesterday; the day list
// applies to the day the window started.
absl::StatusOr<WindowEval> EvalDaysHHMMWindow(absl::Span<const int64_t> days,
                                              absl::string_view start, absl::string_view end,
                                              absl::Time now, absl::TimeZone zone) {
  if (absl::Status status = ValidateDays(days); !status.ok()) {
    return status;
  }

  std::optional<int> startMinutes = ParseHourMinute(start);
  std::optional<int> endMinutes = ParseHourMinute(end);
  if (!startMinutes || !endMinutes) {
    return absl::InvalidArgumentError(
        absl::StrCat("policy_for_range() expects HH:MM times, got '", start, "' and '", end, "'"));
  }

  absl::CivilDay currentDay{absl::ToCivilSecond(now, zone)};

  for (int dayOffset : {0, -1}) {
    absl::CivilDay startDay = currentDay + dayOffset;
    absl::CivilDay endDay = *endMinutes > *startMinutes ? startDay : startDay + 1;
    absl::Time windowStart = LocalInstant(startDay, *startMinutes, zone);
    absl::Time windowEnd = LocalInstant(endDay, *endMinutes, zone);

    if (windowStart <= now && now < windowEnd && ContainsDay(days, startDay)) {
      return WindowEval{
          .in_range = true, .window_end = windowEnd, .window_length = windowEnd - windowStart};
    }
  }

  return WindowEval{};
}

// Absolute instants. The day check applies to the instant asked about.
absl::StatusOr<WindowEval> EvalDaysTimestampWindow(absl::Span<const int64_t> days, absl::Time start,
                                                   absl::Time end, absl::Time now,
                                                   absl::TimeZone zone) {
  if (absl::Status status = ValidateDays(days); !status.ok()) {
    return status;
  }

  absl::CivilDay currentDay{absl::ToCivilSecond(now, zone)};
  if (start <= now && now < end && ContainsDay(days, currentDay)) {
    return WindowEval{.in_range = true, .window_end = end, .window_length = end - start};
  }
  return WindowEval{};
}

WindowEval EvalDurationWindow(absl::Duration d, absl::Time now) {
  return WindowEval{.in_range = true, .window_end = now + d, .window_length = d};
}

std::vector<cel_runtime::CelFunctionDescriptor> PolicyForRangeDescriptors() {
  using Type = cel_runtime::CelValue::Type;
  // Messages (the policy arguments) are kStruct in the runtime's kinds.
  return {
      cel_runtime::CelFunctionDescriptor(
          "policy_for_range", /*receiver_style=*/false,
          /*types=*/
          {Type::kList, Type::kString, Type::kString, Type::kBool, Type::kStruct, Type::kStruct},
          /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("policy_for_range", /*receiver_style=*/false,
                                         /*types=*/
                                         {Type::kList, Type::kTimestamp, Type::kTimestamp,
                                          Type::kBool, Type::kStruct, Type::kStruct},
                                         /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("policy_for_range", /*receiver_style=*/false,
                                         /*types=*/{Type::kDuration, Type::kBool, Type::kStruct},
                                         /*is_strict=*/true),
  };
}

absl::Status PolicyForRangeFunction::Evaluate(absl::Span<const cel_runtime::CelValue> args,
                                              cel_runtime::CelValue* result,
                                              google::protobuf::Arena* arena) const {
  // Every overload answers against the current time, so a cached decision would
  // outlive the window. Mark the evaluation non-cacheable.
  *used_sink_ = true;

  absl::Time now = absl::Now();

  if (args.size() == kDaysOverloadArgCount) {
    absl::StatusOr<std::vector<int64_t>> days = DayList(args[0], arena);
    if (!days.ok()) {
      return days.status();
    }

    absl::TimeZone zone = absl::LocalTimeZone();
    absl::StatusOr<WindowEval> window =
        args[1].type() == cel_runtime::CelValue::Type::kString
            ? EvalDaysHHMMWindow(*days, args[1].StringOrDie().value(),
                                 args[2].StringOrDie().value(), now, zone)
            : EvalDaysTimestampWindow(*days, args[1].TimestampOrDie(), args[2].TimestampOrDie(),
                                      now, zone);
    if (!window.ok()) {
      return window.status();
    }

    // Either way the answer is one of the policy arguments, passed through
    // untouched so a composite policy (e.g. a TouchID cooldown) keeps its
    // fields.
    *result = window->in_range ? args[kDaysOverloadPolicyIndex]
                               : args[kDaysOverloadOutOfRangePolicyIndex];
    return absl::OkStatus();
  }

  if (args.size() == kDurationOverloadArgCount) {
    absl::Duration length = args[0].DurationOrDie();
    if (length <= absl::ZeroDuration()) {
      return absl::InvalidArgumentError("policy_for_range() duration must be positive");
    }

    // [now, now + d) always contains now, so there is no out_of_range_policy to
    // choose between and nothing to compute: EvalDurationWindow() is only needed
    // once the window's end is acted on.
    *result = args[kDurationOverloadPolicyIndex];
    return absl::OkStatus();
  }

  return absl::InvalidArgumentError(
      "policy_for_range() called with an unexpected number of arguments");
}

absl::Status AddPolicyForRangeCompilerLibrary(::cel::CompilerBuilder& builder) {
  return builder.AddLibrary(::cel::CompilerLibrary::FromCheckerLibrary(
      {"policy_for_range", &RegisterPolicyForRangeDecls}));
}

absl::Status RegisterPolicyForRangeFunctions(cel_runtime::CelFunctionRegistry* registry,
                                             const cel_runtime::InterpreterOptions&) {
  // Lazy, like today(): the Activation vends the implementations so the calls
  // are never constant-folded and can mark the evaluation non-cacheable.
  for (const auto& descriptor : PolicyForRangeDescriptors()) {
    CEL_RETURN_IF_ERROR(registry->RegisterLazyFunction(descriptor));
  }
  return absl::OkStatus();
}

}  // namespace cel
}  // namespace santa
