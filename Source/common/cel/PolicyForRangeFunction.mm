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
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "Source/common/cel/result.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/civil_time.h"
#include "absl/time/time.h"
#include "celv2/v2.pb.h"
#include "google/protobuf/arena.h"
#include "google/protobuf/message.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/ast.h"
#include "common/decl.h"
#include "common/expr.h"
#include "common/navigable_ast.h"
#include "common/type.h"
#include "eval/public/structs/cel_proto_wrapper.h"
#include "internal/status_macros.h"
#include "validator/validator.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

namespace {

// Argument layouts, one per overload. The counts are all different, which is
// what the runtime dispatches on; the policies are always the trailing arguments.
//
//   (d, policy)
constexpr size_t kDurationOverloadArgCount = 2;
constexpr size_t kDurationOverloadPolicyIndex = 1;
//   (start, end, policy, out_of_range_policy)
constexpr size_t kTimestampOverloadArgCount = 4;
constexpr size_t kTimestampOverloadPolicyIndex = 2;
constexpr size_t kTimestampOverloadOutOfRangePolicyIndex = 3;
//   (days, start, end, policy, out_of_range_policy)
constexpr size_t kDaysOverloadArgCount = 5;
constexpr size_t kDaysOverloadPolicyIndex = 3;
constexpr size_t kDaysOverloadOutOfRangePolicyIndex = 4;
//   (days, start, end, zone, policy, out_of_range_policy)
constexpr size_t kDaysZoneOverloadArgCount = 6;
constexpr size_t kDaysZoneOverloadZoneIndex = 3;
constexpr size_t kDaysZoneOverloadPolicyIndex = 4;
constexpr size_t kDaysZoneOverloadOutOfRangePolicyIndex = 5;

// Overload ids are matched by the sync server's version gate, so they are part
// of the interface and must not be renamed.
constexpr absl::string_view kKillOnExpiryOverloadId = "kill_on_expiry_result";
constexpr absl::string_view kDaysStringOverloadId = "policy_for_range_days_string";
constexpr absl::string_view kDaysStringGrantOverloadId = "policy_for_range_days_string_grant";
constexpr absl::string_view kDaysStringTzOverloadId = "policy_for_range_days_string_tz";
constexpr absl::string_view kDaysStringTzGrantOverloadId = "policy_for_range_days_string_tz_grant";
constexpr absl::string_view kTimestampOverloadId = "policy_for_range_timestamp";
constexpr absl::string_view kTimestampGrantOverloadId = "policy_for_range_timestamp_grant";
constexpr absl::string_view kDurationGrantOverloadId = "policy_for_range_duration_grant";

// The zone a window with no zone argument is read in, spelled the way the zone
// argument spells it. Recorded on a pending kill so the kill-time re-check reads
// the same calendar the evaluation did.
constexpr absl::string_view kDefaultZone = "local";

// The warning lead is 10% of the window's length, at least 5 minutes and at
// most an hour: a work-day window warns 48 minutes out, anything from 10 hours
// up warns an hour out, and a window shorter than the floor warns at launch
// because the notify time clamps to the evaluation.
constexpr absl::Duration kMinNotificationLead = absl::Minutes(5);
constexpr absl::Duration kMaxNotificationLead = absl::Hours(1);
constexpr int64_t kNotificationLeadDivisor = 10;

// Parses a strict "[+-]HH:MM" fixed offset into seconds east of UTC. The width
// is exact: no "+5:30", no seconds field, no bare "05:30". cel-cpp's own
// timestamp functions handle such an offset by shifting the timestamp instead of
// building a zone, which loses the civil-day boundary the window math needs, so
// this parses the offset itself.
std::optional<int> ParseFixedOffsetSeconds(absl::string_view zone) {
  if (zone.size() != 6 || (zone[0] != '+' && zone[0] != '-')) {
    return std::nullopt;
  }

  std::optional<int> minutes = ParseHourMinute(zone.substr(1));
  if (!minutes) {
    return std::nullopt;
  }
  return zone[0] == '-' ? -*minutes * 60 : *minutes * 60;
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

bool ContainsDay(absl::Span<const int64_t> days, absl::CivilDay day) {
  return std::find(days.begin(), days.end(), DayOfWeek(day)) != days.end();
}

// The instant a local civil time falls on, resolved the way absl::FromCivil()
// does so that today() and a window edge never disagree about the same civil
// time. A DST transition makes the requested civil time either repeated or
// skipped. A repeated civil time resolves to its first occurrence, so a window
// with both edges inside the repeated hour keeps its full length and fires once,
// on the first pass. A skipped civil time resolves to the transition instant.
// FromCivil() is documented to be order preserving, which is what keeps
// windowStart <= windowEnd. Back-to-back 24h occurrences stay contiguous because
// a window's closing edge and the next occurrence's opening edge are the same
// civil expression and so land on the same instant under any deterministic rule.
absl::Time LocalInstant(absl::CivilDay day, int minutesAfterMidnight, absl::TimeZone zone) {
  return absl::FromCivil(absl::CivilSecond(day) + minutesAfterMidnight * 60, zone);
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

// Policies that let a process start, and so leave something to quit at expiry.
bool IsGrantable(::santa::cel::v2::ReturnValue value) {
  switch (value) {
    case ::santa::cel::v2::ALLOWLIST:
    case ::santa::cel::v2::AUDIT:
    case ::santa::cel::v2::SEATBELT:
    case ::santa::cel::v2::REQUIRE_TOUCHID:
    case ::santa::cel::v2::REQUIRE_TOUCHID_ONLY: return true;
    default: return false;
  }
}

// The Result a policy argument holds, or nullptr for any other value.
const Result* AsResult(const cel_runtime::CelValue& value) {
  return value.IsMessage() ? google::protobuf::DynamicCastMessage<Result>(value.MessageOrDie())
                           : nullptr;
}

struct DecodedPolicy {
  cel_runtime::CelValue result;
  bool kill_on_expiry;
};

// Unwraps a policy argument. A Grant is only legal in the in-range slot and only
// around a grantable Result; the checker guarantees both for compiled rules, so
// this is the backstop for values that bypassed it.
absl::StatusOr<DecodedPolicy> DecodePolicy(const cel_runtime::CelValue& value, bool grantAllowed,
                                           google::protobuf::Arena* arena) {
  if (AsResult(value)) {
    return DecodedPolicy{.result = value, .kill_on_expiry = false};
  }
  const Grant* grant = value.IsMessage()
                           ? google::protobuf::DynamicCastMessage<Grant>(value.MessageOrDie())
                           : nullptr;
  if (grant && grantAllowed && grant->has_policy() && IsGrantable(grant->policy().value())) {
    return DecodedPolicy{
        .result = cel_runtime::CelProtoWrapper::CreateMessage(&grant->policy(), arena),
        .kill_on_expiry = true};
  }
  return absl::InvalidArgumentError(
      grantAllowed ? "policy_for_range() expects a Result or kill_on_expiry() policy"
                   : "policy_for_range() out-of-range policy must be a Result");
}

// kill_on_expiry(Result) -> Grant. Eager and pure: it checks the policy is
// grantable and wraps it. policy_for_range() is what records the kill.
class KillOnExpiryFunction : public cel_runtime::CelFunction {
 public:
  KillOnExpiryFunction()
      : cel_runtime::CelFunction(cel_runtime::CelFunctionDescriptor(
            "kill_on_expiry", /*receiver_style=*/false, {cel_runtime::CelValue::Type::kStruct},
            /*is_strict=*/true)) {}

  absl::Status Evaluate(absl::Span<const cel_runtime::CelValue> args, cel_runtime::CelValue* result,
                        google::protobuf::Arena* arena) const override {
    const Result* policy = AsResult(args[0]);
    if (!policy) {
      return absl::InvalidArgumentError("kill_on_expiry() expects a Result policy");
    }
    if (!IsGrantable(policy->value())) {
      return absl::InvalidArgumentError(absl::StrCat(
          ::santa::cel::v2::ReturnValue_Name(policy->value()),
          " cannot be used with kill_on_expiry() because it does not allow a process to start"));
    }
    auto* grant = google::protobuf::Arena::Create<Grant>(arena);
    *grant->mutable_policy() = *policy;
    *result = cel_runtime::CelProtoWrapper::CreateMessage(grant, arena);
    return absl::OkStatus();
  }
};

// Reports the kill an in-window kill_on_expiry() asked for. `days`, `start`,
// `end` and `zone` carry the window's shape, empty for the non-recurring
// overloads.
void RecordPendingKill(std::optional<PendingKill>* sink, const WindowEval& window, absl::Time now,
                       absl::Span<const int64_t> days, absl::string_view start,
                       absl::string_view end, absl::string_view zone) {
  absl::Duration lead = NotificationLead(window.window_length);
  PendingKill kill = {.deadline = window.window_end,
                      .notify_at = std::max(now, window.window_end - lead),
                      .window_days = {days.begin(), days.end()},
                      .window_start = std::string(start),
                      .window_end = std::string(end),
                      .window_zone = std::string(zone)};

  // One expression can call policy_for_range() more than once (e.g. through a
  // nested ternary); the earlier deadline governs everything the rule covers,
  // and the window shape it came with goes with it.
  if (!sink->has_value() || kill.deadline < (*sink)->deadline) {
    *sink = std::move(kill);
  }
}

// The in-range argument index of a grant overload, nullopt for anything else.
std::optional<size_t> GrantPolicyIndex(absl::string_view overloadId) {
  if (overloadId == kDaysStringGrantOverloadId) return kDaysOverloadPolicyIndex;
  if (overloadId == kDaysStringTzGrantOverloadId) return kDaysZoneOverloadPolicyIndex;
  if (overloadId == kTimestampGrantOverloadId) return kTimestampOverloadPolicyIndex;
  if (overloadId == kDurationGrantOverloadId) return kDurationOverloadPolicyIndex;
  return std::nullopt;
}

const ::cel::Reference* FindReference(const ::cel::Ast& ast, int64_t id) {
  auto it = ast.reference_map().find(id);
  return it == ast.reference_map().end() ? nullptr : &it->second;
}

bool HasMessageType(const ::cel::Ast& ast, int64_t id, absl::string_view name) {
  auto it = ast.type_map().find(id);
  return it != ast.type_map().end() && it->second.has_message_type() &&
         it->second.message_type().type() == name;
}

bool IsCall(const ::cel::Expr& expr, absl::string_view function) {
  return expr.has_call_expr() && expr.call_expr().function() == function;
}

// The wrapped policy must be a named allow-like policy or a Touch ID cooldown
// helper, both recognizable from the checked references alone.
bool ValidateWrappedPolicy(::cel::ValidationContext& context, const ::cel::Expr& policy) {
  const ::cel::Reference* ref = FindReference(context.ast(), policy.id());
  if (ref && policy.has_ident_expr()) {
    ::santa::cel::v2::ReturnValue value;
    if (::santa::cel::v2::ReturnValue_Parse(ref->name(), &value)) {
      if (IsGrantable(value)) {
        return true;
      }
      context.ReportErrorAt(
          policy.id(), absl::StrCat(ref->name(), " cannot be used with kill_on_expiry() because it "
                                                 "does not allow a process to start"));
      return false;
    }
  }
  if (ref && policy.has_call_expr() && ref->overload_id().size() == 1 &&
      (ref->overload_id()[0] == "require_touchid_with_cooldown_minutes_int" ||
       ref->overload_id()[0] == "require_touchid_only_with_cooldown_minutes_int")) {
    return true;
  }
  context.ReportErrorAt(policy.id(),
                        "kill_on_expiry() requires a statically known allow-like policy");
  return false;
}

// The wrapper must be the in-range argument of a grant overload, and that call
// must reach the root through ternary branches only, so the kill it asks for is
// always attached to the rule's own decision.
bool ValidatePlacement(::cel::ValidationContext& context, const ::cel::NavigableAstNode& wrapper) {
  const ::cel::NavigableAstNode* range = wrapper.parent();
  const ::cel::Reference* ref = range ? FindReference(context.ast(), range->expr()->id()) : nullptr;
  std::optional<size_t> index;
  if (ref && ref->overload_id().size() == 1) {
    index = GrantPolicyIndex(ref->overload_id()[0]);
  }
  if (!index || wrapper.child_index() < 0 || static_cast<size_t>(wrapper.child_index()) != *index) {
    context.ReportErrorAt(
        wrapper.expr()->id(),
        "kill_on_expiry() may only be used as the in-range policy of policy_for_range()");
    return false;
  }
  for (const ::cel::NavigableAstNode* node = range; node->parent() != nullptr;
       node = node->parent()) {
    if (!IsCall(*node->parent()->expr(), "_?_:_") || node->child_index() == 0) {
      context.ReportErrorAt(
          range->expr()->id(),
          "a policy_for_range() using kill_on_expiry() must produce the rule's result");
      return false;
    }
  }
  return true;
}

// Runs after type checking. Every kill_on_expiry() must wrap a recognizable
// allow-like policy and sit in the in-range slot of a policy_for_range() on the
// rule's result path; a rule using one must itself produce a Result, and Grant
// is never constructed directly.
bool ValidateKillOnExpiry(::cel::ValidationContext& context) {
  const ::cel::Ast& ast = context.ast();
  bool valid = true;
  bool usesKillOnExpiry = false;
  for (const ::cel::NavigableAstNode& node : context.navigable_ast().Root().DescendantsPreorder()) {
    const ::cel::Expr& expr = *node.expr();
    if (expr.has_struct_expr()) {
      const ::cel::Reference* ref = FindReference(ast, expr.id());
      if (ref && ref->name() == Grant::descriptor()->full_name()) {
        context.ReportErrorAt(expr.id(), "santa.cel.Grant is internal; use kill_on_expiry()");
        valid = false;
      }
    }
    if (!IsCall(expr, "kill_on_expiry")) {
      continue;
    }
    usesKillOnExpiry = true;
    if (!ValidateWrappedPolicy(context, expr.call_expr().args()[0])) {
      valid = false;
    }
    if (!ValidatePlacement(context, node)) {
      valid = false;
    }
  }
  if (usesKillOnExpiry &&
      !HasMessageType(ast, ast.root_expr().id(), Result::descriptor()->full_name())) {
    context.ReportErrorAt(ast.root_expr().id(),
                          "a rule using kill_on_expiry() must produce a santa.cel.Result");
    valid = false;
  }
  return valid;
}

absl::Status RegisterPolicyForRangeDecls(::cel::TypeCheckerBuilder& builder) {
  // Named policies and the cooldown helpers are all santa.cel.Result. A Grant is
  // only ever kill_on_expiry()'s result, so the checker alone keeps it out of the
  // out-of-range slot and out of the rule's result.
  auto result = ::cel::MessageType(::santa::cel::Result::descriptor());
  auto grant = ::cel::MessageType(::santa::cel::Grant::descriptor());
  auto dayList = ::cel::ListType(builder.arena(), ::cel::IntType());
  auto str = ::cel::StringType();
  auto ts = ::cel::TimestampType();

  CEL_ASSIGN_OR_RETURN(
      auto killOnExpiry,
      ::cel::MakeFunctionDecl("kill_on_expiry",
                              ::cel::MakeOverloadDecl(kKillOnExpiryOverloadId, grant, result)));
  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(killOnExpiry)));

  CEL_ASSIGN_OR_RETURN(
      auto policyForRange,
      ::cel::MakeFunctionDecl(
          "policy_for_range",
          ::cel::MakeOverloadDecl(kDaysStringOverloadId, result, dayList, str, str, result, result),
          ::cel::MakeOverloadDecl(kDaysStringGrantOverloadId, result, dayList, str, str, grant,
                                  result),
          ::cel::MakeOverloadDecl(kDaysStringTzOverloadId, result, dayList, str, str, str, result,
                                  result),
          ::cel::MakeOverloadDecl(kDaysStringTzGrantOverloadId, result, dayList, str, str, str,
                                  grant, result),
          ::cel::MakeOverloadDecl(kTimestampOverloadId, result, ts, ts, result, result),
          ::cel::MakeOverloadDecl(kTimestampGrantOverloadId, result, ts, ts, grant, result),
          ::cel::MakeOverloadDecl(kDurationGrantOverloadId, result, ::cel::DurationType(), grant)));
  return builder.AddFunction(std::move(policyForRange));
}

}  // namespace

// Minutes after midnight, so a caller comparing two of them is comparing civil
// times on the same day.
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

// Every day is 0 (Sunday) through 6 (Saturday); anything else is an error
// naming the offending day.
static absl::Status ValidateDays(absl::Span<const int64_t> days) {
  for (int64_t day : days) {
    if (day < 0 || day > 6) {
      return absl::InvalidArgumentError(absl::StrCat(
          "policy_for_range() day must be 0 (Sunday) through 6 (Saturday), got ", day));
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<absl::TimeZone> ResolveTimeZone(absl::string_view zone) {
  // "local" is the only name that means "whatever this host is set to"; every
  // other form names the same calendar on every host.
  if (zone == "local") {
    return absl::LocalTimeZone();
  }

  if (std::optional<int> offsetSeconds = ParseFixedOffsetSeconds(zone); offsetSeconds) {
    return absl::FixedTimeZone(*offsetSeconds);
  }

  // Everything left goes to the platform's zone loader, which takes IANA names
  // and "UTC" but also opens some names as files: "file:<path>" and "libc:*"
  // (cctz documents both as test-only spellings), plus any name starting with
  // "/" (the loader skips its zoneinfo prefix for absolute paths) or escaping
  // that prefix with "..". No IANA name contains a colon or ".." or starts with
  // "/", and the offset form is already handled above, so all three shapes are
  // rejections here.
  absl::TimeZone loaded;
  if (!absl::StrContains(zone, ':') && !absl::StartsWith(zone, "/") &&
      !absl::StrContains(zone, "..") && absl::LoadTimeZone(std::string(zone), &loaded)) {
    return loaded;
  }

  return absl::InvalidArgumentError(
      absl::StrCat("unknown time zone '", zone,
                   "': expected \"local\", an IANA name such as \"America/New_York\", or a "
                   "[+-]HH:MM offset"));
}

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

// Absolute instants, so there is no calendar to read: no day list and no zone.
// A timestamp literal carries its zone in the offset it is written with.
WindowEval EvalTimestampWindow(absl::Time start, absl::Time end, absl::Time now) {
  if (start <= now && now < end) {
    return WindowEval{.in_range = true, .window_end = end, .window_length = end - start};
  }
  return WindowEval{};
}

WindowEval EvalDurationWindow(absl::Duration d, absl::Time now) {
  return WindowEval{.in_range = true, .window_end = now + d, .window_length = d};
}

absl::Duration NotificationLead(absl::Duration window_length) {
  return std::clamp(window_length / kNotificationLeadDivisor, kMinNotificationLead,
                    kMaxNotificationLead);
}

std::vector<cel_runtime::CelFunctionDescriptor> PolicyForRangeDescriptors() {
  using Type = cel_runtime::CelValue::Type;
  // Result and Grant are both kStruct at runtime, so one descriptor per argument
  // count covers the plain and grant overloads of a shape.
  return {
      cel_runtime::CelFunctionDescriptor(
          "policy_for_range", /*receiver_style=*/false,
          /*types=*/
          {Type::kList, Type::kString, Type::kString, Type::kStruct, Type::kStruct},
          /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor(
          "policy_for_range", /*receiver_style=*/false,
          /*types=*/
          {Type::kList, Type::kString, Type::kString, Type::kString, Type::kStruct, Type::kStruct},
          /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor(
          "policy_for_range", /*receiver_style=*/false,
          /*types=*/{Type::kTimestamp, Type::kTimestamp, Type::kStruct, Type::kStruct},
          /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("policy_for_range", /*receiver_style=*/false,
                                         /*types=*/{Type::kDuration, Type::kStruct},
                                         /*is_strict=*/true),
  };
}

absl::Status PolicyForRangeFunction::Evaluate(absl::Span<const cel_runtime::CelValue> args,
                                              cel_runtime::CelValue* result,
                                              google::protobuf::Arena* arena) const {
  // Every overload answers against the current time, so a cached decision would
  // outlive the window. Mark the evaluation non-cacheable.
  *used_sink_ = true;

  absl::Time now = now_();

  if (args.size() == kDaysOverloadArgCount || args.size() == kDaysZoneOverloadArgCount) {
    bool zoneGiven = args.size() == kDaysZoneOverloadArgCount;
    size_t policyIndex = zoneGiven ? kDaysZoneOverloadPolicyIndex : kDaysOverloadPolicyIndex;
    size_t outOfRangeIndex =
        zoneGiven ? kDaysZoneOverloadOutOfRangePolicyIndex : kDaysOverloadOutOfRangePolicyIndex;
    // Both policies are decoded on every evaluation so a bad argument fails the
    // same way whether or not the window is open.
    CEL_ASSIGN_OR_RETURN(DecodedPolicy policy, DecodePolicy(args[policyIndex], true, arena));
    CEL_ASSIGN_OR_RETURN(DecodedPolicy outOfRange,
                         DecodePolicy(args[outOfRangeIndex], false, arena));

    absl::StatusOr<std::vector<int64_t>> days = DayList(args[0], arena);
    if (!days.ok()) {
      return days.status();
    }

    // Without a zone argument the window is read in the host's zone, the same
    // zone "local" resolves to.
    absl::string_view zoneArg = kDefaultZone;
    absl::TimeZone zone = absl::LocalTimeZone();
    if (zoneGiven) {
      zoneArg = args[kDaysZoneOverloadZoneIndex].StringOrDie().value();
      absl::StatusOr<absl::TimeZone> named = ResolveTimeZone(zoneArg);
      if (!named.ok()) {
        return named.status();
      }
      zone = *named;
    }

    absl::StatusOr<WindowEval> window = EvalDaysHHMMWindow(
        *days, args[1].StringOrDie().value(), args[2].StringOrDie().value(), now, zone);
    if (!window.ok()) {
      return window.status();
    }

    if (window->in_range && policy.kill_on_expiry) {
      RecordPendingKill(pending_kill_sink_, *window, now, *days, args[1].StringOrDie().value(),
                        args[2].StringOrDie().value(), zoneArg);
    }
    *result = window->in_range ? policy.result : outOfRange.result;
    return absl::OkStatus();
  }

  if (args.size() == kTimestampOverloadArgCount) {
    CEL_ASSIGN_OR_RETURN(DecodedPolicy policy,
                         DecodePolicy(args[kTimestampOverloadPolicyIndex], true, arena));
    CEL_ASSIGN_OR_RETURN(DecodedPolicy outOfRange,
                         DecodePolicy(args[kTimestampOverloadOutOfRangePolicyIndex], false, arena));

    // An absolute span names one occurrence, so there is no recurring shape for
    // a restart to re-check: the deadline it records stands alone.
    WindowEval window =
        EvalTimestampWindow(args[0].TimestampOrDie(), args[1].TimestampOrDie(), now);
    if (window.in_range && policy.kill_on_expiry) {
      RecordPendingKill(pending_kill_sink_, window, now, {}, "", "", "");
    }
    *result = window.in_range ? policy.result : outOfRange.result;
    return absl::OkStatus();
  }

  if (args.size() == kDurationOverloadArgCount) {
    CEL_ASSIGN_OR_RETURN(DecodedPolicy policy,
                         DecodePolicy(args[kDurationOverloadPolicyIndex], true, arena));
    absl::Duration length = args[0].DurationOrDie();
    if (length <= absl::ZeroDuration()) {
      return absl::InvalidArgumentError("policy_for_range() duration must be positive");
    }

    // [now, now + d) always contains now, so the window only places a deadline.
    if (policy.kill_on_expiry) {
      RecordPendingKill(pending_kill_sink_, EvalDurationWindow(length, now), now, {}, "", "", "");
    }
    *result = policy.result;
    return absl::OkStatus();
  }

  return absl::InvalidArgumentError(
      "policy_for_range() called with an unexpected number of arguments");
}

absl::Status AddPolicyForRangeCompilerLibrary(::cel::CompilerBuilder& builder) {
  builder.GetValidator().AddValidation(::cel::Validation(&ValidateKillOnExpiry, "kill_on_expiry"));
  return builder.AddLibrary(::cel::CompilerLibrary::FromCheckerLibrary(
      {"policy_for_range", &RegisterPolicyForRangeDecls}));
}

absl::Status RegisterPolicyForRangeFunctions(cel_runtime::CelFunctionRegistry* registry,
                                             const cel_runtime::InterpreterOptions&) {
  // kill_on_expiry() is eager: it has no side effect, so folding it is harmless.
  // The policy_for_range() overloads stay lazy, vended by the Activation, so they
  // are never folded and can mark the evaluation non-cacheable.
  CEL_RETURN_IF_ERROR(registry->Register(std::make_unique<KillOnExpiryFunction>()));
  for (const auto& descriptor : PolicyForRangeDescriptors()) {
    CEL_RETURN_IF_ERROR(registry->RegisterLazyFunction(descriptor));
  }
  return absl::OkStatus();
}

}  // namespace cel
}  // namespace santa
