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

#include "Source/common/cel/RelativeTimeFunction.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

// today(zone) resolves its zone with policy_for_range()'s resolver so the two
// cannot drift apart. Same build target, so this costs no new dependency.
#include "Source/common/cel/PolicyForRangeFunction.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/civil_time.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/decl.h"
#include "common/kind.h"
#include "common/type.h"
#include "eval/public/containers/container_backed_list_impl.h"
#include "internal/status_macros.h"
#include "runtime/function_adapter.h"
#pragma clang diagnostic pop

namespace cel_runtime = ::google::api::expr::runtime;

namespace santa {
namespace cel {

namespace {
// days(n) -> duration. Pure: n*24h. Sugar because CEL's native duration() only
// parses units up to hours.
absl::Duration DaysImpl(int64_t n, const google::protobuf::DescriptorPool*,
                        google::protobuf::MessageFactory*, google::protobuf::Arena*) {
  return absl::Hours(24) * n;
}

cel_runtime::CelFunctionDescriptor WeekdaysDescriptor() {
  return cel_runtime::CelFunctionDescriptor("weekdays", /*receiver_style=*/false, /*types=*/{},
                                            /*is_strict=*/true);
}

// weekdays() -> list<int>. A pure constant, [1, 2, 3, 4, 5] (Monday through
// Friday) in the 0=Sunday day-of-week numbering. Written as a CelFunction
// rather than a function adapter because the adapters have no list return.
class WeekdaysFunction : public cel_runtime::CelFunction {
 public:
  WeekdaysFunction() : cel_runtime::CelFunction(WeekdaysDescriptor()) {}

  absl::Status Evaluate(absl::Span<const cel_runtime::CelValue> args, cel_runtime::CelValue* result,
                        google::protobuf::Arena* arena) const override {
    if (!args.empty()) {
      return absl::InvalidArgumentError("weekdays() expects no arguments");
    }

    std::vector<cel_runtime::CelValue> days;
    days.reserve(5);
    for (int64_t day = 1; day <= 5; ++day) {
      days.push_back(cel_runtime::CelValue::CreateInt64(day));
    }

    *result = cel_runtime::CelValue::CreateList(
        arena->Create<cel_runtime::ContainerBackedListImpl>(arena, std::move(days)));
    return absl::OkStatus();
  }
};
}  // namespace

std::vector<cel_runtime::CelFunctionDescriptor> TodayDescriptors() {
  using Type = cel_runtime::CelValue::Type;
  return {
      cel_runtime::CelFunctionDescriptor("today", /*receiver_style=*/false, /*types=*/{},
                                         /*is_strict=*/true),
      cel_runtime::CelFunctionDescriptor("today", /*receiver_style=*/false,
                                         /*types=*/{Type::kString},
                                         /*is_strict=*/true),
  };
}

absl::Status TodayFunction::Evaluate(absl::Span<const cel_runtime::CelValue> args,
                                     cel_runtime::CelValue* result,
                                     google::protobuf::Arena*) const {
  if (args.size() > 1) {
    return absl::InvalidArgumentError("today() expects at most a time zone argument");
  }

  // The value changes at the next midnight in whichever zone applies, so a
  // cached decision could go stale. Marked before the zone can fail to resolve,
  // the same order policy_for_range() uses: a failed evaluation produces no
  // decision to cache either way.
  *used_sink_ = true;

  // Both forms are the same path; the bare one is its "local" case. The zone
  // argument names a calendar for the windows that must mean one instant
  // fleet-wide. The default is deliberately the same call ResolveTimeZone()'s
  // "local" branch makes rather than a call to the resolver, which would put a
  // status on a path that cannot fail; if what "local" means ever changes there,
  // change it here and in PolicyForRangeFunction::Evaluate() too.
  absl::TimeZone zone = absl::LocalTimeZone();
  if (args.size() == 1) {
    absl::StatusOr<absl::TimeZone> named = ResolveTimeZone(args[0].StringOrDie().value());
    if (!named.ok()) {
      return named.status();
    }
    zone = *named;
  }

  // The start of the civil day that zone is in right now, off the system clock:
  // today() is the date this machine says it is, in the calendar asked for.
  absl::Time now = absl::Now();
  *result = cel_runtime::CelValue::CreateTimestamp(
      absl::FromCivil(absl::CivilDay{absl::ToCivilSecond(now, zone)}, zone));
  return absl::OkStatus();
}

cel_runtime::CelFunctionDescriptor NowDescriptor() {
  return cel_runtime::CelFunctionDescriptor("now", /*receiver_style=*/false, /*types=*/{},
                                            /*is_strict=*/true);
}

absl::Status NowFunction::Evaluate(absl::Span<const cel_runtime::CelValue> args,
                                   cel_runtime::CelValue* result, google::protobuf::Arena*) const {
  if (!args.empty()) {
    return absl::InvalidArgumentError("now() expects no arguments");
  }

  // The value changes on every evaluation, so a cached decision could go stale
  // immediately. Mark the evaluation non-cacheable.
  *used_sink_ = true;

  *result = cel_runtime::CelValue::CreateTimestamp(now_());
  return absl::OkStatus();
}

absl::Status AddRelativeTimeCompilerLibrary(::cel::CompilerBuilder& builder) {
  return builder.AddLibrary(::cel::CompilerLibrary::FromCheckerLibrary(
      {"relative_time", [](::cel::TypeCheckerBuilder& checker) -> absl::Status {
         CEL_ASSIGN_OR_RETURN(
             auto today_decl,
             ::cel::MakeFunctionDecl(
                 "today", ::cel::MakeOverloadDecl("today_timestamp", ::cel::TimestampType()),
                 ::cel::MakeOverloadDecl("today_timestamp_tz", ::cel::TimestampType(),
                                         ::cel::StringType())));
         CEL_ASSIGN_OR_RETURN(auto days_decl,
                              ::cel::MakeFunctionDecl(
                                  "days", ::cel::MakeOverloadDecl("days_int", ::cel::DurationType(),
                                                                  ::cel::IntType())));
         CEL_ASSIGN_OR_RETURN(
             auto now_decl,
             ::cel::MakeFunctionDecl(
                 "now", ::cel::MakeOverloadDecl("now_timestamp", ::cel::TimestampType())));
         CEL_ASSIGN_OR_RETURN(
             auto weekdays_decl,
             ::cel::MakeFunctionDecl(
                 "weekdays",
                 ::cel::MakeOverloadDecl("weekdays_list",
                                         ::cel::ListType(checker.arena(), ::cel::IntType()))));
         CEL_RETURN_IF_ERROR(checker.AddFunction(std::move(today_decl)));
         CEL_RETURN_IF_ERROR(checker.AddFunction(std::move(days_decl)));
         CEL_RETURN_IF_ERROR(checker.AddFunction(std::move(now_decl)));
         return checker.AddFunction(std::move(weekdays_decl));
       }}));
}

absl::Status RegisterRelativeTimeFunctions(cel_runtime::CelFunctionRegistry* registry,
                                           const cel_runtime::InterpreterOptions&) {
  // today() and now() are lazy: the implementations are vended by the Activation
  // so they are never constant-folded and can mark the evaluation
  // non-cacheable.
  for (const auto& descriptor : TodayDescriptors()) {
    CEL_RETURN_IF_ERROR(registry->RegisterLazyFunction(descriptor));
  }
  CEL_RETURN_IF_ERROR(registry->RegisterLazyFunction(NowDescriptor()));

  // weekdays() is a pure constant.
  CEL_RETURN_IF_ERROR(registry->Register(std::make_unique<WeekdaysFunction>()));

  // days() is a normal pure function.
  return ::cel::UnaryFunctionAdapter<absl::Duration, int64_t>::RegisterGlobalOverload(
      "days", &DaysImpl, registry->InternalGetRegistry());
}

}  // namespace cel
}  // namespace santa
