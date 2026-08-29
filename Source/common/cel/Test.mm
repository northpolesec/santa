/// Copyright 2025 North Pole Security, Inc.
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

#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/Evaluator.h"
#include "Source/common/cel/PolicyForRangeFunction.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/civil_time.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "google/protobuf/arena.h"

namespace {

// The activation boilerplate the newer cases share. Callers take a fresh
// activation per expression: the relative-time flag accumulates on the
// activation, so reusing one leaks non-cacheability into the next case.
//
// `now` is the clock now() and policy_for_range() read (today() reads the system
// clock, whatever this is); the default is the system clock, which is what every
// case that isn't about the clock wants.
template <bool IsV2>
std::unique_ptr<santa::cel::Activation<IsV2>> MakeActivation(
    std::function<absl::Time()> now = absl::Now) {
  using ExecutableFileT = typename santa::cel::CELProtoTraits<IsV2>::ExecutableFileT;
  using AncestorT = typename santa::cel::CELProtoTraits<IsV2>::AncestorT;
  using FileDescriptorT = typename santa::cel::CELProtoTraits<IsV2>::FileDescriptorT;

  return std::make_unique<santa::cel::Activation<IsV2>>(
      std::make_unique<ExecutableFileT>(),
      ^std::vector<std::string>() {
        return {"/usr/bin/test", "-y"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      },
      std::move(now));
}

constexpr int kMinutesPerDay = 24 * 60;

// A fixed offset east of UTC, in minutes, written the way the zone argument
// wants it: [+-]HH:MM.
std::string FixedOffsetZone(int offsetMinutes) {
  int magnitude = std::abs(offsetMinutes);
  char formatted[7];
  std::snprintf(formatted, sizeof(formatted), "%c%02d:%02d", offsetMinutes < 0 ? '-' : '+',
                magnitude / 60, magnitude % 60);
  return formatted;
}

// An instant as a CEL timestamp() literal, in UTC so the text carries no zone
// question of its own.
std::string AsUTCLiteral(absl::Time instant) {
  return absl::FormatTime("%Y-%m-%dT%H:%M:%SZ", instant, absl::UTCTimeZone());
}

// The offset, in minutes east of UTC, of a fixed zone in which `now` reads as
// hour:minute local. Lets a case pin a civil time through the CEL path, which
// can only ever ask about the current instant, without knowing the host's zone
// or the date. Always in [0, kMinutesPerDay), so always writable as +HH:MM.
int OffsetWhereNowReads(absl::Time now, int hour, int minute) {
  absl::CivilSecond utcNow = absl::ToCivilSecond(now, absl::UTCTimeZone());
  int wanted = hour * 60 + minute;
  int current = utcNow.hour() * 60 + utcNow.minute();
  return ((wanted - current) % kMinutesPerDay + kMinutesPerDay) % kMinutesPerDay;
}

// Pins the host zone for as long as it is in scope, by setting $TZ:
// absl::LocalTimeZone() re-reads $TZ on every call, so this is what the
// functions under test see as "the host's zone".
//
// The cases that check a host-local default need this. Where the suite runs in
// CI there is no TZ set at all, which means UTC, and on a UTC host a host-local
// default and a UTC default are the same answer to every question the CEL path
// can ask: those cases would pass whichever one the code implemented. Pinning a
// zone with a nonzero offset is what makes them discriminate.
//
// The previous value is put back on the way out, including when an assertion in
// the scope failed, since XCTest assertion failures do not unwind.
class ScopedHostZone {
 public:
  explicit ScopedHostZone(const char* zone) {
    if (const char* previous = getenv("TZ"); previous != nullptr) {
      previous_ = std::string(previous);
    }
    setenv("TZ", zone, 1);
  }

  ~ScopedHostZone() {
    if (previous_.has_value()) {
      setenv("TZ", previous_->c_str(), 1);
    } else {
      unsetenv("TZ");
    }
  }

  ScopedHostZone(const ScopedHostZone&) = delete;
  ScopedHostZone& operator=(const ScopedHostZone&) = delete;

 private:
  std::optional<std::string> previous_;
};

}  // namespace

@interface CELTest : XCTestCase
@end

@implementation CELTest

- (void)testBasic {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  f->set_is_platform_binary(false);
  f->set_team_id("EQHXZ8M8AV");
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {{"DYLD_INSERT_LIBRARIES", "1"}};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  if (!sut.ok()) {
    XCTFail("Failed to create evaluator: %s", sut.status().message().data());
  }

  {
    // Test bad expression.
    auto result = sut.value()->CompileAndEvaluate("foo", activation);
    if (result.ok()) XCTFail("Expected failure to evaluate, got ok!");
  }
  {
    // Timestamp comparison by seconds.
    auto result =
        sut.value()->CompileAndEvaluate("target.signing_time >= timestamp(1748436989)", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Timestamp comparison by date string.
    auto result = sut.value()->CompileAndEvaluate(
        "target.signing_time >= timestamp('2025-05-28T12:00:00Z')", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Static - is_platform_binary on target
    auto result = sut.value()->CompileAndEvaluate("target.is_platform_binary == false", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Static - team_id on target
    auto result = sut.value()->CompileAndEvaluate("target.team_id == 'EQHXZ8M8AV'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Combined - is_platform_binary and team_id
    auto result = sut.value()->CompileAndEvaluate(
        "!target.is_platform_binary && target.team_id == 'EQHXZ8M8AV'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Re-use of a compiled expression.
    google::protobuf::Arena arena;
    auto expr =
        sut.value()->Compile("target.signing_time >= timestamp('2025-05-28T12:00:00Z')", &arena);
    if (!expr.ok()) {
      XCTFail("Failed to compile: %s", expr.status().message().data());
    }

    auto result = sut.value()->Evaluate(expr.value().get(), activation, &arena);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }

    auto f2 = std::make_unique<ExecutableFileT>();
    f2->mutable_signing_time()->set_seconds(1716916129);
    santa::cel::Activation<true> activation2(
        std::move(f2),
        ^std::vector<std::string>() {
          return {"hello", "world"};
        },
        ^std::map<std::string, std::string>() {
          return {{"DYLD_INSERT_LIBRARIES", "1"}};
        },
        ^uid_t() {
          return 501;
        },
        ^std::string() {
          return "/Users/foo";
        },
        ^std::string() {
          return "/usr/bin/test";
        },
        ^std::vector<santa::cel::v2::Ancestor>() {
          return {};
        },
        ^std::vector<FileDescriptorT>() {
          return {};
        });

    auto result2 = sut.value()->Evaluate(expr.value().get(), activation2, &arena);
    if (!result2.ok()) {
      XCTFail("Failed to evaluate: %s", result2.status().message().data());
    } else {
      XCTAssertEqual(result2.value().value, ReturnValue::BLOCKLIST);
      XCTAssertEqual(result2.value().cacheable, true);
    }
  }
  {
    // Dynamic - process args
    auto result = sut.value()->CompileAndEvaluate("args[0] == 'hello'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Dynamic, env vars, ternary
    auto result = sut.value()->CompileAndEvaluate(
        "! has(envs.DYLD_INSERT_LIBRARIES) ? ALLOWLIST : BLOCKLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Activation integration: a producer runs at most once per evaluation even
    // when its variable is referenced multiple times, so per-exec work like
    // ExecArgs is not repeated. (The Memoizer unit contract — compute-once,
    // no-copy, stable reference — is covered directly by MemoizerTest.)
    __block int argsCallCount = 0;
    santa::cel::Activation<true> activation(
        std::move(f),
        ^std::vector<std::string>() {
          argsCallCount++;
          return {"hello", "world"};
        },
        ^std::map<std::string, std::string>() {
          return {{"DYLD_INSERT_LIBRARIES", "1"}};
        },
        ^uid_t() {
          return 0;
        },
        ^std::string {
          return "/";
        },
        ^std::string() {
          return "/usr/bin/test";
        },
        ^std::vector<santa::cel::v2::Ancestor>() {
          return {};
        },
        ^std::vector<FileDescriptorT>() {
          return {};
        });

    auto result = sut.value()->CompileAndEvaluate(
        "args[0] == 'foo' || args[0] == 'bar' || args[0] == 'hello'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
    XCTAssertEqual(argsCallCount, 1);
  }
  {
    // Test args.join(' ') - joining arguments with space
    auto result = sut.value()->CompileAndEvaluate("args.join(' ') == 'hello world'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Dynamic - filepath via path field
    auto result = sut.value()->CompileAndEvaluate("path == '/usr/bin/test'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Dynamic - path with startsWith
    auto result = sut.value()->CompileAndEvaluate("path.startsWith('/usr/bin')", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testRelativeTimestamps {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  constexpr int64_t kSecondsPerDay = 24 * 60 * 60;
  int64_t nowSec = absl::ToUnixSeconds(absl::Now());

  // Binary signed 10 days ago.
  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_secure_signing_time()->set_seconds(nowSec - 10 * kSecondsPerDay);
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Expressions that don't use today() are cacheable. Checked first, on a
    // fresh activation: the relative-time flag is sticky, so once a today()
    // expression below marks the activation non-cacheable it stays that way.
    auto result =
        sut.value()->CompileAndEvaluate("target.secure_signing_time >= timestamp(0)", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertTrue(result.value().cacheable);
    }
  }
  {
    // Signed within the last 5 days? No (signed 10 days ago) -> BLOCKLIST.
    // Using today() must make the result non-cacheable.
    auto result = sut.value()->CompileAndEvaluate("target.secure_signing_time > today() - days(5)",
                                                  activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // Signed within the last 90 days? Yes (10 days ago) -> ALLOWLIST.
    // duration() arithmetic should work natively too (90 days == 2160h).
    auto result = sut.value()->CompileAndEvaluate(
        "target.secure_signing_time > today() - duration('2160h')", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // The relative-time flag is sticky: reusing this activation for a non-today()
    // expression still yields a non-cacheable result.
    auto result =
        sut.value()->CompileAndEvaluate("target.secure_signing_time >= timestamp(0)", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
}

- (void)testNowAndWeekdays {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // weekdays() is the constant [1, 2, 3, 4, 5], Monday through Friday in the
    // 0=Sunday numbering. Being a constant it leaves the result cacheable.
    auto activation = MakeActivation<true>();
    auto result = sut.value()->CompileAndEvaluate("weekdays() == [1, 2, 3, 4, 5]", *activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertTrue(result.value().cacheable);
    }
  }
  {
    // now() is a timestamp, and using it must make the result non-cacheable.
    auto activation = MakeActivation<true>();
    auto result = sut.value()->CompileAndEvaluate("now() > timestamp(0)", *activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // Unlike today(), now() is not truncated to the start of the day: it is the
    // current instant, somewhere inside the local day today() starts. The upper
    // bound allows a 25 hour day, which is what a fall-back DST transition makes
    // of one.
    auto activation = MakeActivation<true>();
    auto result = sut.value()->CompileAndEvaluate(
        "now() >= today() && now() < today() + days(1) + duration('1h')", *activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
}

// today(): the start of the current civil day in the host's zone, and today(zone)
// the same in a named one, both read off this machine's clock.
- (void)testTodayInZone {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  auto evaluate = [&sut](absl::string_view expr) {
    auto activation = MakeActivation<true>();
    return sut.value()->CompileAndEvaluate(expr, *activation);
  };

  absl::Time now = absl::Now();

  {
    // The two rows below are the only ones that can catch today() reverting to
    // the UTC meaning it shipped with, and neither can do it on a host whose zone
    // is UTC, so they run against a pinned host zone with a nonzero offset.
    ScopedHostZone hostZone("America/New_York");

    {
      // The bare form is the "local" case of the same path, so asking for
      // "local" must give the same answer. A UTC truncation answers a different
      // instant here for every hour of every day.
      auto result = evaluate("today('local') == today()");
      if (!result.ok()) {
        XCTFail("Failed to evaluate: %s", result.status().message().data());
      } else {
        XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
        XCTAssertFalse(result.value().cacheable);
      }
    }
    {
      // And the value is the host's civil day start, computed here with absl
      // against the same pinned zone. Both candidate day starts are accepted,
      // because a local midnight landing between this clock read and the
      // evaluation moves the answer on to the next one; both are host-local
      // midnights, so a UTC truncation matches neither.
      absl::TimeZone host = absl::LocalTimeZone();
      absl::CivilDay hostDay{absl::ToCivilSecond(now, host)};

      auto result = evaluate(
          "today() == timestamp('" + AsUTCLiteral(absl::FromCivil(hostDay, host)) +
          "') || today() == timestamp('" + AsUTCLiteral(absl::FromCivil(hostDay + 1, host)) + "')");
      if (!result.ok()) {
        XCTFail("Failed to evaluate: %s", result.status().message().data());
      } else {
        XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      }
    }
  }
  {
    // Two zones an hour apart across a local midnight: right now it is 00:30 in
    // one and 23:30 of the day before in the other, so their civil days start 23
    // hours apart. A today() that ignored its zone would answer zero.
    int offsetAfterMidnight = OffsetWhereNowReads(now, 0, 30);
    std::string afterMidnight = FixedOffsetZone(offsetAfterMidnight);
    std::string beforeMidnight = FixedOffsetZone(offsetAfterMidnight - 60);

    auto result = evaluate("today('" + afterMidnight + "') - today('" + beforeMidnight +
                           "') == duration('23h')");
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      // The zone form alone has to mark the evaluation non-cacheable: nothing
      // here calls the bare today(), so this is the assertion that fails if the
      // sink is dropped from that path.
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // A named zone resolves and truncates to that zone's civil day. A New York
    // day starts at 04:00Z or 05:00Z, never at 00:00Z, so this is a different
    // instant from the UTC day start at every hour of every day; what varies
    // with the hour is only whether the two zones agree on the civil date. The
    // expectation is computed here rather than assumed.
    //
    // Both candidate day starts are accepted, because a New York midnight
    // landing between this clock read and the evaluation moves the answer on to
    // the next one. Both are New York midnights, so a today() that truncated in
    // UTC still matches neither.
    absl::TimeZone newYork;
    XCTAssertTrue(absl::LoadTimeZone("America/New_York", &newYork));
    absl::CivilDay newYorkDay{absl::ToCivilSecond(now, newYork)};

    auto result = evaluate("today('America/New_York') == timestamp('" +
                           AsUTCLiteral(absl::FromCivil(newYorkDay, newYork)) +
                           "') || today('America/New_York') == timestamp('" +
                           AsUTCLiteral(absl::FromCivil(newYorkDay + 1, newYork)) + "')");
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    }
  }
  {
    // An unresolvable zone fails the evaluation here too: the resolver is shared
    // with policy_for_range(), but this is a separate call site for its error.
    XCTAssertFalse(evaluate("today('Mars/Olympus') > timestamp(0)").ok());
  }
}

- (void)testNowIsNotConstantFolded {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto activation = MakeActivation<true>();

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  // A threshold three seconds out. The same compiled plan must answer BLOCKLIST
  // before that instant and ALLOWLIST after it: if now() were constant-folded
  // at compile time its value would be frozen before the threshold and both
  // evaluations would answer BLOCKLIST. The slack is for the compile and the
  // first evaluation, which take milliseconds on an idle machine but can take
  // far longer on a loaded CI one.
  // Quantized to the literal's millisecond precision so the compiled threshold,
  // the guard below, and the sleep all name the same instant.
  absl::Time thresholdTime =
      absl::FromUnixMillis(absl::ToUnixMillis(absl::Now() + absl::Seconds(3)));
  std::string threshold =
      absl::FormatTime("%Y-%m-%dT%H:%M:%E3SZ", thresholdTime, absl::UTCTimeZone());

  google::protobuf::Arena arena;
  auto expr = sut.value()->Compile("now() > timestamp('" + threshold + "')", &arena);
  if (!expr.ok()) {
    XCTFail("Failed to compile: %s", expr.status().message().data());
    return;
  }

  auto before = sut.value()->Evaluate(expr.value().get(), *activation, &arena);
  // If even three seconds was not enough for one compile and one evaluation,
  // fail on the timing assumption by name rather than blaming constant folding.
  XCTAssertLessThan(absl::Now(), thresholdTime,
                    @"compile plus first evaluation overran the threshold slack");
  if (!before.ok()) {
    XCTFail("Failed to evaluate: %s", before.status().message().data());
  } else {
    XCTAssertEqual(before.value().value, ReturnValue::BLOCKLIST);
  }

  // Sleep to just past the threshold, however much of the slack is left.
  absl::SleepFor(thresholdTime + absl::Milliseconds(500) - absl::Now());

  auto after = sut.value()->Evaluate(expr.value().get(), *activation, &arena);
  if (!after.ok()) {
    XCTFail("Failed to evaluate: %s", after.status().message().data());
  } else {
    XCTAssertEqual(after.value().value, ReturnValue::ALLOWLIST);
  }
}

// now() and policy_for_range() read the clock the activation was built with.
// today() does not, and that is deliberate: it is calendar truth from the system
// clock, which rules older than time windows already depend on, and putting it
// on a clock that only ever moves forward would make a stuck forward jump the
// date those rules see. The window case below is the mix that matters -- its
// edges come from now(), so the comparison is on one clock throughout.
- (void)testTheActivationsClockGovernsNowButNotToday {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  // A Wednesday noon UTC, an hour into a window that closed in January 2026 and
  // so can never contain the system clock again.
  absl::Time provided;
  std::string parseErr;
  XCTAssertTrue(absl::ParseTime(absl::RFC3339_full, "2026-01-07T12:00:00Z", &provided, &parseErr));

  auto evaluate = [&sut](absl::string_view expr, std::function<absl::Time()> now) {
    auto activation = MakeActivation<true>(std::move(now));
    return sut.value()->CompileAndEvaluate(expr, *activation);
  };

  // Each of these is true on the provided instant and cannot be true on the
  // system clock, so the answer says which clock was read.
  std::vector<std::string> onTheActivationsClock = {
      "now() == timestamp('2026-01-07T12:00:00Z')",
      "policy_for_range(now() - duration('1h'), timestamp('2026-01-07T13:00:00Z'), false, "
      "ALLOWLIST, BLOCKLIST)",
  };

  for (const std::string& expr : onTheActivationsClock) {
    auto onProvided = evaluate(expr, [provided] { return provided; });
    if (!onProvided.ok()) {
      XCTFail("Failed to evaluate '%s': %s", expr.c_str(), onProvided.status().message().data());
      continue;
    }
    XCTAssertEqual(onProvided.value().value, ReturnValue::ALLOWLIST, @"%s", expr.c_str());

    // The same expression on the system clock, which is not that instant.
    auto onSystemClock = evaluate(expr, absl::Now);
    if (!onSystemClock.ok()) {
      XCTFail("Failed to evaluate '%s': %s", expr.c_str(), onSystemClock.status().message().data());
      continue;
    }
    XCTAssertEqual(onSystemClock.value().value, ReturnValue::BLOCKLIST, @"%s", expr.c_str());
  }

  // today() answers from the system clock's day even though the activation
  // carries an instant months earlier. The day is the host's, computed here with
  // absl against the same zone rather than assumed to be UTC. Both candidate day
  // starts are accepted, because a local midnight landing between this clock read
  // and the evaluation moves the answer on to the next one.
  absl::TimeZone host = absl::LocalTimeZone();
  absl::CivilDay systemDay{absl::ToCivilSecond(absl::Now(), host)};
  auto systemDayResult =
      evaluate("today() == timestamp('" + AsUTCLiteral(absl::FromCivil(systemDay, host)) +
                   "') || today() == timestamp('" +
                   AsUTCLiteral(absl::FromCivil(systemDay + 1, host)) + "')",
               [provided] { return provided; });
  if (!systemDayResult.ok()) {
    XCTFail("Failed to evaluate today(): %s", systemDayResult.status().message().data());
  } else {
    XCTAssertEqual(systemDayResult.value().value, ReturnValue::ALLOWLIST);
  }
}

- (void)testRelativeTimestampsV1Unsupported {
  using ExecutableFileT = santa::cel::CELProtoTraits<false>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<false>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<false>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  santa::cel::Activation<false> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<false>::Create();
  XCTAssertTrue(sut.ok());

  // today() / days() are CELv2 only.
  auto result =
      sut.value()->CompileAndEvaluate("target.signing_time > today() - days(5)", activation);
  XCTAssertFalse(result.ok());

  // So are now() / weekdays().
  XCTAssertFalse(sut.value()->CompileAndEvaluate("now() > timestamp(0)", activation).ok());
  XCTAssertFalse(sut.value()->CompileAndEvaluate("weekdays() == [1]", activation).ok());
}

- (void)testAuditReturnValue {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  XCTAssertEqual(santa::cel::CELProtoTraits<true>::AUDIT, ::santa::cel::v2::AUDIT);

  auto f = std::make_unique<ExecutableFileT>();
  f->set_team_id("EQHXZ8M8AV");
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Static - AUDIT returned when team_id matches
    auto result = sut.value()->CompileAndEvaluate(
        "target.team_id == 'EQHXZ8M8AV' ? AUDIT : ALLOWLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::AUDIT);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Dynamic - AUDIT returned when args non-empty
    auto result = sut.value()->CompileAndEvaluate("size(args) > 0 ? AUDIT : ALLOWLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::AUDIT);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testV2Only {
  auto argsFn = ^std::vector<std::string>() {
    return {"hello", "world"};
  };
  auto envsFn = ^std::map<std::string, std::string>() {
    return {{"DYLD_INSERT_LIBRARIES", "1"}};
  };
  auto euidFn = ^uid_t() {
    return 0;
  };
  auto cwdFn = ^std::string() {
    return "/";
  };
  auto pathFn = ^std::string() {
    return "/usr/bin/test";
  };
  auto ancestorsV1Fn = ^std::vector<santa::cel::CELProtoTraits<false>::AncestorT>() {
    return {};
  };
  auto ancestorsV2Fn = ^std::vector<santa::cel::CELProtoTraits<true>::AncestorT>() {
    return {};
  };
  auto fdsV1Fn = ^std::vector<santa::cel::CELProtoTraits<false>::FileDescriptorT>() {
    return {};
  };
  auto fdsV2Fn = ^std::vector<santa::cel::CELProtoTraits<true>::FileDescriptorT>() {
    return {};
  };

  {
    // V1
    auto f = std::make_unique<santa::cel::CELProtoTraits<false>::ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    santa::cel::Activation<false> activation(std::move(f), argsFn, envsFn, euidFn, cwdFn, pathFn,
                                             ancestorsV1Fn, fdsV1Fn);
    auto sut = santa::cel::Evaluator<false>::Create();
    XCTAssertTrue(sut.ok());

    // V1 does not support the TOUCHID return value
    auto result =
        sut.value()->CompileAndEvaluate("euid == 0 ? REQUIRE_TOUCHID : BLOCKLIST", activation);
    XCTAssertFalse(result.ok());
  }

  {
    // V2
    using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
    auto f = std::make_unique<santa::cel::CELProtoTraits<true>::ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    santa::cel::Activation<true> activation(std::move(f), argsFn, envsFn, euidFn, cwdFn, pathFn,
                                            ancestorsV2Fn, fdsV2Fn);
    auto sut = santa::cel::Evaluator<true>::Create();
    XCTAssertTrue(sut.ok());

    // V2 _does_ support the TOUCHID return value
    auto result =
        sut.value()->CompileAndEvaluate("euid == 0 ? REQUIRE_TOUCHID : BLOCKLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testFds {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;
  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        FileDescriptorT fd0;
        fd0.set_fd(0);
        fd0.set_type(FileDescriptorT::FD_TYPE_VNODE);
        FileDescriptorT fd1;
        fd1.set_fd(1);
        fd1.set_type(FileDescriptorT::FD_TYPE_PIPE);
        FileDescriptorT fd2;
        fd2.set_fd(2);
        fd2.set_type(FileDescriptorT::FD_TYPE_SOCKET);
        return {fd0, fd1, fd2};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Test fds size
    auto result = sut.value()->CompileAndEvaluate("size(fds) == 3", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test fd number access
    auto result = sut.value()->CompileAndEvaluate("fds[0].fd == 0u", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test fd type enum comparison
    auto result = sut.value()->CompileAndEvaluate("fds[0].type == FD_TYPE_VNODE", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test exists comprehension over fds
    auto result =
        sut.value()->CompileAndEvaluate("fds.exists(f, f.type == FD_TYPE_SOCKET)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test no match with exists
    auto result =
        sut.value()->CompileAndEvaluate("fds.exists(f, f.type == FD_TYPE_KQUEUE)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testTouchIDCooldownFunctions {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Test require_touchid_with_cooldown_minutes returns REQUIRE_TOUCHID
    auto result =
        sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(10)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 10ULL);
    }
  }
  {
    // Test require_touchid_only_with_cooldown_minutes returns REQUIRE_TOUCHID_ONLY
    auto result = sut.value()->CompileAndEvaluate("require_touchid_only_with_cooldown_minutes(5)",
                                                  activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID_ONLY);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 5ULL);
    }
  }
  {
    // Test conditional usage with cooldown function
    auto result = sut.value()->CompileAndEvaluate(
        "euid == 0 ? require_touchid_with_cooldown_minutes(15) : ALLOWLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 15ULL);
    }
  }
  {
    // Test standard REQUIRE_TOUCHID constant (no cooldown function) - should have no cooldown
    auto result = sut.value()->CompileAndEvaluate("REQUIRE_TOUCHID", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertFalse(result.value().touchIDCooldownMinutes.has_value());
    }
  }
  {
    // Test negative value is treated as 0
    auto result =
        sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(-5)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 0ULL);
    }
  }
  {
    // Test zero cooldown
    auto result =
        sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(0)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 0ULL);
    }
  }
}

- (void)testTouchIDCooldownNotAvailableInV1 {
  using ExecutableFileT = santa::cel::CELProtoTraits<false>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<false>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<false>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation<false> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<false>::Create();
  XCTAssertTrue(sut.ok());

  // V1 should not support TouchID cooldown functions
  auto result =
      sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(10)", activation);
  XCTAssertFalse(result.ok());
}

- (void)testPolicyForRange {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  auto evaluate = [&sut](absl::string_view expr) {
    auto activation = MakeActivation<true>();
    return sut.value()->CompileAndEvaluate(expr, *activation);
  };

  // The current local day in the 0=Sunday numbering policy_for_range() uses,
  // which is what strftime's %w reports. Read from the same clock the function
  // reads, so the day-list cases below know which day is "today".
  std::string today = absl::FormatTime("%w", absl::Now(), absl::LocalTimeZone());
  std::string notToday = std::to_string((std::stoi(today) + 1) % 7);

  {
    // In range (the timestamp overload straddles now) returns the policy
    // argument, and any use of policy_for_range() is non-cacheable.
    auto result = evaluate(
        "policy_for_range(now() - duration('1h'), now() + duration('1h'), false, ALLOWLIST, "
        "BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // Out of range returns the out_of_range_policy argument, not a hardcoded
    // BLOCKLIST: SILENT_BLOCKLIST here proves the argument is what comes back.
    auto result = evaluate(
        "policy_for_range(now() + duration('1h'), now() + duration('2h'), false, ALLOWLIST, "
        "SILENT_BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::SILENT_BLOCKLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // Timestamp edges are the instants they name, offset included: these are
    // written as civil times in +05:30, so an evaluation that read them as UTC
    // would place the window five and a half hours in the past and answer
    // BLOCKLIST.
    absl::TimeZone offsetZone = absl::FixedTimeZone(5 * 3600 + 30 * 60);
    auto literal = [&offsetZone](absl::Time instant) {
      return absl::FormatTime("%Y-%m-%dT%H:%M:%S+05:30", instant, offsetZone);
    };
    absl::Time now = absl::Now();

    auto result = evaluate("policy_for_range(timestamp('" + literal(now - absl::Minutes(30)) +
                           "'), timestamp('" + literal(now + absl::Minutes(30)) +
                           "'), false, ALLOWLIST, BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    }
  }
  {
    // An empty day list is never in range.
    auto result = evaluate("policy_for_range([], '00:00', '00:00', false, ALLOWLIST, BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // Day list membership, HH:MM overload. Equal ends make the window the whole
    // day starting at 00:00, so the day it starts on is always today.
    auto inList = evaluate("policy_for_range([" + today +
                           "], '00:00', '00:00', false, ALLOWLIST, BLOCKLIST)");
    auto notInList = evaluate("policy_for_range([" + notToday +
                              "], '00:00', '00:00', false, ALLOWLIST, BLOCKLIST)");
    if (!inList.ok() || !notInList.ok()) {
      XCTFail(@"Failed to evaluate day list membership");
    } else {
      XCTAssertEqual(inList.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(notInList.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // HH:MM windows: whatever the local time is, exactly one of the morning
    // window and the midnight-crossing afternoon window contains it.
    auto morning = evaluate(
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], '00:00', '12:00', false, ALLOWLIST, BLOCKLIST)");
    auto crosser = evaluate(
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], '12:00', '00:00', false, ALLOWLIST, BLOCKLIST)");
    if (!morning.ok() || !crosser.ok()) {
      XCTFail(@"Failed to evaluate HH:MM windows");
    } else {
      XCTAssertNotEqual(morning.value().value, crosser.value().value);
      XCTAssertTrue(morning.value().value == ReturnValue::ALLOWLIST ||
                    crosser.value().value == ReturnValue::ALLOWLIST);
    }
  }
  {
    // Double-quoted times, exactly as the rule editor writes them.
    auto result = evaluate(
        "policy_for_range([1, 2, 3, 4, 5], \"09:00\", \"17:00\", false, ALLOWLIST, BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertTrue(result.value().value == ReturnValue::ALLOWLIST ||
                    result.value().value == ReturnValue::BLOCKLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // Block during the window, allow outside it: the policies are just
    // arguments, so the gate works in either direction.
    auto result = evaluate(
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], '00:00', '00:00', false, BLOCKLIST, ALLOWLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // The policy argument passes through untouched, so a TouchID policy keeps
    // its cooldown in range.
    auto result =
        evaluate("policy_for_range(now() - duration('1h'), now() + duration('1h'), false, "
                 "require_touchid_with_cooldown_minutes(30), BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 30ULL);
    }
  }
  {
    // And the same holds in the out_of_range_policy position.
    auto result = evaluate(
        "policy_for_range(now() + duration('1h'), now() + duration('2h'), false, ALLOWLIST, "
        "require_touchid_with_cooldown_minutes(15))");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 15ULL);
    }
  }
  {
    // The duration overload is always in range, so it always returns its policy.
    // It takes no out_of_range_policy for that reason.
    auto result = evaluate("policy_for_range(duration('30m'), false, ALLOWLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // should_kill records a pending kill (see testPolicyForRangePendingKill)
    // but has no effect on the decision.
    auto result = evaluate("policy_for_range(duration('30m'), true, ALLOWLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // weekdays() composes as the day list.
    auto result =
        evaluate("policy_for_range(weekdays(), '00:00', '00:00', false, ALLOWLIST, BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    }
  }
  {
    // Ternary composition with another condition.
    auto result =
        evaluate("'-y' in args ? policy_for_range(duration('30m'), true, ALLOWLIST) : BLOCKLIST");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // The policy in the untaken ternary branch is not what comes back: '-z' is
    // absent from args, so the answer is the else branch's BLOCKLIST and not the
    // ALLOWLIST held by the policy_for_range() call. Cacheability says nothing
    // here either way, since the 'in args' guard alone makes the result
    // non-cacheable.
    auto result =
        evaluate("'-z' in args ? policy_for_range(duration('30m'), true, ALLOWLIST) : BLOCKLIST");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // policy_for_range() returns a decision, not a bool, so && composition is
    // rejected at compile time; the ternary is the supported form.
    auto result = evaluate("policy_for_range(duration('30m'), false, ALLOWLIST) && '-y' in args");
    XCTAssertFalse(result.ok());
  }
  {
    // Malformed HH:MM fails the evaluation.
    auto result = evaluate("policy_for_range([1], '9:00', '17:00', false, ALLOWLIST, BLOCKLIST)");
    XCTAssertFalse(result.ok());
  }
  {
    // A day outside 0-6 fails the evaluation.
    auto result = evaluate("policy_for_range([7], '09:00', '17:00', false, ALLOWLIST, BLOCKLIST)");
    XCTAssertFalse(result.ok());
  }
  {
    // So does a zone that is neither "local", nor a name absl can load, nor a
    // [+-]HH:MM offset.
    auto result = evaluate(
        "policy_for_range([1], '09:00', '17:00', 'Mars/Olympus', false, ALLOWLIST, BLOCKLIST)");
    XCTAssertFalse(result.ok());
  }
  {
    // An absolute span carries no calendar, so there is no day-list form of it
    // and no zone form either: both fail to compile rather than silently
    // ignoring the extra arguments.
    XCTAssertFalse(
        evaluate("policy_for_range([1], now(), now() + duration('1h'), false, ALLOWLIST, "
                 "BLOCKLIST)")
            .ok());
    XCTAssertFalse(evaluate("policy_for_range([1], now(), now() + duration('1h'), 'local', false, "
                            "ALLOWLIST, BLOCKLIST)")
                       .ok());
    // Including the likeliest version of the mistake, a zone appended to the
    // span with no day list in front of it.
    XCTAssertFalse(evaluate("policy_for_range(now(), now() + duration('1h'), 'local', false, "
                            "ALLOWLIST, BLOCKLIST)")
                       .ok());
  }
  {
    // A non-positive duration fails the evaluation.
    auto result = evaluate("policy_for_range(duration('0s'), false, ALLOWLIST)");
    XCTAssertFalse(result.ok());
  }
}

/// A pending kill's times are measured from the instant the expression was
/// evaluated, a moment after the `now` the caller read. A few seconds of slack
/// covers that gap while still failing on a wrong lead, the smallest of which is
/// minutes.
- (void)assertTime:(absl::Time)got near:(absl::Time)want what:(NSString*)what {
  absl::Duration off = got - want;
  XCTAssertTrue(off > -absl::Seconds(5) && off < absl::Seconds(5), @"%@ is off by %s", what,
                absl::FormatDuration(off).c_str());
}

// The kill an in-window should_kill asks for: when it fires, when the user is
// warned, and the window shape that rides along for a restart re-check.
- (void)testPolicyForRangePendingKill {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  auto evaluate = [&sut](absl::string_view expr) {
    auto activation = MakeActivation<true>();
    return sut.value()->CompileAndEvaluate(expr, *activation);
  };

  // The day gate is not what any of these cases is probing, so they all name
  // every day: a list pinned to the day this test process read would flip out
  // from under an evaluation that straddles local midnight.
  {
    // A 30 minute grant: the lead is 10% of the window, three minutes.
    absl::Time now = absl::Now();
    auto result = evaluate("policy_for_range(duration('30m'), true, ALLOWLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertTrue(result.value().pendingKill.has_value());
      [self assertTime:result.value().pendingKill->deadline
                  near:now + absl::Minutes(30)
                  what:@"deadline"];
      [self assertTime:result.value().pendingKill->notify_at
                  near:now + absl::Minutes(27)
                  what:@"notify_at"];
      // The duration overload's window does not recur, so it carries no shape.
      XCTAssertTrue(result.value().pendingKill->window_days.empty());
      XCTAssertTrue(result.value().pendingKill->window_start.empty());
      XCTAssertTrue(result.value().pendingKill->window_end.empty());
      XCTAssertTrue(result.value().pendingKill->window_zone.empty());
    }
  }
  {
    // A nine hour window: 10% of it is longer than five minutes, so the lead is
    // capped at five.
    absl::Time now = absl::Now();
    auto result = evaluate(
        "policy_for_range(now() - duration('1h'), now() + duration('8h'), true, ALLOWLIST, "
        "BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertTrue(result.value().pendingKill.has_value());
      [self assertTime:result.value().pendingKill->deadline
                  near:now + absl::Hours(8)
                  what:@"deadline"];
      [self assertTime:result.value().pendingKill->notify_at
                  near:now + absl::Hours(8) - absl::Minutes(5)
                  what:@"notify_at"];
      // The absolute span names one occurrence, so it carries no shape either,
      // zone included: there is no later occurrence to re-check, and no calendar
      // was read to reach it.
      XCTAssertTrue(result.value().pendingKill->window_days.empty());
      XCTAssertTrue(result.value().pendingKill->window_zone.empty());
    }
  }
  {
    // An exec allowed in the window's last moments is warned about at once
    // rather than at a notify time that has already passed.
    absl::Time now = absl::Now();
    auto result = evaluate(
        "policy_for_range(now() - duration('1h'), now() + duration('1s'), true, ALLOWLIST, "
        "BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertTrue(result.value().pendingKill.has_value());
      [self assertTime:result.value().pendingKill->notify_at near:now what:@"notify_at"];
      XCTAssertTrue(result.value().pendingKill->notify_at >= now);
    }
  }
  {
    // should_kill false asks for nothing, in window or not.
    auto result = evaluate("policy_for_range(duration('30m'), false, ALLOWLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertFalse(result.value().pendingKill.has_value());
    }
  }
  {
    // Out of window nothing is asked for, even when the out_of_range_policy is
    // the one that allows the execution.
    auto result = evaluate(
        "policy_for_range(now() + duration('1h'), now() + duration('2h'), true, BLOCKLIST, "
        "ALLOWLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().pendingKill.has_value());
    }
  }
  {
    // The HH:MM overload recurs, so its shape is carried: the day list, both
    // times and the zone, exactly as written. Whatever the time is in the named
    // zone, exactly one of these two windows is open, so the one that recorded
    // is the open one. The zone is a named one rather than "local" so the
    // assertion below fails on a shape that defaulted its calendar instead of
    // carrying the rule's.
    auto morning = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '00:00', '12:00', "
                            "'America/New_York', true, ALLOWLIST, BLOCKLIST)");
    auto afternoon = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '12:00', '00:00', "
                              "'America/New_York', true, ALLOWLIST, BLOCKLIST)");
    if (!morning.ok() || !afternoon.ok()) {
      XCTFail(@"Failed to evaluate HH:MM windows");
    } else {
      XCTAssertNotEqual(morning.value().pendingKill.has_value(),
                        afternoon.value().pendingKill.has_value());
      bool isMorning = morning.value().pendingKill.has_value();
      const auto& kill = isMorning ? *morning.value().pendingKill : *afternoon.value().pendingKill;
      XCTAssertTrue(kill.window_days == (std::vector<int64_t>{0, 1, 2, 3, 4, 5, 6}));
      XCTAssertEqualObjects(@(kill.window_start.c_str()), isMorning ? @"00:00" : @"12:00");
      XCTAssertEqualObjects(@(kill.window_end.c_str()), isMorning ? @"12:00" : @"00:00");
      XCTAssertEqualObjects(@(kill.window_zone.c_str()), @"America/New_York");
    }
  }
  // Nested policy_for_range() calls. Workshop rejects this form at authoring
  // time, so it never arrives, but CEL evaluates every argument eagerly: the
  // inner call records its deadline even from a slot the outer call discards.
  {
    // Both calls run whichever holds the earlier deadline, and the earlier
    // deadline is what comes back.
    absl::Time now = absl::Now();
    auto innerEarlier = evaluate("policy_for_range(duration('1h'), true, "
                                 "policy_for_range(duration('30m'), true, ALLOWLIST))");
    auto outerEarlier = evaluate("policy_for_range(duration('30m'), true, "
                                 "policy_for_range(duration('1h'), true, ALLOWLIST))");
    if (!innerEarlier.ok() || !outerEarlier.ok()) {
      XCTFail(@"Failed to evaluate nested policy_for_range()");
    } else {
      XCTAssertTrue(innerEarlier.value().pendingKill.has_value());
      XCTAssertTrue(outerEarlier.value().pendingKill.has_value());
      [self assertTime:innerEarlier.value().pendingKill->deadline
                  near:now + absl::Minutes(30)
                  what:@"inner-first deadline"];
      [self assertTime:outerEarlier.value().pendingKill->deadline
                  near:now + absl::Minutes(30)
                  what:@"outer-first deadline"];
    }
  }
  {
    // The whole-day window closes within 25 hours, so its shape is the one that
    // comes back; with no zone argument that shape records "local", not empty.
    auto result = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '00:00', '00:00', true, "
                           "policy_for_range(duration('48h'), true, ALLOWLIST), BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertTrue(result.value().pendingKill.has_value());
      XCTAssertEqual(result.value().pendingKill->window_days.size(), 7UL);
      XCTAssertEqualObjects(@(result.value().pendingKill->window_start.c_str()), @"00:00");
      XCTAssertEqualObjects(@(result.value().pendingKill->window_zone.c_str()), @"local");
    }
  }
  {
    // An empty day list is never in range, so the outer window is closed and the
    // only kill is the inner grant's, recorded from a slot that was discarded.
    auto result = evaluate("policy_for_range([], '00:00', '00:00', true, "
                           "policy_for_range(duration('30m'), true, ALLOWLIST), BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
      XCTAssertTrue(result.value().pendingKill.has_value());
      XCTAssertTrue(result.value().pendingKill->window_days.empty());
      XCTAssertTrue(result.value().pendingKill->window_start.empty());
      XCTAssertTrue(result.value().pendingKill->window_zone.empty());
    }
  }
}

// The zone argument, and its absence, reaching the window math through the full
// rule path. Every case builds its zones and times from the current instant, so
// they answer the same way whatever time it is; the cases that turn on what the
// host's zone is pin it rather than reading whatever the machine happens to be
// set to. The zone math itself is pinned in testPolicyForRangeWindowMath.
- (void)testPolicyForRangeZone {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  auto evaluate = [&sut](absl::string_view expr) {
    auto activation = MakeActivation<true>();
    return sut.value()->CompileAndEvaluate(expr, *activation);
  };

  absl::Time now = absl::Now();

  {
    // HH:MM overload: an 11:00 to 13:00 window holds the instant in the zone
    // where it is 12:00 and not in the zone where it is 00:00. Every day is
    // listed and the expressions are otherwise identical, so only the zone
    // argument can account for the difference.
    std::string noon = FixedOffsetZone(OffsetWhereNowReads(now, 12, 0));
    std::string midnight = FixedOffsetZone(OffsetWhereNowReads(now, 0, 0));

    auto inZone = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '11:00', '13:00', '" + noon +
                           "', false, ALLOWLIST, BLOCKLIST)");
    auto outOfZone = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '11:00', '13:00', '" +
                              midnight + "', false, ALLOWLIST, BLOCKLIST)");
    if (!inZone.ok() || !outOfZone.ok()) {
      XCTFail(@"Failed to evaluate HH:MM window under a named zone");
    } else {
      XCTAssertEqual(inZone.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(outOfZone.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // No zone argument means the host's zone, which is what "local" spells out.
    // The window is the hour either side of the host's current clock time, so it
    // is in range in the host's zone: the two forms have to agree, and a default
    // of anything more than an hour off the host's clock would show up as a
    // BLOCKLIST from the six argument form. The host zone is pinned because that
    // last sentence is vacuous on a UTC host, which is where CI runs.
    ScopedHostZone hostZone("America/New_York");

    auto hostLocalHourMinute = [](absl::Time instant) {
      return absl::FormatTime("%H:%M", instant, absl::LocalTimeZone());
    };
    std::string start = hostLocalHourMinute(now - absl::Hours(1));
    std::string end = hostLocalHourMinute(now + absl::Hours(1));

    auto defaulted = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '" + start + "', '" + end +
                              "', false, ALLOWLIST, BLOCKLIST)");
    auto spelled = evaluate("policy_for_range([0, 1, 2, 3, 4, 5, 6], '" + start + "', '" + end +
                            "', 'local', false, ALLOWLIST, BLOCKLIST)");
    if (!defaulted.ok() || !spelled.ok()) {
      XCTFail(@"Failed to evaluate the defaulted and spelled out local forms");
    } else {
      XCTAssertEqual(defaulted.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(spelled.value().value, defaulted.value().value);
    }
  }
  {
    // A named zone answers the same on every host: one expression, evaluated
    // under two different host zones, has to give one decision. This is what the
    // zone argument is for, so it is worth asserting rather than assuming.
    std::string expr = "policy_for_range([0, 1, 2, 3, 4, 5, 6], '11:00', '13:00', '" +
                       FixedOffsetZone(OffsetWhereNowReads(now, 12, 0)) +
                       "', false, ALLOWLIST, BLOCKLIST)";

    auto evaluateOnHost = [&evaluate](const char* hostZone, absl::string_view expression) {
      ScopedHostZone pinned(hostZone);
      return evaluate(expression);
    };
    auto inNewYork = evaluateOnHost("America/New_York", expr);
    auto inKolkata = evaluateOnHost("Asia/Kolkata", expr);
    if (!inNewYork.ok() || !inKolkata.ok()) {
      XCTFail(@"Failed to evaluate a named zone under two host zones");
    } else {
      XCTAssertEqual(inNewYork.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(inKolkata.value().value, inNewYork.value().value);
    }
  }
}

// The zone argument's grammar, at the resolver itself: every function that takes
// a zone shares this one function, and the rule path can only reach a handful of
// its cases.
- (void)testResolveTimeZone {
  absl::TimeZone newYork;
  XCTAssertTrue(absl::LoadTimeZone("America/New_York", &newYork));

  struct Case {
    absl::string_view zone;
    // The zone the string must resolve to, or nullopt when it must not resolve
    // at all. Zones are compared as zones, not by their offset at some instant:
    // two zones can share an offset and still be different calendars, and a
    // "local" row that only checked the offset could not fail on a UTC host.
    std::optional<absl::TimeZone> resolvesTo;
  };

  const std::vector<Case> cases = {
      {"local", absl::LocalTimeZone()},
      {"UTC", absl::UTCTimeZone()},
      {"America/New_York", newYork},
      {"+05:30", absl::FixedTimeZone(5 * 3600 + 30 * 60)},
      {"-08:00", absl::FixedTimeZone(-8 * 3600)},
      {"+00:00", absl::FixedTimeZone(0)},
      // Neither a name the zone loader knows nor an offset.
      {"Mars/Olympus", std::nullopt},
      // Offsets are strict: the sign is required and the width is exact.
      {"05:30", std::nullopt},
      {"+5:30", std::nullopt},
      {"", std::nullopt},
      // The zone loader would take each of these and open a rule-named path as
      // a tzfile: a "file:" prefix, an absolute path, or a traversal out of its
      // zoneinfo directory. All three are rejected before it gets the chance.
      {"file:/etc/localtime", std::nullopt},
      {"/etc/localtime", std::nullopt},
      {"America/../../etc/localtime", std::nullopt},
  };

  for (const Case& c : cases) {
    std::string zone(c.zone);
    absl::StatusOr<absl::TimeZone> resolved = santa::cel::ResolveTimeZone(c.zone);

    if (!c.resolvesTo.has_value()) {
      XCTAssertFalse(resolved.ok(), "zone '%s' must not resolve", zone.c_str());
    } else if (!resolved.ok()) {
      XCTFail("zone '%s' failed to resolve: %s", zone.c_str(), resolved.status().message().data());
    } else {
      XCTAssertTrue(resolved.value() == c.resolvesTo.value(), "zone '%s' resolved to %s",
                    zone.c_str(), resolved->name().c_str());
    }
  }
}

// The window math itself, exercised directly at fixed instants in a fixed time
// zone: the CEL-level cases above can only ever ask about the current instant in
// the host's zone, which cannot reach a calendar edge or a DST transition.
- (void)testPolicyForRangeWindowMath {
  absl::TimeZone zone;
  XCTAssertTrue(absl::LoadTimeZone("America/Los_Angeles", &zone));

  auto local = [&zone](int year, int month, int day, int hour, int minute) {
    return absl::FromCivil(absl::CivilSecond(year, month, day, hour, minute, 0), zone);
  };

  // 2026-06-10 is a Wednesday (day 3), 2026-06-11 a Thursday (day 4).
  const std::vector<int64_t> wednesday = {3};
  const std::vector<int64_t> thursday = {4};

  {
    // A plain same-day window, in range.
    auto result = santa::cel::EvalDaysHHMMWindow(wednesday, "09:00", "17:00",
                                                 local(2026, 6, 10, 13, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 6, 10, 17, 0));
    XCTAssertTrue(result->window_length == absl::Hours(8));
  }
  {
    // Membership is start <= now < end: closed at the start, open at the end.
    auto atStart =
        santa::cel::EvalDaysHHMMWindow(wednesday, "09:00", "17:00", local(2026, 6, 10, 9, 0), zone);
    auto atEnd = santa::cel::EvalDaysHHMMWindow(wednesday, "09:00", "17:00",
                                                local(2026, 6, 10, 17, 0), zone);
    XCTAssertTrue(atStart.ok());
    XCTAssertTrue(atEnd.ok());
    XCTAssertTrue(atStart->in_range);
    XCTAssertFalse(atEnd->in_range);
  }
  {
    // The day list is checked against the day the window starts, not the day
    // asked about.
    auto result = santa::cel::EvalDaysHHMMWindow(thursday, "09:00", "17:00",
                                                 local(2026, 6, 10, 13, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertFalse(result->in_range);
  }
  {
    // An end at or before the start crosses midnight. Before midnight the
    // occurrence ends the next day.
    auto result = santa::cel::EvalDaysHHMMWindow(wednesday, "22:00", "02:00",
                                                 local(2026, 6, 10, 23, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 6, 11, 2, 0));
    XCTAssertTrue(result->window_length == absl::Hours(4));
  }
  {
    // After midnight the same occurrence still governs: it started Wednesday,
    // so Wednesday is the day the list must contain.
    auto result = santa::cel::EvalDaysHHMMWindow(wednesday, "22:00", "02:00",
                                                 local(2026, 6, 11, 0, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 6, 11, 2, 0));
    XCTAssertTrue(result->window_length == absl::Hours(4));

    // Thursday is when it is asked about, which is not what the list checks.
    auto onThursday =
        santa::cel::EvalDaysHHMMWindow(thursday, "22:00", "02:00", local(2026, 6, 11, 0, 30), zone);
    XCTAssertTrue(onThursday.ok());
    XCTAssertFalse(onThursday->in_range);
  }
  {
    // Equal ends cover the whole day, starting on the listed day.
    auto result = santa::cel::EvalDaysHHMMWindow(wednesday, "09:00", "09:00",
                                                 local(2026, 6, 10, 13, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 6, 11, 9, 0));
    XCTAssertTrue(result->window_length == absl::Hours(24));
  }
  {
    // Wednesday morning is still inside the occurrence that started Tuesday.
    auto result =
        santa::cel::EvalDaysHHMMWindow({2}, "09:00", "09:00", local(2026, 6, 10, 8, 0), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 6, 10, 9, 0));
  }
  {
    // Spring forward: 2026-03-08 (a Sunday) skips 02:00 to 03:00 local, so a
    // 01:00 to 03:00 window is one hour long, not two.
    auto result =
        santa::cel::EvalDaysHHMMWindow({0}, "01:00", "03:00", local(2026, 3, 8, 1, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 3, 8, 3, 0));
    XCTAssertTrue(result->window_length == absl::Hours(1));
  }
  {
    // A window whose start falls in the skipped hour begins at the transition.
    auto result =
        santa::cel::EvalDaysHHMMWindow({0}, "02:30", "04:00", local(2026, 3, 8, 3, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 3, 8, 4, 0));
    XCTAssertTrue(result->window_length == absl::Hours(1));
  }
  {
    // Fall back: 2026-11-01 (a Sunday) repeats 01:00 to 02:00 local, so a 00:30
    // to 02:00 window is two and a half hours long, and both passes through the
    // repeated hour are inside it.
    absl::Time firstPass = local(2026, 11, 1, 1, 30);
    auto result = santa::cel::EvalDaysHHMMWindow({0}, "00:30", "02:00", firstPass, zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == local(2026, 11, 1, 2, 0));
    XCTAssertTrue(result->window_length == absl::Minutes(150));

    auto secondPass =
        santa::cel::EvalDaysHHMMWindow({0}, "00:30", "02:00", firstPass + absl::Hours(1), zone);
    XCTAssertTrue(secondPass.ok());
    XCTAssertTrue(secondPass->in_range);
  }
  {
    // Both edges inside the repeated hour: 01:15 and 01:45 each resolve to their
    // first occurrence, so the window is a real 30 minutes and it fires on the
    // first pass only. By the second pass through 01:30 it is already over.
    absl::Time firstPass = local(2026, 11, 1, 1, 30);
    auto result = santa::cel::EvalDaysHHMMWindow({0}, "01:15", "01:45", firstPass, zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_length == absl::Minutes(30));

    auto secondPass =
        santa::cel::EvalDaysHHMMWindow({0}, "01:15", "01:45", firstPass + absl::Hours(1), zone);
    XCTAssertTrue(secondPass.ok());
    XCTAssertFalse(secondPass->in_range);
  }
  {
    // Unparseable HH:MM has no window to test.
    for (absl::string_view bad : {"9:00", "24:00", "09:60", "0900", "09-00", "09:00:00", ""}) {
      XCTAssertFalse(
          santa::cel::EvalDaysHHMMWindow(wednesday, bad, "17:00", local(2026, 6, 10, 13, 30), zone)
              .ok());
      XCTAssertFalse(
          santa::cel::EvalDaysHHMMWindow(wednesday, "09:00", bad, local(2026, 6, 10, 13, 30), zone)
              .ok());
    }
  }
  {
    // Days are 0 (Sunday) through 6 (Saturday).
    absl::Time now = local(2026, 6, 10, 13, 30);
    XCTAssertFalse(santa::cel::EvalDaysHHMMWindow({7}, "09:00", "17:00", now, zone).ok());
    XCTAssertFalse(santa::cel::EvalDaysHHMMWindow({-1}, "09:00", "17:00", now, zone).ok());
  }
  {
    // An absolute span is [start, end) against the instant asked about, with no
    // calendar in it: closed at the start, open at the end, and nothing else to
    // say. A span crossing midnight needs no separate case for that reason.
    absl::Time start = local(2026, 6, 10, 9, 0);
    absl::Time end = local(2026, 6, 10, 17, 0);

    santa::cel::WindowEval inside =
        santa::cel::EvalTimestampWindow(start, end, local(2026, 6, 10, 13, 30));
    XCTAssertTrue(inside.in_range);
    XCTAssertTrue(inside.window_end == end);
    XCTAssertTrue(inside.window_length == absl::Hours(8));

    XCTAssertTrue(santa::cel::EvalTimestampWindow(start, end, start).in_range);
    XCTAssertFalse(santa::cel::EvalTimestampWindow(start, end, local(2026, 6, 10, 8, 59)).in_range);
    XCTAssertFalse(santa::cel::EvalTimestampWindow(start, end, end).in_range);
  }
  {
    // A duration window runs from the instant asked about, so it is always in
    // range.
    absl::Time now = local(2026, 6, 10, 13, 30);
    santa::cel::WindowEval result = santa::cel::EvalDurationWindow(absl::Minutes(30), now);
    XCTAssertTrue(result.in_range);
    XCTAssertTrue(result.window_end == now + absl::Minutes(30));
    XCTAssertTrue(result.window_length == absl::Minutes(30));
  }
}

- (void)testPolicyForRangeNotAvailableInV1 {
  auto activation = MakeActivation<false>();

  auto sut = santa::cel::Evaluator<false>::Create();
  XCTAssertTrue(sut.ok());

  // policy_for_range() is CELv2 only.
  XCTAssertFalse(
      sut.value()
          ->CompileAndEvaluate("policy_for_range(duration('30m'), false, ALLOWLIST)", *activation)
          .ok());
}

@end
