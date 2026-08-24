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

#include <memory>
#include <optional>
#include <string>
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
template <bool IsV2>
std::unique_ptr<santa::cel::Activation<IsV2>> MakeActivation() {
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
      });
}

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
    // Unlike today(), now() is not truncated to the start of the UTC day: it is
    // the current instant, somewhere inside the day today() starts.
    auto activation = MakeActivation<true>();
    auto result = sut.value()->CompileAndEvaluate("now() >= today() && now() < today() + days(1)",
                                                  *activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
}

- (void)testNowIsNotConstantFolded {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;

  auto activation = MakeActivation<true>();

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  // A threshold one second out. The same compiled plan must answer BLOCKLIST
  // before that instant and ALLOWLIST after it: if now() were constant-folded
  // at compile time its value would be frozen before the threshold and both
  // evaluations would answer BLOCKLIST. The one second of slack is for the
  // compile and the first evaluation, which take milliseconds.
  std::string threshold =
      absl::FormatTime("%Y-%m-%dT%H:%M:%E3SZ", absl::Now() + absl::Seconds(1), absl::UTCTimeZone());

  google::protobuf::Arena arena;
  auto expr = sut.value()->Compile("now() > timestamp('" + threshold + "')", &arena);
  if (!expr.ok()) {
    XCTFail("Failed to compile: %s", expr.status().message().data());
    return;
  }

  auto before = sut.value()->Evaluate(expr.value().get(), *activation, &arena);
  if (!before.ok()) {
    XCTFail("Failed to evaluate: %s", before.status().message().data());
  } else {
    XCTAssertEqual(before.value().value, ReturnValue::BLOCKLIST);
  }

  absl::SleepFor(absl::Milliseconds(1500));

  auto after = sut.value()->Evaluate(expr.value().get(), *activation, &arena);
  if (!after.ok()) {
    XCTFail("Failed to evaluate: %s", after.status().message().data());
  } else {
    XCTAssertEqual(after.value().value, ReturnValue::ALLOWLIST);
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
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], now() - duration('1h'), now() + duration('1h'), "
        "false, ALLOWLIST, BLOCKLIST)");
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
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], now() + duration('1h'), now() + duration('2h'), "
        "false, ALLOWLIST, SILENT_BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::SILENT_BLOCKLIST);
      XCTAssertFalse(result.value().cacheable);
    }
  }
  {
    // An empty day list is never in range.
    auto result = evaluate(
        "policy_for_range([], now() - duration('1h'), now() + duration('1h'), false, ALLOWLIST, "
        "BLOCKLIST)");
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // Day list membership, timestamp overload: the day checked is the day of the
    // evaluation instant.
    auto inList = evaluate("policy_for_range([" + today +
                           "], now() - duration('1h'), now() + duration('1h'), false, ALLOWLIST, "
                           "BLOCKLIST)");
    auto notInList = evaluate("policy_for_range([" + notToday +
                              "], now() - duration('1h'), now() + duration('1h'), false, "
                              "ALLOWLIST, BLOCKLIST)");
    if (!inList.ok() || !notInList.ok()) {
      XCTFail(@"Failed to evaluate day list membership");
    } else {
      XCTAssertEqual(inList.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(notInList.value().value, ReturnValue::BLOCKLIST);
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
    auto result =
        evaluate("policy_for_range([1, 2, 3, 4, 5], \"09:00\", \"17:00\", false, ALLOWLIST, "
                 "BLOCKLIST)");
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
    auto result = evaluate(
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], now() - duration('1h'), now() + duration('1h'), "
        "false, require_touchid_with_cooldown_minutes(30), BLOCKLIST)");
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
        "policy_for_range([0, 1, 2, 3, 4, 5, 6], now() + duration('1h'), now() + duration('2h'), "
        "false, ALLOWLIST, require_touchid_with_cooldown_minutes(15))");
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
    // should_kill is type-checked but has no effect on the decision.
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
    // A non-positive duration fails the evaluation.
    auto result = evaluate("policy_for_range(duration('0s'), false, ALLOWLIST)");
    XCTAssertFalse(result.ok());
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
    XCTAssertFalse(santa::cel::EvalDaysTimestampWindow({7}, now - absl::Hours(1),
                                                       now + absl::Hours(1), now, zone)
                       .ok());
  }
  {
    // The timestamp overload takes the window as absolute instants; the day
    // checked is the day of the instant asked about.
    absl::Time start = local(2026, 6, 10, 9, 0);
    absl::Time end = local(2026, 6, 10, 17, 0);
    auto result = santa::cel::EvalDaysTimestampWindow(wednesday, start, end,
                                                      local(2026, 6, 10, 13, 30), zone);
    XCTAssertTrue(result.ok());
    XCTAssertTrue(result->in_range);
    XCTAssertTrue(result->window_end == end);
    XCTAssertTrue(result->window_length == absl::Hours(8));

    auto wrongDay =
        santa::cel::EvalDaysTimestampWindow(thursday, start, end, local(2026, 6, 10, 13, 30), zone);
    XCTAssertTrue(wrongDay.ok());
    XCTAssertFalse(wrongDay->in_range);

    auto before =
        santa::cel::EvalDaysTimestampWindow(wednesday, start, end, local(2026, 6, 10, 8, 59), zone);
    XCTAssertTrue(before.ok());
    XCTAssertFalse(before->in_range);

    auto atEnd = santa::cel::EvalDaysTimestampWindow(wednesday, start, end, end, zone);
    XCTAssertTrue(atEnd.ok());
    XCTAssertFalse(atEnd->in_range);
  }
  {
    // Unlike the HH:MM overload, a timestamp window that crosses midnight is
    // checked against the day of the instant asked about, not the day it
    // started.
    absl::Time start = local(2026, 6, 10, 22, 0);
    absl::Time end = local(2026, 6, 11, 2, 0);
    absl::Time now = local(2026, 6, 11, 0, 30);
    auto onThursday = santa::cel::EvalDaysTimestampWindow(thursday, start, end, now, zone);
    XCTAssertTrue(onThursday.ok());
    XCTAssertTrue(onThursday->in_range);

    auto onWednesday = santa::cel::EvalDaysTimestampWindow(wednesday, start, end, now, zone);
    XCTAssertTrue(onWednesday.ok());
    XCTAssertFalse(onWednesday->in_range);
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
