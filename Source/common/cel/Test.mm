/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/Evaluator.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <optional>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/arena.h"

@interface CELTest : XCTestCase
@end

@implementation CELTest

- (void)testBasic {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
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
    // Re-use of a compiled expression.
    auto expr = sut.value()->Compile("target.signing_time >= timestamp('2025-05-28T12:00:00Z')");
    if (!expr.ok()) {
      XCTFail("Failed to compile: %s", expr.status().message().data());
    }

    auto result = sut.value()->Evaluate(expr.value().get(), activation);
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
        });

    auto result2 = sut.value()->Evaluate(expr.value().get(), activation2);
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
    // Test memoization
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

  {
    // V1
    auto f = std::make_unique<santa::cel::CELProtoTraits<false>::ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    santa::cel::Activation<false> activation(std::move(f), argsFn, envsFn, euidFn, cwdFn);
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
    santa::cel::Activation<true> activation(std::move(f), argsFn, envsFn, euidFn, cwdFn);
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

- (void)testTouchIDCooldownFunctions {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;

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
      });

  auto sut = santa::cel::Evaluator<false>::Create();
  XCTAssertTrue(sut.ok());

  // V1 should not support TouchID cooldown functions
  auto result =
      sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(10)", activation);
  XCTAssertFalse(result.ok());
}

@end
