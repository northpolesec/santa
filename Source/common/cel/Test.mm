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
#include "Source/common/cel/Evaluator.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <optional>

#include "Source/common/cel/cel.pb.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/arena.h"

namespace pbv1 = ::santa::cel::v1;

@interface CELTest : XCTestCase
@end

@implementation CELTest

- (void)testBasic {
  auto f = std::make_unique<::pbv1::ExecutableFile>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {{"DYLD_INSERT_LIBRARIES", "1"}};
      });

  auto sut = santa::cel::Evaluator::Create();
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
      XCTAssertEqual(result.value().first, pbv1::ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().second, true);
    }
  }
  {
    // Timestamp comparison by date string.
    auto result = sut.value()->CompileAndEvaluate(
        "target.signing_time >= timestamp('2025-05-28T12:00:00Z')", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().first, pbv1::ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().second, true);
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
      XCTAssertEqual(result.value().first, pbv1::ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().second, true);
    }

    auto f2 = std::make_unique<::pbv1::ExecutableFile>();
    f2->mutable_signing_time()->set_seconds(1716916129);
    santa::cel::Activation activation2(
        std::move(f2),
        ^std::vector<std::string>() {
          return {"hello", "world"};
        },
        ^std::map<std::string, std::string>() {
          return {{"DYLD_INSERT_LIBRARIES", "1"}};
        });

    auto result2 = sut.value()->Evaluate(expr.value().get(), activation2);
    if (!result2.ok()) {
      XCTFail("Failed to evaluate: %s", result2.status().message().data());
    } else {
      XCTAssertEqual(result2.value().first, pbv1::ReturnValue::BLOCKLIST);
      XCTAssertEqual(result2.value().second, true);
    }
  }
  {
    // Dynamic - process args
    auto result = sut.value()->CompileAndEvaluate("args[0] == 'hello'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().first, pbv1::ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().second, false);
    }
  }
  {
    // Dynamic, env vars, ternary
    auto result = sut.value()->CompileAndEvaluate(
        "! has(envs.DYLD_INSERT_LIBRARIES) ? ALLOWLIST : BLOCKLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().first, pbv1::ReturnValue::BLOCKLIST);
      XCTAssertEqual(result.value().second, false);
    }
  }
  {
    // Test memoization
    __block int argsCallCount = 0;
    santa::cel::Activation activation(
        std::move(f),
        ^std::vector<std::string>() {
          argsCallCount++;
          return {"hello", "world"};
        },
        ^std::map<std::string, std::string>() {
          return {{"DYLD_INSERT_LIBRARIES", "1"}};
        });

    auto result = sut.value()->CompileAndEvaluate(
        "args[0] == 'foo' || args[0] == 'bar' || args[0] == 'hello'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().first, pbv1::ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().second, false);
    }
    XCTAssertEqual(argsCallCount, 1);
  }
}

@end
