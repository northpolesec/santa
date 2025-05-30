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

#include "Source/common/CEL.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <optional>

#include "Source/common/CEL.pb.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/protobuf/arena.h"
#include "sync/v1.pb.h"

namespace syncv1 = ::santa::sync::v1;
namespace pbv1 = ::santa::cel::v1;

@interface CELTest : XCTestCase
@end

@implementation CELTest

- (void)testBasic {
  google::protobuf::Arena arena;
  auto e = google::protobuf::Arena::Create<::pbv1::CELStaticContext>(&arena);

  e->mutable_binary()->mutable_signing_timestamp()->set_seconds(1748436989);

  santa::CELEvaluator sut;
  if (auto result = sut.Initialize(); !result.ok()) {
    XCTFail("Failed to initialize: %s", result.message().data());
  }

  {
    // Test bad expression.
    auto result = sut.CompileAndEvaluate("foo", e, nil);
    if (result.ok()) XCTFail("Expected failure to evaluate, got ok!");
  }
  {
    // Timestamp comparison by seconds.
    auto result =
        sut.CompileAndEvaluate("binary.signing_timestamp >= timestamp(1748436989)", e, nil);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value(), syncv1::Policy::ALLOWLIST);
    }
  }
  {
    // Timestamp comparison by date string.
    auto result = sut.CompileAndEvaluate(
        "binary.signing_timestamp >= timestamp('2025-05-28T12:00:00Z')", e, nil);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value(), syncv1::Policy::ALLOWLIST);
    }
  }
  {
    // Re-use of a compiled expression.
    auto expr = sut.Compile("binary.signing_timestamp >= timestamp('2025-05-28T12:00:00Z')");
    if (!expr.ok()) {
      XCTFail("Failed to compile: %s", expr.status().message().data());
    }

    auto result = sut.Evaluate(expr.value().get(), e, nil);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value(), syncv1::Policy::ALLOWLIST);
    }

    ::pbv1::CELStaticContext *e2 =
        google::protobuf::Arena::Create<::pbv1::CELStaticContext>(&arena);
    e2->mutable_binary()->mutable_signing_timestamp()->set_seconds(1716916129);
    auto result2 = sut.Evaluate(expr.value().get(), e2, nil);
    if (!result2.ok()) {
      XCTFail("Failed to evaluate: %s", result2.status().message().data());
    } else {
      XCTAssertEqual(result2.value(), syncv1::Policy::BLOCKLIST);
    }
  }
  {
    // Dynamic - process args
    auto result = sut.CompileAndEvaluate(
        "getDynamic().process.args[0] == 'hello'", e,
        ^::pbv1::CELDynamicContext *(google::protobuf::Arena *arena) {
          auto dyn = google::protobuf::Arena::Create<::pbv1::CELDynamicContext>(arena);
          dyn->mutable_process()->mutable_args()->Add("hello");
          dyn->mutable_process()->mutable_args()->Add("world");
          return dyn;
        });
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value(), syncv1::Policy::ALLOWLIST);
    }
  }
  {
    // Dynamic, env vars, ternary
    auto result = sut.CompileAndEvaluate(
        "'DYLD_INSERT_LIBRARIES=1' in getDynamic().process.envs ? santa.sync.v1.Policy.ALLOWLIST : "
        "santa.sync.v1.Policy.BLOCKLIST",
        e, ^::pbv1::CELDynamicContext *(google::protobuf::Arena *arena) {
          auto dyn = google::protobuf::Arena::Create<::pbv1::CELDynamicContext>(arena);
          dyn->mutable_process()->mutable_envs()->Add("DYLD_INSERT_LIBRARIES=1");
          return dyn;
        });
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value(), syncv1::Policy::ALLOWLIST);
    }
  }
}

@end
