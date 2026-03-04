/// Copyright 2026 North Pole Security, Inc.
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

#include <mach/mach.h>
#include <cstddef>
#include <string>
#include <vector>

#include "absl/status/statusor.h"

static size_t GetResidentMemoryBytes() {
  mach_task_basic_info_data_t info;
  mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
  if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) !=
      KERN_SUCCESS) {
    return 0;
  }
  return info.resident_size;
}

@interface ArenaGrowthTest : XCTestCase
@end

@implementation ArenaGrowthTest

/// Demonstrates unbounded arena growth in CompileAndEvaluate.
///
/// This reproduces usage for a reported bug: the Evaluator holds a
/// single protobuf Arena that is used for every compile+evaluate cycle. Since
/// Arena is a monotonic bump allocator that never frees individual allocations,
/// every evaluation leaks materialized variable values (args strings, env maps,
/// etc.) and compilation temporaries.
///
/// The test mimics the real-world trigger: a TEAMID CEL rule with
/// `args.exists(...)` evaluated on every matching exec event. With high-frequency
/// processes like VS Code/yarn/node, this grows without bound.
- (void)testCompileAndEvaluateArenaGrowth {
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;

  // Create an evaluator (holds a single Arena for its lifetime).
  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok(), @"Failed to create evaluator: %s", sut.status().message().data());

  // Build a large args list to amplify per-evaluation arena allocation.
  // This simulates a process like `node` or `yarn` with many arguments.
  std::vector<std::string> largeArgs;
  largeArgs.reserve(200);
  for (int i = 0; i < 200; i++) {
    largeArgs.push_back(std::string(256, 'a' + (i % 26)));
  }

  // Expression that forces materialization of the full args list onto the arena.
  // This is the pattern from the bug report: args.exists(x, x == '...')
  absl::string_view expr = "args.exists(x, x == 'nonexistent_value')";

  // Warm up: run a few iterations to stabilize RSS and JIT/lazy allocations.
  for (int i = 0; i < 10; i++) {
    auto f = std::make_unique<ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    auto argsCopy = largeArgs;
    santa::cel::Activation<true> activation(
        std::move(f),
        ^std::vector<std::string>() {
          return argsCopy;
        },
        ^std::map<std::string, std::string>() {
          return {};
        },
        ^uid_t() {
          return 501;
        },
        ^std::string() {
          return "/usr/local/bin";
        },
        ^std::vector<AncestorT>() {
          return {};
        });
    auto result = sut.value()->CompileAndEvaluate(expr, activation);
    XCTAssertTrue(result.ok(), @"Warmup failed: %s", result.status().message().data());
  }

  size_t rssBaseline = GetResidentMemoryBytes();
  XCTAssertGreaterThan(rssBaseline, (size_t)0, @"Failed to read RSS");

  // Run many iterations of CompileAndEvaluate. Each iteration materializes
  // ~200 * 256 = ~50KB of arg strings onto the arena, plus compilation
  // temporaries. Over 5000 iterations this should grow by ~250MB+ with the bug.
  const int iterations = 5000;
  for (int i = 0; i < iterations; i++) {
    auto f = std::make_unique<ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    auto argsCopy = largeArgs;
    santa::cel::Activation<true> activation(
        std::move(f),
        ^std::vector<std::string>() {
          return argsCopy;
        },
        ^std::map<std::string, std::string>() {
          return {{"PATH", "/usr/bin"}, {"HOME", "/Users/test"}};
        },
        ^uid_t() {
          return 501;
        },
        ^std::string() {
          return "/usr/local/bin";
        },
        ^std::vector<AncestorT>() {
          return {};
        });
    auto result = sut.value()->CompileAndEvaluate(expr, activation);
    XCTAssertTrue(result.ok(), @"Iteration %d failed: %s", i, result.status().message().data());
  }

  size_t rssAfter = GetResidentMemoryBytes();
  size_t growth = rssAfter > rssBaseline ? rssAfter - rssBaseline : 0;

  double growthMB = (double)growth / (1024.0 * 1024.0);
  NSLog(@"Arena growth test: baseline=%.1fMB, after=%.1fMB, growth=%.1fMB over %d iterations",
        (double)rssBaseline / (1024.0 * 1024.0), (double)rssAfter / (1024.0 * 1024.0), growthMB,
        iterations);

  // With the bug: each iteration leaks ~50KB+ onto the arena.
  // 5000 iterations * ~50KB = ~250MB growth (conservative estimate).
  // With the fix: the stack-local arena is destroyed each call, so growth
  // should be negligible (a few MB for normal heap churn at most).
  //
  // Threshold: 50MB is generous enough to avoid flakiness from normal heap
  // activity, but will clearly catch the unbounded arena growth.
  double thresholdMB = 50.0;
  XCTAssertLessThan(growthMB, thresholdMB,
                    @"CompileAndEvaluate leaked %.1fMB over %d iterations "
                    @"(threshold: %.0fMB). This indicates unbounded arena growth.",
                    growthMB, iterations, thresholdMB);
}

@end
