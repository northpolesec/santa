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

/// Regression test for unbounded arena growth in CompileAndEvaluate.
///
/// Previously, the Evaluator used a single protobuf Arena for every
/// compile+evaluate cycle. Since Arena is a monotonic bump allocator that never
/// frees individual allocations, every evaluation leaked materialized variable
/// values (args strings, env maps, etc.) and compilation temporaries.
///
/// The fix uses a stack-local Arena in CompileAndEvaluate so temporaries are
/// freed at end of scope. This test verifies memory stays bounded.
- (void)testCompileAndEvaluateArenaGrowth {
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto sut = santa::cel::Evaluator<true>::Create();
  if (!sut.ok()) {
    XCTFail(@"Failed to create evaluator: %.*s", (int)sut.status().message().size(),
            sut.status().message().data());
    return;
  }

  // Build a large args list to amplify per-evaluation arena allocation.
  // This simulates a process like `node` or `yarn` with many arguments.
  std::vector<std::string> largeArgs;
  largeArgs.reserve(200);
  for (int i = 0; i < 200; i++) {
    largeArgs.push_back(std::string(256, 'a' + (i % 26)));
  }
  const auto* argsPtr = &largeArgs;

  // Expression that forces materialization of the full args list onto the arena.
  absl::string_view expr = "args.exists(x, x == 'nonexistent_value')";

  // Warm up: run a few iterations to stabilize RSS and JIT/lazy allocations.
  for (int i = 0; i < 10; i++) {
    @autoreleasepool {
      auto f = std::make_unique<ExecutableFileT>();
      f->mutable_signing_time()->set_seconds(1748436989);
      santa::cel::Activation<true> activation(
          std::move(f),
          ^std::vector<std::string>() {
            return *argsPtr;
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
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<AncestorT>() {
            return {};
          },
          ^std::vector<FileDescriptorT>() {
            return {};
          });
      auto result = sut.value()->CompileAndEvaluate(expr, activation);
      if (!result.ok()) {
        XCTFail(@"Warmup failed: %.*s", (int)result.status().message().size(),
                result.status().message().data());
        return;
      }
    }
  }

  size_t rssBaseline = GetResidentMemoryBytes();
  XCTAssertGreaterThan(rssBaseline, (size_t)0, @"Failed to read RSS");

  // Run many iterations of CompileAndEvaluate. Each iteration materializes
  // ~200 * 256 = ~50KB of arg strings onto the arena, plus compilation
  // temporaries. Before the fix this grew by ~600MB+ over 5000 iterations,
  // so 1500 iterations still produces ~180MB pre-fix while keeping post-fix
  // RSS comfortably under the 50MB threshold.
  const int iterations = 1500;
  for (int i = 0; i < iterations; i++) {
    @autoreleasepool {
      auto f = std::make_unique<ExecutableFileT>();
      f->mutable_signing_time()->set_seconds(1748436989);
      santa::cel::Activation<true> activation(
          std::move(f),
          ^std::vector<std::string>() {
            return *argsPtr;
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
          ^std::string() {
            return "/usr/bin/test";
          },
          ^std::vector<AncestorT>() {
            return {};
          },
          ^std::vector<FileDescriptorT>() {
            return {};
          });
      auto result = sut.value()->CompileAndEvaluate(expr, activation);
      if (!result.ok()) {
        XCTFail(@"Iteration %d failed: %.*s", i, (int)result.status().message().size(),
                result.status().message().data());
        return;
      }
    }
  }

  size_t rssAfter = GetResidentMemoryBytes();
  size_t growth = rssAfter > rssBaseline ? rssAfter - rssBaseline : 0;

  double growthMB = (double)growth / (1024.0 * 1024.0);
  NSLog(@"Arena growth test: baseline=%.1fMB, after=%.1fMB, growth=%.1fMB over %d iterations",
        (double)rssBaseline / (1024.0 * 1024.0), (double)rssAfter / (1024.0 * 1024.0), growthMB,
        iterations);

  // Threshold: 50MB is generous enough to avoid flakiness from normal heap
  // activity, but will clearly catch unbounded arena growth (~600MB before fix).
  double thresholdMB = 50.0;
  XCTAssertLessThan(growthMB, thresholdMB,
                    @"CompileAndEvaluate leaked %.1fMB over %d iterations "
                    @"(threshold: %.0fMB). This indicates unbounded arena growth.",
                    growthMB, iterations, thresholdMB);
}

@end
