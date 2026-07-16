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

#import <XCTest/XCTest.h>

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELPlanCache.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/Evaluator.h"
#include "absl/status/statusor.h"
#include "google/protobuf/arena.h"

using santa::cel::CELPlanCache;
using santa::cel::Evaluator;
using santa::cel::PlanPtr;

namespace {
std::unique_ptr<santa::cel::Activation<true>> MakeActivationWithTeamID(const std::string& teamID) {
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;
  auto f = std::make_unique<ExecutableFileT>();
  f->set_team_id(teamID);
  return std::make_unique<santa::cel::Activation<true>>(
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
        return "";
      },
      ^std::string() {
        return "";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });
}
}  // namespace

@interface CELPlanCacheTest : XCTestCase
@end

@implementation CELPlanCacheTest {
  std::unique_ptr<Evaluator<true>> _ev;
}

- (void)setUp {
  auto ev = Evaluator<true>::Create();
  XCTAssertTrue(ev.ok());
  _ev = std::move(*ev);
}

// Second GetOrCompile of the same text returns the SAME CompiledCELPlan
// (pointer identity) — i.e. a cache hit, no recompile.
- (void)testHitReturnsSamePlan {
  CELPlanCache<true> cache(_ev.get(), 128);
  const std::string expr = "target.team_id == 'EQHXZ8M8AV'";

  absl::StatusOr<PlanPtr> a = cache.GetOrCompile(expr);
  absl::StatusOr<PlanPtr> b = cache.GetOrCompile(expr);

  XCTAssertTrue(a.ok());
  XCTAssertTrue(b.ok());
  XCTAssertTrue(a->get() != nullptr);
  XCTAssertEqual(a->get(), b->get());  // same CompiledCELPlan instance
  XCTAssertEqual(cache.Size(), (uint64_t)1);
}

// Distinct texts produce distinct plans.
- (void)testDistinctExprsDistinctPlans {
  CELPlanCache<true> cache(_ev.get(), 128);
  auto a = cache.GetOrCompile("target.team_id == 'AAAAAAAAAA'");
  auto b = cache.GetOrCompile("target.team_id == 'BBBBBBBBBB'");
  XCTAssertTrue(a.ok());
  XCTAssertTrue(b.ok());
  XCTAssertNotEqual(a->get(), b->get());
  XCTAssertEqual(cache.Size(), (uint64_t)2);
}

// A syntactically invalid expression returns an error status, not a crash.
- (void)testInvalidExprReturnsError {
  CELPlanCache<true> cache(_ev.get(), 128);
  auto r = cache.GetOrCompile("this is not (valid CEL");
  XCTAssertFalse(r.ok());
  XCTAssertEqual(cache.Size(), (uint64_t)0);  // nothing cached on failure
}

// A PlanPtr held by a caller stays fully usable (arena + expression alive)
// after the cache is cleared mid-flight. Proves the bundle refcount, not the
// cache, governs lifetime — no use-after-free.
- (void)testPlanUsableAfterClear {
  CELPlanCache<true> cache(_ev.get(), 128);
  auto r = cache.GetOrCompile("target.team_id == 'TESTTEAMID'");
  XCTAssertTrue(r.ok());
  PlanPtr held = *r;

  cache.Clear();
  XCTAssertEqual(cache.Size(), (uint64_t)0);

  // Evaluate through the held plan AFTER the cache dropped its reference.
  auto act = MakeActivationWithTeamID("TESTTEAMID");
  google::protobuf::Arena evalArena;
  auto result = _ev->Evaluate(held->expression.get(), *act, &evalArena);
  XCTAssertTrue(result.ok());
}

// Exceeding the cap drains the cache (SantaCache drains all on overflow), so
// Size never exceeds the cap.
- (void)testDrainWhenFull {
  CELPlanCache<true> cache(_ev.get(), /*maxSize=*/4);
  for (int i = 0; i < 20; i++) {
    std::string expr = "target.team_id == 'ID" + std::to_string(i) + "'";
    auto r = cache.GetOrCompile(expr);
    XCTAssertTrue(r.ok());
    XCTAssertLessThanOrEqual(cache.Size(), (uint64_t)4);
  }
}

// Concurrent GetOrCompile over a small shared set of expressions from many
// threads: exercises concurrent reads, the benign compile-on-miss race, and
// concurrent eviction. The cap (8) is kept below the 10-distinct-key working
// set so the drain path genuinely fires under contention. Passes if there is
// no crash/UAF and every returned plan is valid. Models the ES-worker-thread
// concurrency the cache runs under.
- (void)testConcurrentGetOrCompile {
  CELPlanCache<true> cache(_ev.get(), /*maxSize=*/8);
  constexpr int kThreads = 8;
  constexpr int kItersPerThread = 2000;
  std::atomic<int> failures{0};

  std::vector<std::thread> threads;
  for (int t = 0; t < kThreads; t++) {
    threads.emplace_back([&cache, &failures]() {
      for (int i = 0; i < kItersPerThread; i++) {
        // 10 distinct expressions shared across all threads → contended keys.
        std::string expr = "target.team_id == 'ID" + std::to_string(i % 10) + "'";
        auto r = cache.GetOrCompile(expr);
        if (!r.ok() || r->get() == nullptr) failures.fetch_add(1);
      }
    });
  }
  for (auto& th : threads)
    th.join();

  XCTAssertEqual(failures.load(), 0);
}

@end
