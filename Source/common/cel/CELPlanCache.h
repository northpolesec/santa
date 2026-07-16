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

#ifndef SANTA_COMMON_CEL_CELPLANCACHE_H
#define SANTA_COMMON_CEL_CELPLANCACHE_H

#include <memory>
#include <string>

#include "Source/common/SantaCache.h"
#include "Source/common/cel/Evaluator.h"
#include "absl/status/statusor.h"
#include "google/protobuf/arena.h"

// Evaluator.h already wraps the cel-cpp includes (which warn-as-error) in the
// needed pragma push/pop and exposes CelExpression.

namespace santa {
namespace cel {

// A compiled CEL plan bundled with the arena it references. The arena holds
// constant-folding data the CelExpression points into, so it MUST outlive the
// expression: arena is declared FIRST so it is destroyed LAST (members destruct
// in reverse declaration order). Mirrors celFallbackArena_/celFallbackRules_ in
// SNTPolicyProcessor.
struct CompiledCELPlan {
  std::unique_ptr<google::protobuf::Arena> arena;
  std::unique_ptr<::google::api::expr::runtime::CelExpression> expression;

  CompiledCELPlan(
      std::unique_ptr<google::protobuf::Arena> a,
      std::unique_ptr<::google::api::expr::runtime::CelExpression> e)
      : arena(std::move(a)), expression(std::move(e)) {}
};

// The cache value type is the WHOLE bundle, never a bare
// shared_ptr<CelExpression> (that would let eviction free the arena under a
// live plan). get() copies this shared_ptr out under SantaCache's bucket lock,
// so a caller holding it keeps arena+expression alive across a concurrent
// eviction. const: the plan is immutable after compilation.
using PlanPtr = std::shared_ptr<const CompiledCELPlan>;

// Caches compiled CEL plans for ONE evaluator, keyed by expression text.
// Lazy: compiles on first miss, reuses thereafter. Bounded: SantaCache drains
// all entries when full (LRU is planned separately). No invalidation is needed
// or wired — a plan is a pure function of (text, evaluator) and the evaluator
// is fixed for the process lifetime, so a cached plan is never stale.
template <bool IsV2>
class CELPlanCache {
 public:
  // evaluator must outlive this cache (owned by the caller, e.g.
  // SNTPolicyProcessor). maxSize is the entry cap (see kCELPlanCacheMaxSize).
  CELPlanCache(Evaluator<IsV2>* evaluator, uint64_t maxSize)
      : evaluator_(evaluator), cache_(maxSize) {}

  CELPlanCache(const CELPlanCache&) = delete;
  CELPlanCache& operator=(const CELPlanCache&) = delete;

  // Returns the cached plan for expr, compiling and caching it on a miss.
  // Returns an error status only when compilation fails (never a null PlanPtr
  // on an ok() result). The benign compile-on-miss race (two threads compiling
  // the same text) is fine: last writer wins, both hold a valid plan. The
  // guarantee rests on returning the freshly-compiled local `plan` rather than
  // re-getting from the cache after set(): a racing thread whose entry was
  // overwritten still returns its own plan (kept alive by that shared_ptr, not
  // the cache's reference), so every caller gets a valid, non-null PlanPtr.
  absl::StatusOr<PlanPtr> GetOrCompile(const std::string& expr) {
    if (PlanPtr hit = cache_.get(expr)) {
      return hit;
    }
    auto arena = std::make_unique<google::protobuf::Arena>();
    absl::StatusOr<std::unique_ptr<::google::api::expr::runtime::CelExpression>>
        compiled = evaluator_->Compile(expr, arena.get());
    if (!compiled.ok()) {
      return compiled.status();
    }
    PlanPtr plan = std::make_shared<const CompiledCELPlan>(
        std::move(arena), std::move(compiled).value());
    cache_.set(expr, plan);
    return plan;
  }

  void Clear() { cache_.clear(); }
  uint64_t Size() const { return cache_.count(); }

 private:
  Evaluator<IsV2>* evaluator_;  // non-owning; must outlive this cache
  SantaCache<std::string, PlanPtr> cache_;
};

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_CELPLANCACHE_H
