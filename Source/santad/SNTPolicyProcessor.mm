/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santad/SNTPolicyProcessor.h"
#import "Source/common/SNTCommonEnums.h"

#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <Security/SecCode.h>
#import <Security/Security.h>

#import "Source/common/CertificateHelpers.h"
#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCELFallbackRule.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeepCopy.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SigningIDHelpers.h"
#include "Source/common/String.h"
#include "Source/common/cel/CELPlanCache.h"
#include "Source/common/cel/Evaluator.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "cel/v1.pb.h"

static constexpr uint64_t kCELPlanCacheMaxSize = 128;

enum class PlatformBinaryState {
  kRuntimeTrue = 0,
  kRuntimeFalse,
  kStaticCheck,
};

struct CELEvaluationResult {
  bool succeeded;            // Whether CEL evaluation succeeded
  bool decisionMade;         // If !succeeded, whether a decision was made (fail-closed)
  SNTRuleState resultState;  // If succeeded, the resulting state
};

static void ApplySilentBlock(SNTCachedDecision* cd, SNTRuleState state);

struct RuleIdentifiers CreateRuleIDs(SNTCachedDecision* cd) {
  return [SNTRuleIdentifiers filterIdentifiers:{
                                                   .cdhash = cd.cdhash,
                                                   .binarySHA256 = cd.sha256,
                                                   .signingID = cd.signingID,
                                                   .certificateSHA256 = cd.certSHA256,
                                                   .teamID = cd.teamID,
                                               }
                              forSigningStatus:cd.signingStatus];
}

namespace {

// A compiled CEL fallback rule: the plan plus the customMsg/URL to report when
// it matches.
struct CompiledFallbackRule {
  // unique_ptr: the batch is the sole owner (the vector is never copied, only
  // the batch pointer is shared). Removes N control blocks.
  std::unique_ptr<::google::api::expr::runtime::CelExpression> expression;
  NSString* customMsg;
  NSString* customURL;
  NSString* eventDetailButtonText;
};

// Immutable once published. arena declared FIRST -> destroyed LAST, because the
// compiled plans point into its constant-folding data (same rule as
// CompiledCELPlan and the old celFallbackArena_-before-celFallbackRules_ order).
struct FallbackBatch {
  std::unique_ptr<google::protobuf::Arena> arena;
  std::vector<CompiledFallbackRule> rules;

  FallbackBatch(std::unique_ptr<google::protobuf::Arena> a, std::vector<CompiledFallbackRule> r)
      : arena(std::move(a)), rules(std::move(r)) {}

  // Compiles each rule's expression with `evaluator` into a fresh shared arena
  // and returns an immutable batch. Returns nullptr if any expression fails to
  // compile (logging which); the caller then keeps its currently-published batch.
  static std::shared_ptr<const FallbackBatch> Create(santa::cel::Evaluator<true>* evaluator,
                                                     NSArray<SNTCELFallbackRule*>* rules) {
    auto arena = std::make_unique<google::protobuf::Arena>();
    std::vector<CompiledFallbackRule> compiled;
    compiled.reserve(rules.count);
    for (SNTCELFallbackRule* rule in rules) {
      auto result = evaluator->Compile(santa::NSStringToUTF8StringView(rule.celExpr), arena.get());
      if (!result.ok()) {
        LOGE(@"Failed to compile CEL fallback expression '%@': %s", rule.celExpr,
             std::string(result.status().message()).c_str());
        return nullptr;
      }
      compiled.push_back(
          {std::move(*result), rule.customMsg, rule.customURL, rule.eventDetailButtonText});
    }
    return std::make_shared<FallbackBatch>(std::move(arena), std::move(compiled));
  }
};

}  // namespace

@interface SNTPolicyProcessor () {
  std::unique_ptr<santa::cel::Evaluator<false>> celEvaluatorV1_;
  std::unique_ptr<santa::cel::Evaluator<true>> celEvaluatorV2_;
  std::shared_ptr<santa::EntitlementsFilter> entitlementsFilter_;
  // Immutable, atomically-swapped batch of compiled fallback rules
  // (CompiledFallbackRule / FallbackBatch are defined in the anonymous namespace
  // above). Accessed ONLY via the std::atomic_*_explicit shared_ptr free
  // functions (see compileFallbackRules: / evaluateCELFallbackExpressions:).
  std::shared_ptr<const FallbackBatch> celFallbackBatch_;
  std::unique_ptr<santa::cel::CELPlanCache<false>> celPlanCacheV1_;
  std::unique_ptr<santa::cel::CELPlanCache<true>> celPlanCacheV2_;
}
@property SNTRuleTable* ruleTable;
@property SNTConfigurator* configurator;
@property SNTKVOManager* celFallbackRulesObserver;
@end

@implementation SNTPolicyProcessor

- (instancetype)init {
  self = [super init];
  if (self) {
    _configurator = [SNTConfigurator configurator];

    auto evaluatorV1 = santa::cel::Evaluator<false>::Create();
    if (evaluatorV1.ok()) {
      celEvaluatorV1_ = std::move(*evaluatorV1);
      celPlanCacheV1_ = std::make_unique<santa::cel::CELPlanCache<false>>(celEvaluatorV1_.get(),
                                                                          kCELPlanCacheMaxSize);
    } else {
      LOGW(@"Failed to create CEL v1 evaluator: %s",
           std::string(evaluatorV1.status().message()).c_str());
    }

    // This evaluator also handles CEL fallback expressions, which may return
    // UNSPECIFIED to fall through to the next rule.
    auto evaluatorV2 = santa::cel::Evaluator<true>::Create(/*allowUnspecified=*/true);
    if (evaluatorV2.ok()) {
      celEvaluatorV2_ = std::move(*evaluatorV2);
      celPlanCacheV2_ = std::make_unique<santa::cel::CELPlanCache<true>>(celEvaluatorV2_.get(),
                                                                         kCELPlanCacheMaxSize);
    } else {
      LOGW(@"Failed to create CEL v2 evaluator: %s",
           std::string(evaluatorV2.status().message()).c_str());
    }

    // Pre-compile any existing fallback rules
    [self compileFallbackRules:_configurator.celFallbackRules];

    // Observe changes to fallback rules
    __weak __typeof(self) weakSelf = self;
    _celFallbackRulesObserver = [[SNTKVOManager alloc]
        initWithObject:_configurator
              selector:@selector(celFallbackRules)
                  type:[NSArray class]
              callback:^(NSArray* oldValue, NSArray* newValue) {
                if ((!oldValue && !newValue) || [oldValue isEqualToArray:newValue]) {
                  return;
                }
                [weakSelf compileFallbackRules:newValue];
              }];
  }
  return self;
}

- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable
               entitlementsFilter:(std::shared_ptr<santa::EntitlementsFilter>)entitlementsFilter {
  self = [self init];
  if (self) {
    _ruleTable = ruleTable;
    entitlementsFilter_ = std::move(entitlementsFilter);
  }
  return self;
}

- (void)compileFallbackRules:(NSArray<SNTCELFallbackRule*>*)rules {
  if (!celEvaluatorV2_) {
    return;
  }

  if (rules.count > 10) {
    LOGE(@"Number of CEL fallback rules is above the limit of 10");
    return;
  }

  std::shared_ptr<const FallbackBatch> batch = FallbackBatch::Create(celEvaluatorV2_.get(), rules);
  if (!batch) {
    return;  // compile failure already logged; keep the currently-published batch
  }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  std::atomic_store_explicit(&celFallbackBatch_, std::move(batch), std::memory_order_release);
#pragma clang diagnostic pop
}

- (BOOL)evaluateCELFallbackExpressions:(SNTCachedDecision*)cd
                    activationCallback:(ActivationCallbackBlock)activationCallback {
  if (!celEvaluatorV2_ || !activationCallback) {
    return NO;
  }

  // Snapshot the published batch with a single atomic load + refcount bump
  // (O(1) regardless of rule count). The snapshot co-owns the arena and all
  // compiled plans, so this stays valid even if compileFallbackRules: swaps
  // in a new batch concurrently.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  std::shared_ptr<const FallbackBatch> batch =
      std::atomic_load_explicit(&celFallbackBatch_, std::memory_order_acquire);
#pragma clang diagnostic pop

  if (!batch || batch->rules.empty()) {
    return NO;
  }

  auto activation = activationCallback(/*useV2=*/true);

  // Use a stack-local arena for evaluation temporaries.
  google::protobuf::Arena evalArena;

  for (const CompiledFallbackRule& rule : batch->rules) {
    CELEvaluationResult celResult = [self evaluateCompiledCELExpression:rule.expression.get()
                                                                  useV2:true
                                                         cachedDecision:cd
                                                             activation:*activation
                                                              evalArena:&evalArena
                                                      inFallbackContext:YES];

    if (!celResult.succeeded) {
      if (celResult.decisionMade) {
        return YES;
      }
      continue;
    }

    cd.decision = (celResult.resultState == SNTRuleStateAllow ||
                   celResult.resultState == SNTRuleStateAllowCompiler)
                      ? SNTEventStateAllowCELFallback
                      : SNTEventStateBlockCELFallback;
    cd.customMsg = rule.customMsg;
    cd.customURL = rule.customURL;
    cd.eventDetailButtonText = rule.eventDetailButtonText;
    return YES;
  }

  return NO;
}

- (CELEvaluationResult)
    evaluateCompiledCELExpression:(const ::google::api::expr::runtime::CelExpression*)expression
                            useV2:(bool)useV2
                   cachedDecision:(SNTCachedDecision*)cd
                       activation:(const ::google::api::expr::runtime::BaseActivation&)activation
                        evalArena:(google::protobuf::Arena*)evalArena
                inFallbackContext:(BOOL)inFallbackContext {
  int returnValue = 0;
  bool cacheable = true;
  std::optional<uint64_t> touchIDCooldownMinutes;

  if (useV2) {
    const auto& v2Activation = static_cast<const santa::cel::Activation<true>&>(activation);
    assert(dynamic_cast<const santa::cel::Activation<true>*>(&activation) != nullptr);
    auto evalResult = celEvaluatorV2_->Evaluate(expression, v2Activation, evalArena);

    if (!evalResult.ok()) {
      LOGE(@"Failed to evaluate CEL expression: %s",
           std::string(evalResult.status().message()).c_str());
      if (self.configurator.failClosed) {
        cd.decision = SNTEventStateBlockUnknown;
        return {.succeeded = false, .decisionMade = true, .resultState = {}};
      }
      return {.succeeded = false, .decisionMade = false, .resultState = {}};
    }

    returnValue = static_cast<int>(evalResult->value);
    cacheable = evalResult->cacheable;
    touchIDCooldownMinutes = evalResult->touchIDCooldownMinutes;
  } else {
    const auto& v1Activation = static_cast<const santa::cel::Activation<false>&>(activation);
    assert(dynamic_cast<const santa::cel::Activation<false>*>(&activation) != nullptr);
    auto evalResult = celEvaluatorV1_->Evaluate(expression, v1Activation, evalArena);

    if (!evalResult.ok()) {
      LOGE(@"Failed to evaluate CEL expression: %s",
           std::string(evalResult.status().message()).c_str());
      if (self.configurator.failClosed) {
        cd.decision = SNTEventStateBlockUnknown;
        return {.succeeded = false, .decisionMade = true, .resultState = {}};
      }
      return {.succeeded = false, .decisionMade = false, .resultState = {}};
    }

    returnValue = static_cast<int>(evalResult->value);
    cacheable = evalResult->cacheable;
    // V1 doesn't support TouchID, so cooldown is always nullopt
  }

  // Apply cacheability before the switch below so that an early return from a
  // particular return value doesn't drop a non-cacheable result.
  if (!cacheable) {
    cd.cacheable = NO;
  }

  SNTRuleState resultState;
  if (useV2) {
    using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
    switch (static_cast<ReturnValue>(returnValue)) {
      case ReturnValue::UNSPECIFIED:
        return {.succeeded = false, .decisionMade = false, .resultState = {}};
      case ReturnValue::ALLOWLIST: resultState = SNTRuleStateAllow; break;
      case ReturnValue::ALLOWLIST_COMPILER: resultState = SNTRuleStateAllowCompiler; break;
      case ReturnValue::BLOCKLIST: resultState = SNTRuleStateBlock; break;
      case ReturnValue::SILENT_BLOCKLIST: resultState = SNTRuleStateSilentBlock; break;
      case ReturnValue::SILENT_GUI_BLOCKLIST: resultState = SNTRuleStateSilentBlockGUI; break;
      case ReturnValue::SILENT_TTY_BLOCKLIST: resultState = SNTRuleStateSilentBlockTTY; break;
      case ReturnValue::AUDIT:
        // AUDIT is identical to ALLOWLIST on the client; the only difference
        // is that the resulting event is flagged so the sync server can
        // distinguish audit-only matches.
        cd.auditReturn = YES;
        resultState = SNTRuleStateAllow;
        break;
      case ReturnValue::REQUIRE_TOUCHID_ONLY:
        // REQUIRE_TOUCHID_ONLY is like REQUIRE_TOUCHID but it skips the Santa dialog
        cd.silentTouchID = YES;
        [[fallthrough]];
      case ReturnValue::REQUIRE_TOUCHID:
        // REQUIRE_TOUCHID responses are not cacheable.
        cd.holdAndAsk = YES;
        cd.cacheable = NO;
        resultState = SNTRuleStateBlock;
        // Extract cooldown if specified via require_touchid_with_cooldown_minutes()
        if (touchIDCooldownMinutes.has_value()) {
          cd.touchIDCooldownMinutes = @(touchIDCooldownMinutes.value());
        }
        break;
      case ReturnValue::SEATBELT:
        // SEATBELT is not supported from CEL fallback rules: a fallback rule
        // does not carry a seatbelt_policy, so there is nothing to enforce
        // with. Reject before touching `cd` so no state leaks to the next
        // fallback iteration. The sync server should not send fallback rules
        // that can return SEATBELT; this is a defense-in-depth check.
        if (inFallbackContext) {
          LOGW(@"CEL fallback expression returned SEATBELT; ignoring (fallback "
               @"rules cannot carry a seatbelt policy)");
          return {.succeeded = false, .decisionMade = false, .resultState = {}};
        }
        // SEATBELT responses are not cacheable: the per-exec expectation is
        // one-shot, so every execution must re-check via prepareSandboxExec.
        resultState = SNTRuleStateSeatbelt;
        cd.cacheable = NO;
        break;
      default:
        LOGW(@"Unexpected return value from CEL expression: %d", returnValue);
        return {.succeeded = false, .decisionMade = false, .resultState = {}};
    }
  } else {
    using ReturnValue = santa::cel::CELProtoTraits<false>::ReturnValue;
    switch (static_cast<ReturnValue>(returnValue)) {
      case ReturnValue::ALLOWLIST: resultState = SNTRuleStateAllow; break;
      case ReturnValue::ALLOWLIST_COMPILER: resultState = SNTRuleStateAllowCompiler; break;
      case ReturnValue::BLOCKLIST: resultState = SNTRuleStateBlock; break;
      case ReturnValue::SILENT_BLOCKLIST: resultState = SNTRuleStateSilentBlock; break;
      case ReturnValue::SILENT_GUI_BLOCKLIST: resultState = SNTRuleStateSilentBlockGUI; break;
      case ReturnValue::SILENT_TTY_BLOCKLIST: resultState = SNTRuleStateSilentBlockTTY; break;
      default:
        LOGW(@"Unexpected return value from CEL expression: %d", returnValue);
        return {.succeeded = false, .decisionMade = false, .resultState = {}};
    }
  }

  ApplySilentBlock(cd, resultState);

  return {.succeeded = true, .decisionMade = false, .resultState = resultState};
}

- (CELEvaluationResult)evaluateCELExpressionForRule:(SNTRule*)rule
                                     cachedDecision:(SNTCachedDecision*)cd
                                 activationCallback:(ActivationCallbackBlock)activationCallback {
  bool useV2 = (rule.state == SNTRuleStateCELv2);
  auto activation = activationCallback(useV2);

  if ((useV2 && !celPlanCacheV2_) || (!useV2 && !celPlanCacheV1_)) {
    LOGE(@"CEL v%d evaluator unavailable", useV2 ? 2 : 1);
    if (self.configurator.failClosed) {
      cd.decision = SNTEventStateBlockUnknown;
      return {.succeeded = false, .decisionMade = true, .resultState = {}};
    }
    return {.succeeded = false, .decisionMade = false, .resultState = {}};
  }

  std::string expr = santa::NSStringToUTF8String(rule.celExpr);
  absl::StatusOr<santa::cel::PlanPtr> planResult =
      useV2 ? celPlanCacheV2_->GetOrCompile(expr) : celPlanCacheV1_->GetOrCompile(expr);

  if (!planResult.ok()) {
    LOGE(@"Failed to compile CEL rule (%@): %s", rule.celExpr,
         std::string(planResult.status().message()).c_str());
    if (self.configurator.failClosed) {
      cd.decision = SNTEventStateBlockUnknown;
      return {.succeeded = false, .decisionMade = true, .resultState = {}};
    }
    return {.succeeded = false, .decisionMade = false, .resultState = {}};
  }

  // Per-exec evaluation temporaries live on a stack arena; the plan's own
  // (cached) constant arena is long-lived and read-only here.
  google::protobuf::Arena evalArena;
  return [self evaluateCompiledCELExpression:(*planResult)->expression.get()
                                       useV2:useV2
                              cachedDecision:cd
                                  activation:*activation
                                   evalArena:&evalArena
                           inFallbackContext:NO];
}

// Sets the GUI/TTY notification suppression flags on the cached decision based
// on which silent-block variant the rule resolved to.
static void ApplySilentBlock(SNTCachedDecision* cd, SNTRuleState state) {
  switch (state) {
    case SNTRuleStateSilentBlock:
      cd.silentBlockGUI = YES;
      cd.silentBlockTTY = YES;
      break;
    case SNTRuleStateSilentBlockGUI: cd.silentBlockGUI = YES; break;
    case SNTRuleStateSilentBlockTTY: cd.silentBlockTTY = YES; break;
    default: break;
  }
}

// This method applies the rules to the cached decision object.
//
// It returns YES if the decision was made, NO if the decision was not made.
- (BOOL)decision:(SNTCachedDecision*)cd
                     forRule:(SNTRule*)rule
         withTransitiveRules:(BOOL)enableTransitiveRules
    andCELActivationCallback:(ActivationCallbackBlock)activationCallback {
  SNTRuleState state = rule.state;
  SNTRuleType type = rule.type;

  if ((state == SNTRuleStateCEL || state == SNTRuleStateCELv2) && activationCallback) {
    CELEvaluationResult celResult = [self evaluateCELExpressionForRule:rule
                                                        cachedDecision:cd
                                                    activationCallback:activationCallback];
    if (!celResult.succeeded) {
      return celResult.decisionMade;
    }
    state = celResult.resultState;
  }

  static const auto decisions =
      absl::flat_hash_map<std::pair<SNTRuleType, SNTRuleState>, SNTEventState>{
          {{SNTRuleTypeCDHash, SNTRuleStateAllow}, SNTEventStateAllowCDHash},
          {{SNTRuleTypeCDHash, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompilerCDHash},
          {{SNTRuleTypeCDHash, SNTRuleStateBlock}, SNTEventStateBlockCDHash},
          {{SNTRuleTypeCDHash, SNTRuleStateSilentBlock}, SNTEventStateBlockCDHash},
          {{SNTRuleTypeCDHash, SNTRuleStateSilentBlockGUI}, SNTEventStateBlockCDHash},
          {{SNTRuleTypeCDHash, SNTRuleStateSilentBlockTTY}, SNTEventStateBlockCDHash},
          {{SNTRuleTypeBinary, SNTRuleStateAllow}, SNTEventStateAllowBinary},
          {{SNTRuleTypeBinary, SNTRuleStateAllowLocalBinary}, SNTEventStateAllowLocalBinary},
          {{SNTRuleTypeBinary, SNTRuleStateAllowTransitive}, SNTEventStateAllowTransitive},
          {{SNTRuleTypeBinary, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompilerBinary},
          {{SNTRuleTypeBinary, SNTRuleStateSilentBlock}, SNTEventStateBlockBinary},
          {{SNTRuleTypeBinary, SNTRuleStateSilentBlockGUI}, SNTEventStateBlockBinary},
          {{SNTRuleTypeBinary, SNTRuleStateSilentBlockTTY}, SNTEventStateBlockBinary},
          {{SNTRuleTypeBinary, SNTRuleStateBlock}, SNTEventStateBlockBinary},
          {{SNTRuleTypeSigningID, SNTRuleStateAllow}, SNTEventStateAllowSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateAllowLocalSigningID},
           SNTEventStateAllowLocalSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompilerSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateSilentBlock}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateSilentBlockGUI}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateSilentBlockTTY}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateBlock}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeCertificate, SNTRuleStateAllow}, SNTEventStateAllowCertificate},
          {{SNTRuleTypeCertificate, SNTRuleStateSilentBlock}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeCertificate, SNTRuleStateSilentBlockGUI}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeCertificate, SNTRuleStateSilentBlockTTY}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeCertificate, SNTRuleStateBlock}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeTeamID, SNTRuleStateAllow}, SNTEventStateAllowTeamID},
          {{SNTRuleTypeTeamID, SNTRuleStateSilentBlock}, SNTEventStateBlockTeamID},
          {{SNTRuleTypeTeamID, SNTRuleStateSilentBlockGUI}, SNTEventStateBlockTeamID},
          {{SNTRuleTypeTeamID, SNTRuleStateSilentBlockTTY}, SNTEventStateBlockTeamID},
          {{SNTRuleTypeTeamID, SNTRuleStateBlock}, SNTEventStateBlockTeamID},
          // Seatbelt rules start out as a block of the rule's type. If the
          // ancestor/sandbox check succeeds in the execution controller, the
          // decision is flipped to the matching allow state via
          // BlockToAllowDecision. Starting at block means the fail-safe outcome
          // is to deny if the check is ever skipped.
          {{SNTRuleTypeCDHash, SNTRuleStateSeatbelt}, SNTEventStateBlockCDHash},
          {{SNTRuleTypeBinary, SNTRuleStateSeatbelt}, SNTEventStateBlockBinary},
          {{SNTRuleTypeSigningID, SNTRuleStateSeatbelt}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeCertificate, SNTRuleStateSeatbelt}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeTeamID, SNTRuleStateSeatbelt}, SNTEventStateBlockTeamID},
      };

  auto iterator = decisions.find(std::pair<SNTRuleType, SNTRuleState>{type, state});
  if (iterator != decisions.end()) {
    cd.decision = iterator->second;
  } else {
    // If we have an invalid state combination then either we have stale data in
    // the database or a programming error. We treat this as if the
    // corresponding rule was not found.
    LOGE(@"Invalid rule type/state combination %ld/%ld", type, state);
    return NO;
  }

  switch (state) {
    case SNTRuleStateSilentBlock:
    case SNTRuleStateSilentBlockGUI:
    case SNTRuleStateSilentBlockTTY: ApplySilentBlock(cd, state); break;
    case SNTRuleStateAllowCompiler:
      if (!enableTransitiveRules) {
        switch (type) {
          case SNTRuleTypeCDHash: cd.decision = SNTEventStateAllowCDHash; break;
          case SNTRuleTypeBinary: cd.decision = SNTEventStateAllowBinary; break;
          case SNTRuleTypeSigningID: cd.decision = SNTEventStateAllowSigningID; break;
          default:
            // Programming error. Something's marked as a compiler that shouldn't be.
            LOGE(@"Invalid compiler rule type %ld", type);
            [NSException
                 raise:@"Invalid compiler rule type"
                format:@"decision:forRule:withTransitiveRules: Unexpected compiler rule type: %ld",
                       type];
            break;
        }
      }
      break;
    case SNTRuleStateAllowTransitive:
      // If transitive rules are disabled, then we treat SNTRuleStateAllowTransitive rules
      // as if a matching rule was not found and set the state to unknown. Otherwise the
      // decision map will have already set the EventState to SNTEventStateAllowTransitive.
      if (!enableTransitiveRules) {
        cd.decision = SNTEventStateUnknown;
        return NO;
      }
      break;
    case SNTRuleStateSeatbelt:
      // Seatbelt decisions must not be cached: the per-exec expectation is
      // one-shot, so every execution must re-check via prepareSandboxExec.
      cd.cacheable = NO;
      cd.seatbeltRequired = YES;
      break;
    default:
      // If its not one of the special cases above, we don't need to do anything.
      break;
  }

  // We know we have a match so apply the custom messages
  cd.customMsg = rule.customMsg;
  cd.customURL = rule.customURL;
  cd.eventDetailButtonText = rule.eventDetailButtonText;
  cd.staticRule = rule.staticRule;
  cd.ruleId = rule.ruleId;

  return YES;
}

static void UpdateCachedDecisionSigningInfo(
    SNTCachedDecision* cd, MOLCodesignChecker* csInfo, PlatformBinaryState platformBinaryState,
    NSDictionary* _Nullable (^entitlementsFilterCallback)(NSDictionary* _Nullable entitlements)) {
  cd.certSHA256 = csInfo.leafCertificate.SHA256;
  cd.certCommonName = csInfo.leafCertificate.commonName;
  cd.certChain = csInfo.certificates;
  cd.rawSigningID = csInfo.signingID;
  // Check if we need to get teamID from code signing.
  if (!cd.teamID) {
    cd.teamID = csInfo.teamID;
  }

  // Check if we need to get signing ID from code signing.
  if (!cd.signingID) {
    cd.signingID = FormatSigningID(csInfo);
  }

  // Ensure that if no teamID exists but a signingID does exist, that the binary
  // is a platform binary. If not, remove the signingID.
  if (!cd.teamID && cd.signingID) {
    switch (platformBinaryState) {
      case PlatformBinaryState::kRuntimeTrue: break;
      case PlatformBinaryState::kStaticCheck:
        if (!csInfo.platformBinary) {
          cd.signingID = nil;
        }
        break;
      case PlatformBinaryState::kRuntimeFalse: OS_FALLTHROUGH;
      default: cd.signingID = nil; break;
    }
  }

  NSDictionary* entitlements = csInfo.entitlements;
  cd.rawEntitlements = [entitlements sntDeepCopy];

  if (entitlementsFilterCallback) {
    cd.entitlements = entitlementsFilterCallback(entitlements);
    cd.entitlementsFiltered = (cd.entitlements.count != entitlements.count);
  } else {
    cd.entitlements = cd.rawEntitlements;
    cd.entitlementsFiltered = NO;
  }

  cd.secureSigningTime = csInfo.secureSigningTime;
  cd.signingTime = csInfo.signingTime;
}

- (nonnull SNTCachedDecision*)
           decisionForFileInfo:(nonnull SNTFileInfo*)fileInfo
                   configState:(nonnull SNTConfigState*)configState
                cachedDecision:(nonnull SNTCachedDecision*)cd
           platformBinaryState:(PlatformBinaryState)platformBinaryState
         signingStatusCallback:(SNTSigningStatus (^_Nonnull)())signingStatusCallback
            activationCallback:(nullable ActivationCallbackBlock)activationCallback
    entitlementsFilterCallback:
        (NSDictionary* _Nullable (^_Nullable)(NSDictionary* _Nullable entitlements))
            entitlementsFilterCallback {
  // If the binary is a critical system binary, don't check its signature.
  // The binary was validated at startup when the rule table was initialized.
  SNTCachedDecision* systemCd = [self.ruleTable.criticalSystemBinaries[cd.signingID] copy];
  if (systemCd) {
    systemCd.decisionClientMode = configState.clientMode;
    return systemCd;
  }

  if (!cd.sha256) {
    cd.sha256 = fileInfo.SHA256;
  }
  cd.signingStatus = signingStatusCallback();
  cd.platformBinary = (platformBinaryState == PlatformBinaryState::kRuntimeTrue);
  cd.decisionClientMode = configState.clientMode;
  cd.quarantineURL = fileInfo.quarantineDataURL;

  NSError* csInfoError;
  if (!cd.certSHA256.length) {
    // Grab the code signature, if there's an error don't try to capture
    // any of the signature details.
    // TODO(mlw): MOLCodesignChecker should be updated to still grab signing information
    // even if validity check fails. Once that is done, this code can be updated to grab
    // cert information so that it can still be reported to the sync server.
    MOLCodesignChecker* csInfo = [fileInfo codesignCheckerWithError:&csInfoError];
    if (csInfoError) {
      csInfo = nil;
      cd.decisionExtra = [NSString
          stringWithFormat:@"Signature ignored due to error: %ld", (long)csInfoError.code];
      cd.signingStatus = (cd.signingStatus == SNTSigningStatusUnsigned ? SNTSigningStatusUnsigned
                                                                       : SNTSigningStatusInvalid);
    } else {
      UpdateCachedDecisionSigningInfo(cd, csInfo, platformBinaryState, entitlementsFilterCallback);
    }
  }

  SNTRule* rule = [self.ruleTable executionRuleForIdentifiers:CreateRuleIDs(cd)];
  if (rule) {
    // If we have a rule match we don't need to process any further.
    if ([self decision:cd
                             forRule:rule
                 withTransitiveRules:self.configurator.enableTransitiveRules
            andCELActivationCallback:activationCallback]) {
      return cd;
    }
  }

  if ([self.configurator enableBadSignatureProtection] && csInfoError &&
      csInfoError.code != errSecCSUnsigned) {
    cd.decisionExtra =
        [NSString stringWithFormat:@"Blocked due to signature error: %ld", (long)csInfoError.code];
    cd.decision = SNTEventStateBlockCertificate;
    return cd;
  }

  if ([self evaluateCELFallbackExpressions:cd activationCallback:activationCallback]) {
    return cd;
  }

  if (platformBinaryState == PlatformBinaryState::kRuntimeTrue) {
    cd.decisionExtra = @"Platform Binary";
    cd.decision = SNTEventStateAllowPlatform;
    return cd;
  }

  NSString* msg = [self fileIsScopeBlocked:fileInfo];
  if (msg) {
    cd.decisionExtra = msg;
    cd.decision = SNTEventStateBlockScope;
    return cd;
  }

  msg = [self fileIsScopeAllowed:fileInfo];
  if (msg) {
    cd.decisionExtra = msg;
    cd.decision = SNTEventStateAllowScope;
    return cd;
  }

  switch (configState.clientMode) {
    case SNTClientModeMonitor: cd.decision = SNTEventStateAllowUnknown; return cd;
    case SNTClientModeStandalone: cd.holdAndAsk = YES; [[fallthrough]];
    case SNTClientModeLockdown: cd.decision = SNTEventStateBlockUnknown; return cd;
    default: cd.decision = SNTEventStateBlockUnknown; return cd;
  }
}

- (nonnull SNTCachedDecision*)decisionForFileInfo:(nonnull SNTFileInfo*)fileInfo
                                    targetProcess:(nonnull const es_process_t*)targetProc
                                      configState:(nonnull SNTConfigState*)configState
                               activationCallback:
                                   (nullable ActivationCallbackBlock)activationCallback
                                   cachedDecision:(nullable SNTCachedDecision*)existingDecision {
  PlatformBinaryState pbs = targetProc->is_platform_binary ? PlatformBinaryState::kRuntimeTrue
                                                           : PlatformBinaryState::kRuntimeFalse;

  const char* entitlementsFilterTeamID = NULL;
  SNTCachedDecision* cd;

  if (existingDecision) {
    cd = [[SNTCachedDecision alloc] initWithCachedIdentity:existingDecision];
    // Derive entitlementsFilterTeamID from the cached decision. The cd.teamID
    // was originally set under the same guards used in the else branch
    // (CS_SIGNED, CS_VALID, signing_id exists, team_id exists), so a non-nil
    // teamID implies all those conditions were satisfied.
    if (cd.teamID.length) {
      entitlementsFilterTeamID = cd.teamID.UTF8String;
    } else if (targetProc->is_platform_binary) {
      entitlementsFilterTeamID = "platform";
    }
  } else {
    cd = [[SNTCachedDecision alloc] init];

    if (targetProc->codesigning_flags & CS_SIGNED && targetProc->codesigning_flags & CS_VALID) {
      if (targetProc->signing_id.length > 0) {
        if (targetProc->team_id.length > 0) {
          entitlementsFilterTeamID = targetProc->team_id.data;
          cd.teamID = santa::StringTokenToNSString(targetProc->team_id);
          cd.signingID =
              [NSString stringWithFormat:@"%@:%@", cd.teamID,
                                         santa::StringTokenToNSString(targetProc->signing_id)];
        } else if (targetProc->is_platform_binary) {
          entitlementsFilterTeamID = "platform";
          cd.signingID =
              [NSString stringWithFormat:@"platform:%@",
                                         santa::StringTokenToNSString(targetProc->signing_id)];
        }
      }

      // Only consider the CDHash for processes where the kernel will
      // refuse invalid pages or kill the process if a page is loaded that
      // does not match its CodeDirectory slot hash.
      if (santa::CdhashStrictlyEnforced(targetProc->codesigning_flags)) {
        static NSString* const kCDHashFormatString = @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                                                      "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

        const uint8_t* buf = targetProc->cdhash;
        cd.cdhash = [[NSString alloc]
            initWithFormat:kCDHashFormatString, buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
                           buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13],
                           buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]];
      }
    }
  }

  return [self decisionForFileInfo:fileInfo
      configState:configState
      cachedDecision:cd
      platformBinaryState:pbs
      signingStatusCallback:^SNTSigningStatus {
        uint32_t csFlags = targetProc->codesigning_flags;
        if ((csFlags & CS_SIGNED) == 0) {
          return SNTSigningStatusUnsigned;
        } else if ((csFlags & CS_VALID) == 0) {
          return SNTSigningStatusInvalid;
        } else if ((csFlags & CS_ADHOC) == CS_ADHOC) {
          return SNTSigningStatusAdhoc;
        } else if ((csFlags & CS_DEV_CODE) == CS_DEV_CODE) {
          return SNTSigningStatusDevelopment;
        } else {
          return SNTSigningStatusProduction;
        }
      }
      activationCallback:activationCallback
      entitlementsFilterCallback:^NSDictionary*(NSDictionary* entitlements) {
        return entitlementsFilter_->Filter(entitlementsFilterTeamID, entitlements);
      }];
}

///
///  Checks whether the file at @c path is in-scope for checking with Santa.
///
///  Files that are out of scope:
///    + Non Mach-O files that are not part of an installer package.
///    + Files in allowed path.
///
///  @return @c YES if file is in scope, @c NO otherwise.
///
- (NSString*)fileIsScopeAllowed:(SNTFileInfo*)fi {
  if (!fi) return nil;

  // Determine if file is within an allowed path. Guard on a non-nil regex:
  // rangeOfFirstMatchInString: returns a zeroed NSRange (location 0, not
  // NSNotFound) when messaged on a nil regex, which would otherwise read as a
  // spurious match.
  NSRegularExpression* re = [self.configurator allowedPathRegex];
  if (re) {
    NSString* path = fi.path;
    if ([re rangeOfFirstMatchInString:path options:0 range:NSMakeRange(0, path.length)].location !=
        NSNotFound) {
      return @"Allowed Path Regex";
    }
  }

  // If file is not a Mach-O file, we're not interested.
  if (!fi.isMachO) {
    return @"Not a Mach-O";
  }

  return nil;
}

- (NSString*)fileIsScopeBlocked:(SNTFileInfo*)fi {
  if (!fi) return nil;

  // Guard on a non-nil regex; see fileIsScopeAllowed: for why the nil case
  // must be handled explicitly with rangeOfFirstMatchInString:.
  NSRegularExpression* re = [self.configurator blockedPathRegex];
  if (re) {
    NSString* path = fi.path;
    if ([re rangeOfFirstMatchInString:path options:0 range:NSMakeRange(0, path.length)].location !=
        NSNotFound) {
      return @"Blocked Path Regex";
    }
  }

  if ([self.configurator enablePageZeroProtection] && fi.isMissingPageZero) {
    return @"Missing __PAGEZERO";
  }

  return nil;
}

@end
