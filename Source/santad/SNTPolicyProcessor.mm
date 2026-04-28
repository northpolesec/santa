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
#include <string.h>
#include <sys/stat.h>

#import "Source/common/CertificateHelpers.h"
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
#include "Source/common/cel/Evaluator.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "cel/v1.pb.h"

enum class PlatformBinaryState {
  kRuntimeTrue = 0,
  kRuntimeFalse,
  kStaticCheck,
};

using VerifyIdentityBlock = IdentityVerifyResult (^)(MOLCodesignChecker* _Nullable csInfo);

static BOOL CdhashEqual(const uint8_t* targetCdhash, NSString* _Nullable diskCdhashHex) {
  if (!diskCdhashHex || diskCdhashHex.length != CS_CDHASH_LEN * 2) return NO;
  std::vector<uint8_t> diskBytes = santa::HexStringToBuf(diskCdhashHex);
  if (diskBytes.size() != CS_CDHASH_LEN) return NO;
  return memcmp(targetCdhash, diskBytes.data(), CS_CDHASH_LEN) == 0;
}

struct CELEvaluationResult {
  bool succeeded;            // Whether CEL evaluation succeeded
  bool decisionMade;         // If !succeeded, whether a decision was made (fail-closed)
  SNTRuleState resultState;  // If succeeded, the resulting state
};

struct RuleIdentifiers CreateRuleIDs(SNTCachedDecision* cd) {
  SNTRuleIdentifiers* ri =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{
                                                              .cdhash = cd.cdhash,
                                                              .binarySHA256 = cd.sha256,
                                                              .signingID = cd.signingID,
                                                              .certificateSHA256 = cd.certSHA256,
                                                              .teamID = cd.teamID,
                                                          }
                                         andSigningStatus:cd.signingStatus];

  return [ri toStruct];
}

@interface SNTPolicyProcessor () {
  std::unique_ptr<santa::cel::Evaluator<false>> celEvaluatorV1_;
  std::unique_ptr<santa::cel::Evaluator<true>> celEvaluatorV2_;
  std::shared_ptr<santa::EntitlementsFilter> entitlementsFilter_;
  // Arena used for constant folding during compilation of fallback rules.
  // Declared before celFallbackRules_ so that C++ reverse destruction
  // order destroys rules first, then the arena they reference.
  std::shared_ptr<google::protobuf::Arena> celFallbackArena_;
  struct CompiledFallbackRule {
    std::shared_ptr<::google::api::expr::runtime::CelExpression> expression;
    NSString* customMsg;
    NSString* customURL;
  };
  std::vector<CompiledFallbackRule> celFallbackRules_;
}
@property SNTRuleTable* ruleTable;
@property SNTConfigurator* configurator;
@property dispatch_queue_t celFallbackQueue;
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
    } else {
      LOGW(@"Failed to create CEL v1 evaluator: %s",
           std::string(evaluatorV1.status().message()).c_str());
    }

    auto evaluatorV2 = santa::cel::Evaluator<true>::Create();
    if (evaluatorV2.ok()) {
      celEvaluatorV2_ = std::move(*evaluatorV2);
    } else {
      LOGW(@"Failed to create CEL v2 evaluator: %s",
           std::string(evaluatorV2.status().message()).c_str());
    }

    _celFallbackQueue =
        dispatch_queue_create("com.northpolesec.santa.cel_fallback", DISPATCH_QUEUE_SERIAL);

    // Pre-compile any existing fallback rules
    [self compileFallbackRules:_configurator.celFallbackRules];

    // Observe changes to fallback rules
    __weak __typeof(self) weakSelf = self;
    _celFallbackRulesObserver =
        [[SNTKVOManager alloc] initWithObject:_configurator
                                     selector:@selector(celFallbackRules)
                                         type:[NSArray class]
                                     callback:^(id oldValue, id newValue) {
                                       [weakSelf compileFallbackRules:(NSArray*)newValue];
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

  // Create a fresh arena for this batch of compiled rules.
  // The arena must outlive the compiled plans since constant folding stores
  // data on it.
  __block auto arena = std::make_shared<google::protobuf::Arena>();
  __block std::vector<CompiledFallbackRule> compiled;
  compiled.reserve(rules.count);
  bool compileFailed = false;
  for (SNTCELFallbackRule* rule in rules) {
    auto result =
        celEvaluatorV2_->Compile(santa::NSStringToUTF8StringView(rule.celExpr), arena.get());
    if (result.ok()) {
      compiled.push_back({std::move(*result), rule.customMsg, rule.customURL});
    } else {
      LOGE(@"Failed to compile CEL fallback expression '%@': %s", rule.celExpr,
           std::string(result.status().message()).c_str());
      compileFailed = true;
      break;
    }
  }

  if (compileFailed) {
    return;
  }

  dispatch_sync(self.celFallbackQueue, ^{
    // Release old rules before the old arena (order matters).
    celFallbackRules_ = std::move(compiled);
    celFallbackArena_ = std::move(arena);
  });
}

- (BOOL)evaluateCELFallbackExpressions:(SNTCachedDecision*)cd
                    activationCallback:(ActivationCallbackBlock)activationCallback {
  if (!celEvaluatorV2_ || !activationCallback) {
    return NO;
  }

  // Snapshot the compiled rules and arena under the lock so their
  // lifetimes extend through evaluation even if compileFallbackRules
  // swaps them concurrently.
  __block std::vector<CompiledFallbackRule> rules;
  __block std::shared_ptr<google::protobuf::Arena> arenaRef;
  dispatch_sync(self.celFallbackQueue, ^{
    rules = celFallbackRules_;
    arenaRef = celFallbackArena_;
  });

  if (rules.empty()) {
    return NO;
  }

  auto activation = activationCallback(/*useV2=*/true);

  // Use a stack-local arena for evaluation temporaries.
  google::protobuf::Arena evalArena;

  for (size_t i = 0; i < rules.size(); ++i) {
    CELEvaluationResult celResult = [self evaluateCompiledCELExpression:rules[i].expression.get()
                                                                  useV2:true
                                                         cachedDecision:cd
                                                             activation:*activation
                                                              evalArena:&evalArena];

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
    cd.customMsg = rules[i].customMsg;
    cd.customURL = rules[i].customURL;
    return YES;
  }

  return NO;
}

- (CELEvaluationResult)
    evaluateCompiledCELExpression:(const ::google::api::expr::runtime::CelExpression*)expression
                            useV2:(bool)useV2
                   cachedDecision:(SNTCachedDecision*)cd
                       activation:(const ::google::api::expr::runtime::BaseActivation&)activation
                        evalArena:(google::protobuf::Arena*)evalArena {
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
      if ([SNTConfigurator configurator].failClosed) {
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
      if ([SNTConfigurator configurator].failClosed) {
        cd.decision = SNTEventStateBlockUnknown;
        return {.succeeded = false, .decisionMade = true, .resultState = {}};
      }
      return {.succeeded = false, .decisionMade = false, .resultState = {}};
    }

    returnValue = static_cast<int>(evalResult->value);
    cacheable = evalResult->cacheable;
    // V1 doesn't support TouchID, so cooldown is always nullopt
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
      default:
        LOGW(@"Unexpected return value from CEL expression: %d", returnValue);
        return {.succeeded = false, .decisionMade = false, .resultState = {}};
    }
  }

  if (resultState == SNTRuleStateSilentBlock) {
    cd.silentBlock = YES;
  }

  if (!cacheable) {
    cd.cacheable = NO;
  }

  return {.succeeded = true, .decisionMade = false, .resultState = resultState};
}

- (CELEvaluationResult)evaluateCELExpressionForRule:(SNTRule*)rule
                                     cachedDecision:(SNTCachedDecision*)cd
                                 activationCallback:(ActivationCallbackBlock)activationCallback {
  bool useV2 = (rule.state == SNTRuleStateCELv2);
  auto activation = activationCallback(useV2);

  google::protobuf::Arena arena;

  if ((useV2 && !celEvaluatorV2_) || (!useV2 && !celEvaluatorV1_)) {
    LOGE(@"CEL v%d evaluator unavailable", useV2 ? 2 : 1);
    if ([SNTConfigurator configurator].failClosed) {
      cd.decision = SNTEventStateBlockUnknown;
      return {.succeeded = false, .decisionMade = true, .resultState = {}};
    }
    return {.succeeded = false, .decisionMade = false, .resultState = {}};
  }

  absl::StatusOr<std::unique_ptr<::google::api::expr::runtime::CelExpression>> compileResult;
  if (useV2) {
    assert(dynamic_cast<santa::cel::Activation<true>*>(activation.get()) != nullptr);
    compileResult = celEvaluatorV2_->Compile(santa::NSStringToUTF8StringView(rule.celExpr), &arena);
  } else {
    assert(dynamic_cast<santa::cel::Activation<false>*>(activation.get()) != nullptr);
    compileResult = celEvaluatorV1_->Compile(santa::NSStringToUTF8StringView(rule.celExpr), &arena);
  }

  if (!compileResult.ok()) {
    LOGE(@"Failed to compile CEL rule (%@): %s", rule.celExpr,
         std::string(compileResult.status().message()).c_str());
    if ([SNTConfigurator configurator].failClosed) {
      cd.decision = SNTEventStateBlockUnknown;
      return {.succeeded = false, .decisionMade = true, .resultState = {}};
    }
    return {.succeeded = false, .decisionMade = false, .resultState = {}};
  }

  return [self evaluateCompiledCELExpression:compileResult->get()
                                       useV2:useV2
                              cachedDecision:cd
                                  activation:*activation
                                   evalArena:&arena];
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
          {{SNTRuleTypeBinary, SNTRuleStateAllow}, SNTEventStateAllowBinary},
          {{SNTRuleTypeBinary, SNTRuleStateAllowLocalBinary}, SNTEventStateAllowLocalBinary},
          {{SNTRuleTypeBinary, SNTRuleStateAllowTransitive}, SNTEventStateAllowTransitive},
          {{SNTRuleTypeBinary, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompilerBinary},
          {{SNTRuleTypeBinary, SNTRuleStateSilentBlock}, SNTEventStateBlockBinary},
          {{SNTRuleTypeBinary, SNTRuleStateBlock}, SNTEventStateBlockBinary},
          {{SNTRuleTypeSigningID, SNTRuleStateAllow}, SNTEventStateAllowSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateAllowLocalSigningID},
           SNTEventStateAllowLocalSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompilerSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateSilentBlock}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeSigningID, SNTRuleStateBlock}, SNTEventStateBlockSigningID},
          {{SNTRuleTypeCertificate, SNTRuleStateAllow}, SNTEventStateAllowCertificate},
          {{SNTRuleTypeCertificate, SNTRuleStateSilentBlock}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeCertificate, SNTRuleStateBlock}, SNTEventStateBlockCertificate},
          {{SNTRuleTypeTeamID, SNTRuleStateAllow}, SNTEventStateAllowTeamID},
          {{SNTRuleTypeTeamID, SNTRuleStateSilentBlock}, SNTEventStateBlockTeamID},
          {{SNTRuleTypeTeamID, SNTRuleStateBlock}, SNTEventStateBlockTeamID},
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
    case SNTRuleStateSilentBlock: cd.silentBlock = YES; break;
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
    default:
      // If its not one of the special cases above, we don't need to do anything.
      break;
  }

  // We know we have a match so apply the custom messages
  cd.customMsg = rule.customMsg;
  cd.customURL = rule.customURL;
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

+ (IdentityVerifyResult)verifyIdentityForTargetProc:(const es_process_t*)targetProc
                                                 fd:(int)fd
                                             csInfo:(MOLCodesignChecker*)csInfo {
  // Each non-match return emits a log. Lazily hex-encode the cdhash so no penalty on the happy path
  NSString* (^esCdhashHex)(void) = ^NSString*(void) {
    return santa::StringToNSString(santa::BufToHexString(targetProc->cdhash, CS_CDHASH_LEN));
  };
  NSString* path =
      targetProc->executable->path.data ? @(targetProc->executable->path.data) : @"(null)";

  BOOL esSigned = (targetProc->codesigning_flags & CS_SIGNED) != 0;
  BOOL diskSigned = (csInfo != nil && csInfo.cdhash.length > 0);

  // Case 1: signedness disagrees.
  if (esSigned != diskSigned) {
    LOGW(@"Identity verification: signedness mismatch path=%@ es_signed=%d disk_signed=%d "
         @"es_cdhash=%@ disk_cdhash=%@",
         path, esSigned, diskSigned, esCdhashHex(), csInfo.cdhash ?: @"(nil)");
    return IdentityVerifyResult::kMismatch;
  }

  if (esSigned) {
    // ES suppresses team_id on platform binaries even when the on-disk
    // signature carries an Apple TeamID (observed for Apple-signed XPC
    // services inside framework bundles, e.g. Xcode's helpers). Skip the
    // team_id presence and equality checks for that class; signing_id and
    // cdhash still bind identity end-to-end.
    BOOL esTeamSuppressed = targetProc->is_platform_binary;
    BOOL esHasTeam = targetProc->team_id.length > 0;
    BOOL diskHasTeam = csInfo.teamID.length > 0;
    BOOL esHasSID = targetProc->signing_id.length > 0;
    BOOL diskHasSID = csInfo.signingID.length > 0;

    // Case 2: presence disagrees on a non-suppressed dimension.
    if (esHasSID != diskHasSID || (!esTeamSuppressed && esHasTeam != diskHasTeam)) {
      LOGW(@"Identity verification: signing identifier presence mismatch path=%@ "
           @"es_platform=%d es_has_team=%d disk_has_team=%d "
           @"es_has_sid=%d disk_has_sid=%d es_team=%s es_sid=%s disk_team=%@ disk_sid=%@",
           path, esTeamSuppressed, esHasTeam, diskHasTeam, esHasSID, diskHasSID,
           esHasTeam ? targetProc->team_id.data : "", esHasSID ? targetProc->signing_id.data : "",
           csInfo.teamID ?: @"", csInfo.signingID ?: @"");
      return IdentityVerifyResult::kMismatch;
    }

    if (esHasSID) {
      // Case 3: signing_id must match. team_id is only enforced when ES
      // surfaced one — platform binaries skip team_id equality entirely
      // since the ES side is suppressed.
      NSString* esSID = @(targetProc->signing_id.data);
      if (![esSID isEqualToString:csInfo.signingID]) {
        LOGW(@"Identity verification: signing ID mismatch path=%@ es_sid=%@ disk_sid=%@", path,
             esSID, csInfo.signingID);
        return IdentityVerifyResult::kMismatch;
      }
      if (esHasTeam) {
        NSString* esTeam = @(targetProc->team_id.data);
        if (![esTeam isEqualToString:csInfo.teamID]) {
          LOGW(@"Identity verification: team ID mismatch path=%@ es_team=%@ disk_team=%@ sid=%@",
               path, esTeam, csInfo.teamID, esSID);
          return IdentityVerifyResult::kMismatch;
        }
      }
      if (CdhashEqual(targetProc->cdhash, csInfo.cdhash)) {
        return IdentityVerifyResult::kMatch;
      }
      LOGW(@"Identity verification: cdhash drift (allowed) path=%@ "
           @"es_platform=%d sid=%@ disk_team=%@ es_cdhash=%@ disk_cdhash=%@",
           path, esTeamSuppressed, esSID, csInfo.teamID ?: @"", esCdhashHex(),
           csInfo.cdhash ?: @"(nil)");
      return IdentityVerifyResult::kDriftAllowed;
    }

    // Case 4: no signing_id either side (ad-hoc) -> cdhash must match.
    if (CdhashEqual(targetProc->cdhash, csInfo.cdhash)) {
      return IdentityVerifyResult::kMatch;
    }
    LOGW(@"Identity verification: ad hoc cdhash mismatch path=%@ es_cdhash=%@ disk_cdhash=%@", path,
         esCdhashHex(), csInfo.cdhash ?: @"(nil)");
    return IdentityVerifyResult::kMismatch;
  }

  // Case 5: both unsigned -> stat compare on (dev, ino, size, mtime).
  struct stat st;
  if (fstat(fd, &st) != 0) {
    LOGW(@"Identity verification: disk fstat failed path=%@ errno=%d", path, errno);
    return IdentityVerifyResult::kMismatch;  // fail-closed
  }
  const struct stat* esStat = &targetProc->executable->stat;
  if (st.st_dev != esStat->st_dev || st.st_ino != esStat->st_ino || st.st_size != esStat->st_size ||
      st.st_mtimespec.tv_sec != esStat->st_mtimespec.tv_sec ||
      st.st_mtimespec.tv_nsec != esStat->st_mtimespec.tv_nsec) {
    LOGW(@"Identity verification: unsigned binary metadata mismatch path=%@ "
         @"es_dev=%d disk_dev=%d es_ino=%llu disk_ino=%llu "
         @"es_size=%lld disk_size=%lld es_mtime=%ld.%09ld disk_mtime=%ld.%09ld",
         path, esStat->st_dev, st.st_dev, (unsigned long long)esStat->st_ino,
         (unsigned long long)st.st_ino, (long long)esStat->st_size, (long long)st.st_size,
         (long)esStat->st_mtimespec.tv_sec, (long)esStat->st_mtimespec.tv_nsec,
         (long)st.st_mtimespec.tv_sec, (long)st.st_mtimespec.tv_nsec);
    return IdentityVerifyResult::kMismatch;
  }
  return IdentityVerifyResult::kMatch;
}

- (nonnull SNTCachedDecision*)
           decisionForFileInfo:(nonnull SNTFileInfo*)fileInfo
                   configState:(nonnull SNTConfigState*)configState
                cachedDecision:(nonnull SNTCachedDecision*)cd
           platformBinaryState:(PlatformBinaryState)platformBinaryState
         signingStatusCallback:(SNTSigningStatus (^_Nonnull)())signingStatusCallback
            activationCallback:(nullable ActivationCallbackBlock)activationCallback
                verifyIdentity:(nullable VerifyIdentityBlock)verifyIdentity
    entitlementsFilterCallback:
        (NSDictionary* _Nullable (^_Nullable)(NSDictionary* _Nullable entitlements))
            entitlementsFilterCallback {
  // If the binary is a critical system binary, don't check its signature.
  // Critical binaries are SIP or tamper protected and were validated at
  // startup when the rule table was initialized; the kernel's CS_KILL/CS_HARD
  // enforcement guarantees the SigningID matched here can only be issued for
  // legitimately-signed binaries with that identity.
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
    MOLCodesignChecker* csInfo = [fileInfo codesignCheckerWithError:&csInfoError];

    // The verifier compares ES-side identity against whatever identity MOL
    // was able to extract. MOLCodesignChecker populates `_signingInformation`
    // for partial-validity errors that still let SecCodeCopySigningInformation
    // succeed (e.g. errSecCSInfoPlistFailed for binaries inside bundles, where
    // SecStaticCode via /dev/fd/N can't reach the bundle's Info.plist). When
    // identity could not be extracted (createWithPath failed, or MOL's per-arch
    // consistency check tripped errSecCSSignatureInvalid in MOL's domain), the
    // cdhash is empty and the verifier's case-1 signedness check returns a
    // mismatch on its own — no special-casing needed at the call site.
    if (verifyIdentity) {
      switch (verifyIdentity(csInfo)) {
        case IdentityVerifyResult::kMismatch:
          cd.decision = SNTEventStateBlockBinaryMismatch;
          cd.decisionExtra = @"Binary identity mismatch between ES event and on-disk file";
          return cd;
        case IdentityVerifyResult::kDriftAllowed:
          cd.decisionExtra = @"CDHash drift allowed by matching TeamID/SigningID";
          break;
        case IdentityVerifyResult::kMatch: break;
      }
    }

    if (csInfo && csInfo.cdhash.length > 0) {
      // Identity was extracted — populate signing details and keep whatever
      // signingStatus the kernel reported, even if csInfoError is set.
      UpdateCachedDecisionSigningInfo(cd, csInfo, platformBinaryState, entitlementsFilterCallback);
    } else if (csInfoError) {
      cd.decisionExtra = [NSString
          stringWithFormat:@"Signature ignored due to error: %ld", (long)csInfoError.code];
      cd.signingStatus = (cd.signingStatus == SNTSigningStatusUnsigned ? SNTSigningStatusUnsigned
                                                                       : SNTSigningStatusInvalid);
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

  if ([[SNTConfigurator configurator] enableBadSignatureProtection] && csInfoError &&
      csInfoError.code != errSecCSUnsigned) {
    cd.decisionExtra =
        [NSString stringWithFormat:@"Blocked due to signature error: %ld", (long)csInfoError.code];
    cd.decision = SNTEventStateBlockCertificate;
    return cd;
  }

  if ([self evaluateCELFallbackExpressions:cd activationCallback:activationCallback]) {
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
          cd.teamID = [NSString stringWithUTF8String:targetProc->team_id.data];
          cd.signingID = [NSString
              stringWithFormat:@"%@:%@", cd.teamID,
                               [NSString stringWithUTF8String:targetProc->signing_id.data]];
        } else if (targetProc->is_platform_binary) {
          entitlementsFilterTeamID = "platform";
          cd.signingID = [NSString
              stringWithFormat:@"platform:%@",
                               [NSString stringWithUTF8String:targetProc->signing_id.data]];
        }
      }

      // Only consider the CDHash for processes that have CS_KILL or CS_HARD set.
      // This ensures that the OS will kill the process if the CDHash was tampered
      // with and code was loaded that didn't match a page hash.
      if (targetProc->codesigning_flags & CS_KILL || targetProc->codesigning_flags & CS_HARD) {
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

  VerifyIdentityBlock verifyIdentity = nil;
  if (!existingDecision) {
    int fd = fileInfo.fileHandle.fileDescriptor;
    verifyIdentity = ^IdentityVerifyResult(MOLCodesignChecker* _Nullable csInfo) {
      return [SNTPolicyProcessor verifyIdentityForTargetProc:targetProc fd:fd csInfo:csInfo];
    };
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
      verifyIdentity:verifyIdentity
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

  // Determine if file is within an allowed path
  NSRegularExpression* re = [[SNTConfigurator configurator] allowedPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Allowed Path Regex";
  }

  // If file is not a Mach-O file, we're not interested.
  if (!fi.isMachO) {
    return @"Not a Mach-O";
  }

  return nil;
}

- (NSString*)fileIsScopeBlocked:(SNTFileInfo*)fi {
  if (!fi) return nil;

  NSRegularExpression* re = [[SNTConfigurator configurator] blockedPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Blocked Path Regex";
  }

  if ([[SNTConfigurator configurator] enablePageZeroProtection] && fi.isMissingPageZero) {
    return @"Missing __PAGEZERO";
  }

  return nil;
}

@end
