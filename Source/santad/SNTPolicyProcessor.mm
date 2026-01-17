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
#include "Source/common/SNTCommonEnums.h"

#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#import <Security/SecCode.h>
#import <Security/Security.h>

#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeepCopy.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SigningIDHelpers.h"
#include "Source/common/String.h"
#include "Source/common/cel/Evaluator.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

#include "absl/container/flat_hash_map.h"
#include "cel/v1.pb.h"

enum class PlatformBinaryState {
  kRuntimeTrue = 0,
  kRuntimeFalse,
  kStaticCheck,
};

struct RuleIdentifiers CreateRuleIDs(SNTCachedDecision *cd) {
  SNTRuleIdentifiers *ri =
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
}
@property SNTRuleTable *ruleTable;
@property SNTConfigurator *configurator;
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
  }
  return self;
}

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable
               entitlementsFilter:(std::shared_ptr<santa::EntitlementsFilter>)entitlementsFilter {
  self = [self init];
  if (self) {
    _ruleTable = ruleTable;
    entitlementsFilter_ = std::move(entitlementsFilter);
  }
  return self;
}

// This method applies the rules to the cached decision object.
//
// It returns YES if the decision was made, NO if the decision was not made.
- (BOOL)decision:(SNTCachedDecision *)cd
                     forRule:(SNTRule *)rule
         withTransitiveRules:(BOOL)enableTransitiveRules
    andCELActivationCallback:(ActivationCallbackBlock)activationCallback {
  SNTRuleState state = rule.state;
  SNTRuleType type = rule.type;

  if ((state == SNTRuleStateCEL || state == SNTRuleStateCELv2) && activationCallback) {
    bool useV2 = (state == SNTRuleStateCELv2);
    auto activation = activationCallback(useV2);

    absl::StatusOr<std::pair<int, bool>> evalResult;

    if (useV2) {
      auto *v2Activation = static_cast<santa::cel::Activation<true> *>(activation.get());
      // In debug builds, ensure the returned type matches expectations, but no
      // need to pay the RTTI cost in release builds since the number of returned
      // types is small and should rarely change.
      assert(dynamic_cast<santa::cel::Activation<true> *>(activation.get()) != nullptr);
      evalResult = self->celEvaluatorV2_->CompileAndEvaluate(
          santa::NSStringToUTF8StringView(rule.celExpr), *v2Activation);
    } else {
      auto *v1Activation = static_cast<santa::cel::Activation<false> *>(activation.get());
      assert(dynamic_cast<santa::cel::Activation<false> *>(activation.get()) != nullptr);
      evalResult = self->celEvaluatorV1_->CompileAndEvaluate(
          santa::NSStringToUTF8StringView(rule.celExpr), *v1Activation);
    }

    if (!evalResult.ok()) {
      LOGE(@"Failed to evaluate CEL rule (%@): %s", rule.celExpr,
           std::string(evalResult.status().message()).c_str());

      // If the CEL program failed to execute and the failClosed key is set
      // to true, then we should block.
      if ([SNTConfigurator configurator].failClosed) {
        cd.decision = SNTEventStateBlockUnknown;
        return YES;
      }
      return NO;
    }

    LOGD(@"Ran CEL program and received result: %d (cacheable %d)",
         static_cast<int>(evalResult->first), evalResult->second);

    if (useV2) {
      using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
      switch (static_cast<ReturnValue>(evalResult->first)) {
        case ReturnValue::ALLOWLIST: state = SNTRuleStateAllow; break;
        case ReturnValue::ALLOWLIST_COMPILER: state = SNTRuleStateAllowTransitive; break;
        case ReturnValue::BLOCKLIST: state = SNTRuleStateBlock; break;
        case ReturnValue::SILENT_BLOCKLIST: state = SNTRuleStateSilentBlock; break;
        case ReturnValue::REQUIRE_TOUCHID:
          // REQUIRE_TOUCHID responses are not cacheable.
          cd.holdAndAsk = YES;
          cd.cacheable = NO;
          state = SNTRuleStateBlock;
          break;
        case ReturnValue::REQUIRE_TOUCHID_ONLY:
          // REQUIRE_TOUCHID_ONLY responses are not cacheable.
          // Like REQUIRE_TOUCHID, but skips showing the block dialog.
          cd.holdAndAsk = YES;
          cd.silentTouchID = YES;
          cd.cacheable = NO;
          state = SNTRuleStateBlock;
          break;
        default: break;
      }
    } else {
      using ReturnValue = santa::cel::CELProtoTraits<false>::ReturnValue;
      switch (static_cast<ReturnValue>(evalResult->first)) {
        case ReturnValue::ALLOWLIST: state = SNTRuleStateAllow; break;
        case ReturnValue::ALLOWLIST_COMPILER: state = SNTRuleStateAllowTransitive; break;
        case ReturnValue::BLOCKLIST: state = SNTRuleStateBlock; break;
        case ReturnValue::SILENT_BLOCKLIST: state = SNTRuleStateSilentBlock; break;
        default: break;
      }
    }

    if (!evalResult->second) {
      cd.cacheable = NO;
    }
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

  return YES;
}

static void UpdateCachedDecisionSigningInfo(
    SNTCachedDecision *cd, MOLCodesignChecker *csInfo, PlatformBinaryState platformBinaryState,
    NSDictionary *_Nullable (^entitlementsFilterCallback)(NSDictionary *_Nullable entitlements)) {
  cd.certSHA256 = csInfo.leafCertificate.SHA256;
  cd.certCommonName = csInfo.leafCertificate.commonName;
  cd.certChain = csInfo.certificates;
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

  NSDictionary *entitlements = csInfo.entitlements;

  if (entitlementsFilterCallback) {
    cd.entitlements = entitlementsFilterCallback(entitlements);
    cd.entitlementsFiltered = (cd.entitlements.count != entitlements.count);
  } else {
    cd.entitlements = [entitlements sntDeepCopy];
    cd.entitlementsFiltered = NO;
  }

  cd.secureSigningTime = csInfo.secureSigningTime;
  cd.signingTime = csInfo.signingTime;
}

- (nonnull SNTCachedDecision *)
           decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                   configState:(nonnull SNTConfigState *)configState
                        cdhash:(nullable NSString *)cdhash
                    fileSHA256:(nullable NSString *)fileSHA256
             certificateSHA256:(nullable NSString *)certificateSHA256
                        teamID:(nullable NSString *)teamID
                     signingID:(nullable NSString *)signingID
           platformBinaryState:(PlatformBinaryState)platformBinaryState
         signingStatusCallback:(SNTSigningStatus (^_Nonnull)())signingStatusCallback
            activationCallback:(nullable ActivationCallbackBlock)activationCallback
    entitlementsFilterCallback:
        (NSDictionary *_Nullable (^_Nullable)(NSDictionary *_Nullable entitlements))
            entitlementsFilterCallback {
  // Check the hash before allocating a SNTCachedDecision.
  NSString *fileHash = fileSHA256 ?: fileInfo.SHA256;
  SNTClientMode mode = configState.clientMode;

  // If the binary is a critical system binary, don't check its signature.
  // The binary was validated at startup when the rule table was initialized.
  SNTCachedDecision *systemCd = self.ruleTable.criticalSystemBinaries[signingID];

  if (systemCd) {
    systemCd.decisionClientMode = mode;
    return systemCd;
  }

  // Allocate a new cached decision for the execution.
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.cdhash = cdhash;
  cd.sha256 = fileHash;
  cd.teamID = teamID;
  cd.signingID = signingID;
  cd.signingStatus = signingStatusCallback();
  cd.decisionClientMode = mode;
  cd.quarantineURL = fileInfo.quarantineDataURL;

  NSError *csInfoError;
  if (certificateSHA256.length) {
    cd.certSHA256 = certificateSHA256;
  } else {
    // Grab the code signature, if there's an error don't try to capture
    // any of the signature details.
    // TODO(mlw): MOLCodesignChecker should be updated to still grab signing information
    // even if validity check fails. Once that is done, this code can be updated to grab
    // cert information so that it can still be reported to the sync server.
    MOLCodesignChecker *csInfo = [fileInfo codesignCheckerWithError:&csInfoError];
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

  SNTRule *rule = [self.ruleTable executionRuleForIdentifiers:CreateRuleIDs(cd)];
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

  NSString *msg = [self fileIsScopeBlocked:fileInfo];
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

  switch (mode) {
    case SNTClientModeMonitor: cd.decision = SNTEventStateAllowUnknown; return cd;
    case SNTClientModeStandalone: cd.holdAndAsk = YES; [[fallthrough]];
    case SNTClientModeLockdown: cd.decision = SNTEventStateBlockUnknown; return cd;
    default: cd.decision = SNTEventStateBlockUnknown; return cd;
  }
}

- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                     targetProcess:(nonnull const es_process_t *)targetProc
                                       configState:(nonnull SNTConfigState *)configState
                                activationCallback:
                                    (nullable ActivationCallbackBlock)activationCallback {
  NSString *signingID;
  NSString *teamID;
  NSString *cdhash;

  const char *entitlementsFilterTeamID = NULL;

  if (targetProc->codesigning_flags & CS_SIGNED && targetProc->codesigning_flags & CS_VALID) {
    if (targetProc->signing_id.length > 0) {
      if (targetProc->team_id.length > 0) {
        entitlementsFilterTeamID = targetProc->team_id.data;
        teamID = [NSString stringWithUTF8String:targetProc->team_id.data];
        signingID =
            [NSString stringWithFormat:@"%@:%@", teamID,
                                       [NSString stringWithUTF8String:targetProc->signing_id.data]];
      } else if (targetProc->is_platform_binary) {
        entitlementsFilterTeamID = "platform";
        signingID =
            [NSString stringWithFormat:@"platform:%@",
                                       [NSString stringWithUTF8String:targetProc->signing_id.data]];
      }
    }

    // Only consider the CDHash for processes that have CS_KILL or CS_HARD set.
    // This ensures that the OS will kill the process if the CDHash was tampered
    // with and code was loaded that didn't match a page hash.
    if (targetProc->codesigning_flags & CS_KILL || targetProc->codesigning_flags & CS_HARD) {
      static NSString *const kCDHashFormatString = @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
                                                    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x";

      const uint8_t *buf = targetProc->cdhash;
      cdhash = [[NSString alloc] initWithFormat:kCDHashFormatString, buf[0], buf[1], buf[2], buf[3],
                                                buf[4], buf[5], buf[6], buf[7], buf[8], buf[9],
                                                buf[10], buf[11], buf[12], buf[13], buf[14],
                                                buf[15], buf[16], buf[17], buf[18], buf[19]];
    }
  }

  return [self decisionForFileInfo:fileInfo
      configState:configState
      cdhash:cdhash
      fileSHA256:nil
      certificateSHA256:nil
      teamID:teamID
      signingID:signingID
      platformBinaryState:targetProc->is_platform_binary ? PlatformBinaryState::kRuntimeTrue
                                                         : PlatformBinaryState::kRuntimeFalse
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
      entitlementsFilterCallback:^NSDictionary *(NSDictionary *entitlements) {
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
- (NSString *)fileIsScopeAllowed:(SNTFileInfo *)fi {
  if (!fi) return nil;

  // Determine if file is within an allowed path
  NSRegularExpression *re = [[SNTConfigurator configurator] allowedPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Allowed Path Regex";
  }

  // If file is not a Mach-O file, we're not interested.
  if (!fi.isMachO) {
    return @"Not a Mach-O";
  }

  return nil;
}

- (NSString *)fileIsScopeBlocked:(SNTFileInfo *)fi {
  if (!fi) return nil;

  NSRegularExpression *re = [[SNTConfigurator configurator] blockedPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Blocked Path Regex";
  }

  if ([[SNTConfigurator configurator] enablePageZeroProtection] && fi.isMissingPageZero) {
    return @"Missing __PAGEZERO";
  }

  return nil;
}

@end
