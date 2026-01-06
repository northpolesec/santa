/// Copyright 2015-2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <memory>

#import "src/common/MOLCertificate.h"
#import "src/common/SNTCommonEnums.h"
#import "src/common/SNTConfigState.h"
#import "src/common/SNTRule.h"
#import "src/common/SNTRuleIdentifiers.h"
#include "src/common/cel/Activation.h"
#include "src/santad/EntitlementsFilter.h"

@class MOLCodesignChecker;
@class SNTCachedDecision;
@class SNTFileInfo;
@class SNTRuleTable;

// Use CELv2 for evaluation. v2 will always be a superset of v1.
typedef std::unique_ptr<santa::cel::Activation<true>> (^ActivationCallbackBlock)(void);

///
///  Creates SNTCachedDecision objects from a SNTFileInfo object or a file path. Decisions are based
///  on any existing rules for that specific binary, its signing certificate and the operating mode
///  of santad.
///
@interface SNTPolicyProcessor : NSObject

///
///  @param ruleTable The rule table to be used for every decision
///
- (nullable instancetype)initWithRuleTable:(nonnull SNTRuleTable *)ruleTable
                        entitlementsFilter:
                            (std::shared_ptr<santa::EntitlementsFilter>)entitlementsFilter;

///
///  Convenience initializer. Will obtain the teamID and construct the signingID
///  identifier if able.
///
///  IMPORTANT: The lifetimes of arguments to `entitlementsFilterCallback` are
///  only guaranteed for the duration of the call to the block. Do not perform
///  any async processing without extending their lifetimes.
///
- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                     targetProcess:(nonnull const es_process_t *)targetProc
                                       configState:(nonnull SNTConfigState *)configState
                                activationCallback:
                                    (nullable ActivationCallbackBlock)activationCallback;

///
/// Updates a decision for a given file and agent configuration.
///
/// Returns YES if the decision requires no futher processing NO otherwise.
- (BOOL)decision:(nonnull SNTCachedDecision *)cd
                     forRule:(nonnull SNTRule *)rule
         withTransitiveRules:(BOOL)transitive
    andCELActivationCallback:(nullable ActivationCallbackBlock)activationCallback;

@end
