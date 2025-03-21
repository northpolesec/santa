/// Copyright 2022 Google LLC
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

#import <Foundation/Foundation.h>

#include <memory>

#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTDecisionCache.h"
#include "Source/santad/TTYWriter.h"

@interface SNTEndpointSecurityDataFileAccessAuthorizer
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler, SNTDataFileAccessAuthorizer>

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                        metrics:(std::shared_ptr<santa::Metrics>)metrics
                         logger:(std::shared_ptr<santa::Logger>)logger
                       enricher:(std::shared_ptr<santa::Enricher>)enricher
             faaPolicyProcessor:
                 (std::shared_ptr<santa::DataFAAPolicyProcessorProxy>)faaPolicyProcessorProxy
                      ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter
    findPoliciesForTargetsBlock:(santa::FindPoliciesForTargetsBlock)findPoliciesForTargetsBlock;

@property SNTFileAccessDeniedBlock fileAccessDeniedBlock;

@end
