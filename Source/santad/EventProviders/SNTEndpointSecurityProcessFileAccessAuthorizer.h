/// Copyright 2025 North Pole Security, Inc.
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

#import <Foundation/Foundation.h>

#include <memory>

#include "Source/common/es/ESMetricsObserver.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#include "Source/common/faa/WatchItems.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClient.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"

@interface SNTEndpointSecurityProcessFileAccessAuthorizer
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler,
                                 SNTProcessFileAccessAuthorizer,
                                 SNTEndpointSecurityProbe>

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                        metrics:(std::shared_ptr<santa::ESMetricsObserver>)metrics
             faaPolicyProcessor:
                 (std::shared_ptr<santa::ProcessFAAPolicyProcessorProxy>)faaPolicyProcessorProxy
    iterateProcessPoliciesBlock:(santa::IterateProcessPoliciesBlock)findProcessPoliciesBlock;

@property SNTFileAccessDeniedBlock fileAccessDeniedBlock;

@end
