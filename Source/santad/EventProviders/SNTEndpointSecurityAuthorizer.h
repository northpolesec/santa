/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/common/es/EndpointSecurityAPI.h"
#include "Source/common/es/Enricher.h"

#include "Source/common/es/ESMetricsObserver.h"
#import "Source/common/es/SNTEndpointSecurityClient.h"
#import "Source/common/es/SNTEndpointSecurityEventHandler.h"
#import "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/SNTCompilerController.h"
#import "Source/santad/SNTExecutionController.h"
#include "Source/santad/TTYWriter.h"

/// ES Client focused on subscribing to AUTH variants and authorizing the events
/// based on configured policy.
@interface SNTEndpointSecurityAuthorizer
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler>

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::ESMetricsObserver>)metrics
               execController:(SNTExecutionController *)execController
           compilerController:(SNTCompilerController *)compilerController
              authResultCache:(std::shared_ptr<santa::AuthResultCache>)authResultCache
                    ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter;

- (void)registerAuthExecProbe:(id<SNTEndpointSecurityProbe>)watcher;

@end
