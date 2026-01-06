/// Copyright 2022 Google Inc. All rights reserved.
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

#import "src/common/PrefixTree.h"
#import "src/common/Unit.h"
#import "src/santad/event_providers/AuthResultCache.h"
#include "src/santad/event_providers/endpoint_security/EndpointSecurityAPI.h"
#include "src/santad/event_providers/endpoint_security/Enricher.h"
#import "src/santad/event_providers/SNTEndpointSecurityEventHandler.h"
#import "src/santad/event_providers/SNTEndpointSecurityTreeAwareClient.h"
#include "src/santad/logs/endpoint_security/Logger.h"
#import "src/santad/Metrics.h"
#include "src/santad/process_tree/process_tree.h"
#import "src/santad/SNTCompilerController.h"

/// ES Client focused on subscribing to NOTIFY event variants with the intention of enriching
/// received messages and logging the information.
@interface SNTEndpointSecurityRecorder
    : SNTEndpointSecurityTreeAwareClient <SNTEndpointSecurityEventHandler>

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
                       logger:(std::shared_ptr<santa::Logger>)logger
                     enricher:(std::shared_ptr<santa::Enricher>)enricher
           compilerController:(SNTCompilerController *)compilerController
              authResultCache:(std::shared_ptr<santa::AuthResultCache>)authResultCache
                   prefixTree:(std::shared_ptr<santa::PrefixTree<santa::Unit>>)prefixTree
                  processTree:
                      (std::shared_ptr<santa::santad::process_tree::ProcessTree>)processTree;

@end
