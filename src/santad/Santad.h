/// Copyright 2022 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTAD_SANTAD_H
#define SANTA__SANTAD_SANTAD_H

#import "src/common/MOLXPCConnection.h"
#include "src/common/PrefixTree.h"
#include "src/common/Unit.h"
#include "src/common/faa/WatchItems.h"
#include "src/santad/event_providers/AuthResultCache.h"
#include "src/santad/event_providers/endpoint_security/EndpointSecurityAPI.h"
#include "src/santad/event_providers/endpoint_security/Enricher.h"
#include "src/santad/logs/endpoint_security/Logger.h"
#include "src/santad/Metrics.h"
#include "src/santad/process_tree/process_tree.h"
#import "src/santad/SNTCompilerController.h"
#import "src/santad/SNTExecutionController.h"
#import "src/santad/SNTNotificationQueue.h"
#import "src/santad/SNTSyncdQueue.h"
#include "src/santad/TTYWriter.h"

void SantadMain(
    std::shared_ptr<santa::EndpointSecurityAPI> esapi,
    std::shared_ptr<santa::Logger> logger,
    std::shared_ptr<santa::Metrics> metrics,
    std::shared_ptr<santa::WatchItems> watch_items,
    std::shared_ptr<santa::Enricher> enricher,
    std::shared_ptr<santa::AuthResultCache> auth_result_cache,
    MOLXPCConnection* control_connection,
    SNTCompilerController* compiler_controller,
    SNTNotificationQueue* notifier_queue, SNTSyncdQueue* syncd_queue,
    SNTExecutionController* exec_controller,
    std::shared_ptr<santa::PrefixTree<santa::Unit>> prefix_tree,
    std::shared_ptr<santa::TTYWriter> tty_writer,
    std::shared_ptr<santa::santad::process_tree::ProcessTree> process_tree,
    std::shared_ptr<santa::EntitlementsFilter> entitlements_filter);

#endif
