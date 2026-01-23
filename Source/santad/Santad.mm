/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/santad/Santad.h"

#include <cstdlib>
#include <memory>

#include "Source/common/PrefixTree.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTStoredNetworkMountEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/common/faa/WatchItems.h"
#include "Source/santad/DaemonConfigBundle.h"
#include "Source/santad/DataLayer/SNTEventTable.h"
#include "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDataFileAccessAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDeviceManager.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityRecorder.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/SNTDaemonControlController.h"
#include "Source/santad/SNTDatabaseController.h"
#include "Source/santad/SNTDecisionCache.h"
#include "Source/santad/TTYWriter.h"

using santa::AuthResultCache;
using santa::EndpointSecurityAPI;
using santa::Enricher;
using santa::FlushCacheMode;
using santa::FlushCacheReason;
using santa::Logger;
using santa::Metrics;
using santa::PrefixTree;
using santa::TTYWriter;
using santa::Unit;
using santa::WatchItems;

static NSString *ClientModeName(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor: return @"Monitor";
    case SNTClientModeLockdown: return @"Lockdown";
    case SNTClientModeStandalone: return @"Standalone";
    default: return @"Unknown";
  }
}

void SantadMain(std::shared_ptr<EndpointSecurityAPI> esapi, std::shared_ptr<Logger> logger,
                std::shared_ptr<Metrics> metrics, std::shared_ptr<santa::WatchItems> watch_items,
                std::shared_ptr<Enricher> enricher,
                std::shared_ptr<AuthResultCache> auth_result_cache,
                MOLXPCConnection *control_connection, SNTCompilerController *compiler_controller,
                SNTNotificationQueue *notifier_queue, SNTSyncdQueue *syncd_queue,
                SNTNetworkExtensionQueue *netext_queue, SNTExecutionController *exec_controller,
                std::shared_ptr<santa::PrefixTree<santa::Unit>> prefix_tree,
                std::shared_ptr<TTYWriter> tty_writer,
                std::shared_ptr<santa::santad::process_tree::ProcessTree> process_tree,
                std::shared_ptr<santa::EntitlementsFilter> entitlements_filter) {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  SNTDaemonControlController *dc =
      [[SNTDaemonControlController alloc] initWithAuthResultCache:auth_result_cache
                                                notificationQueue:notifier_queue
                                                       syncdQueue:syncd_queue
                                                netExtensionQueue:netext_queue
                                                           logger:logger
                                                       watchItems:watch_items];

  control_connection.exportedObject = dc;
  [control_connection resume];

  if ([configurator exportMetrics]) {
    metrics->StartPoll();
  }

  SNTEndpointSecurityDeviceManager *device_client =
      [[SNTEndpointSecurityDeviceManager alloc] initWithESAPI:esapi
                                                      metrics:metrics
                                                       logger:logger
                                                     enricher:enricher
                                              authResultCache:auth_result_cache
                                                blockUSBMount:[configurator blockUSBMount]
                                               remountUSBMode:[configurator remountUSBMode]
                                           startupPreferences:[configurator onStartUSBOptions]];

  device_client.deviceBlockCallback = ^(SNTDeviceEvent *event) {
    [[notifier_queue.notifierConnection remoteObjectProxy] postUSBBlockNotification:event];
  };

  device_client.networkMountCallback = ^(SNTStoredNetworkMountEvent *event) {
    [syncd_queue addStoredEvent:event];
    [[notifier_queue.notifierConnection remoteObjectProxy]
        postNetworkMountNotification:event
                        configBundle:santa::NetworkMountConfigBundle(
                                         [SNTConfigurator configurator])];
  };

  SNTEndpointSecurityRecorder *monitor_client =
      [[SNTEndpointSecurityRecorder alloc] initWithESAPI:esapi
                                                 metrics:metrics
                                                  logger:logger
                                                enricher:enricher
                                      compilerController:compiler_controller
                                         authResultCache:auth_result_cache
                                              prefixTree:prefix_tree
                                             processTree:process_tree];

  SNTEndpointSecurityAuthorizer *authorizer_client =
      [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:esapi
                                                   metrics:metrics
                                            execController:exec_controller
                                        compilerController:compiler_controller
                                           authResultCache:auth_result_cache
                                                 ttyWriter:tty_writer];

  // While any client could be used, this implementation chooses to use the
  // authorizer client as it is most concerned with the state of ES caches.
  auth_result_cache->SetESClient(authorizer_client);

  SNTEndpointSecurityTamperResistance *tamper_client =
      [[SNTEndpointSecurityTamperResistance alloc] initWithESAPI:esapi
                                                         metrics:metrics
                                                          logger:logger];

  auto faaPolicyProcessor = std::make_shared<santa::FAAPolicyProcessor>(
      [SNTDecisionCache sharedCache], enricher, logger, tty_writer, metrics,
      configurator.fileAccessGlobalLogsPerSec, configurator.fileAccessGlobalWindowSizeSec,
      ^santa::FAAPolicyProcessor::URLTextPair(
          const std::shared_ptr<santa::WatchItemPolicyBase> &policy) {
        return watch_items->EventDetailLinkInfo(policy);
      },
      ^(SNTStoredFileAccessEvent *event, bool sendImmediately) {
        // Only store FAA events if a sync server is configured.
        if (configurator.syncBaseURL) {
          [[SNTDatabaseController eventTable] addStoredEvent:event];

          if (sendImmediately) {
            [syncd_queue addStoredEvent:event];
          }
        }
      });

  SNTEndpointSecurityDataFileAccessAuthorizer *data_faa_client =
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc]
                        initWithESAPI:esapi
                              metrics:metrics
                               logger:logger
                             enricher:enricher
                   faaPolicyProcessor:std::make_shared<santa::DataFAAPolicyProcessorProxy>(
                                          faaPolicyProcessor)
                            ttyWriter:tty_writer
          findPoliciesForTargetsBlock:^(santa::IterateTargetsBlock iterateBlock) {
            watch_items->FindPoliciesForTargets(iterateBlock);
          }];

  watch_items->RegisterDataWatchItemsUpdatedCallback(
      ^(size_t count, const santa::SetPairPathAndType &new_paths,
        const santa::SetPairPathAndType &removed_paths) {
        [data_faa_client watchItemsCount:count newPaths:new_paths removedPaths:removed_paths];
      });

  data_faa_client.fileAccessDeniedBlock = ^(SNTStoredFileAccessEvent *event, NSString *customMsg,
                                            NSString *customURL, NSString *customText) {
    // TODO: The config state should be an argument to the block.
    SNTConfigState *cs = [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];
    [[notifier_queue.notifierConnection remoteObjectProxy]
        postFileAccessBlockNotification:event
                          customMessage:customMsg
                              customURL:customURL
                             customText:customText
                            configState:cs];
  };

  SNTEndpointSecurityProcessFileAccessAuthorizer *proc_faa_client =
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc]
                        initWithESAPI:esapi
                              metrics:metrics
                   faaPolicyProcessor:std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(
                                          faaPolicyProcessor)
          iterateProcessPoliciesBlock:^(santa::CheckPolicyBlock checkPolicyBlock) {
            watch_items->IterateProcessPolicies(checkPolicyBlock);
          }];

  watch_items->RegisterProcWatchItemsUpdatedCallback(^(size_t count) {
    [proc_faa_client processWatchItemsCount:count];
  });

  proc_faa_client.fileAccessDeniedBlock = ^(SNTStoredFileAccessEvent *event, NSString *customMsg,
                                            NSString *customURL, NSString *customText) {
    // TODO: The config state should be an argument to the block.
    SNTConfigState *cs = [[SNTConfigState alloc] initWithConfig:[SNTConfigurator configurator]];
    [[notifier_queue.notifierConnection remoteObjectProxy]
        postFileAccessBlockNotification:event
                          customMessage:customMsg
                              customURL:customURL
                             customText:customText
                            configState:cs];
  };

  [authorizer_client registerAuthExecProbe:proc_faa_client];

  [syncd_queue reassessSyncServiceConnectionImmediately];

  NSMutableArray<SNTKVOManager *> *kvoObservers = [[NSMutableArray alloc] init];
  [kvoObservers addObjectsFromArray:@[
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(clientMode)
                  type:[NSNumber class]
              callback:^(NSNumber *oldValue, NSNumber *newValue) {
                if ([oldValue longLongValue] == [newValue longLongValue]) {
                  // Note: This case apparently can happen and if not checked
                  // will result in excessive notification messages sent to the
                  // user when calling `postClientModeNotification` below
                  return;
                }

                SNTClientMode clientMode = (SNTClientMode)[newValue longLongValue];

                switch (clientMode) {
                  case SNTClientModeLockdown: [[fallthrough]];
                  case SNTClientModeStandalone:
                    LOGI(@"ClientMode changed: %@ -> %@. Flushing caches.",
                         ClientModeName((SNTClientMode)[oldValue integerValue]),
                         ClientModeName((SNTClientMode)[newValue integerValue]));
                    auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                                  FlushCacheReason::kClientModeChanged);
                    break;
                  case SNTClientModeMonitor: [[fallthrough]];
                  default:
                    LOGI(@"ClientMode changed: %@ -> %@",
                         ClientModeName((SNTClientMode)[oldValue integerValue]),
                         ClientModeName((SNTClientMode)[newValue integerValue]));
                    break;
                }

                [[notifier_queue.notifierConnection remoteObjectProxy]
                    postClientModeNotification:clientMode];
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(syncBaseURL)
                  type:[NSURL class]
              callback:^(NSURL *oldValue, NSURL *newValue) {
                if ((!newValue && !oldValue) ||
                    ([newValue.absoluteString isEqualToString:oldValue.absoluteString])) {
                  return;
                }

                LOGI(@"SyncBaseURL changed: %@ -> %@", oldValue, newValue);

                [syncd_queue reassessSyncServiceConnection];
              }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(enableStatsCollection)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   BOOL oldBool = [oldValue boolValue];
                                   BOOL newBool = [newValue boolValue];
                                   if (oldBool != newBool) {
                                     LOGI(@"EnableStatsCollection changed: %d -> %d", oldBool,
                                          newBool);
                                     [syncd_queue reassessSyncServiceConnection];
                                   }
                                 }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(statsOrganizationID)
                  type:[NSString class]
              callback:^(NSString *oldValue, NSString *newValue) {
                if ((!newValue && !oldValue) || ([newValue isEqualToString:oldValue])) {
                  return;
                } else {
                  LOGI(@"StatsOrganizationID changed: %@ -> %@", oldValue, newValue);
                  // If either the new or old value was missing, we must
                  // reassess the connection. If they both exist, it means the
                  // value changed, but the sync service should already be
                  // running and there is nothing to do.
                  if (!oldValue || !newValue) {
                    [syncd_queue reassessSyncServiceConnection];
                  }
                }
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(exportMetrics)
                  type:[NSNumber class]
              callback:^(NSNumber *oldValue, NSNumber *newValue) {
                BOOL oldBool = [oldValue boolValue];
                BOOL newBool = [newValue boolValue];
                if (oldBool == NO && newBool == YES) {
                  LOGI(@"ExportMetrics changed: %d -> %d. Starting to export metrics.", oldBool,
                       newBool);
                  metrics->StartPoll();
                } else if (oldBool == YES && newBool == NO) {
                  LOGI(@"ExportMetrics changed: %d -> %d. Stopping export of metrics", oldBool,
                       newBool);
                  metrics->StopPoll();
                }
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(metricExportInterval)
                  type:[NSNumber class]
              callback:^(NSNumber *oldValue, NSNumber *newValue) {
                uint64_t oldInterval = [oldValue unsignedIntValue];
                uint64_t newInterval = [newValue unsignedIntValue];
                LOGI(@"MetricExportInterval changed: %llu -> %llu. Restarting export.", oldInterval,
                     newInterval);
                metrics->SetInterval(newInterval);
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(allowedPathRegex)
                  type:[NSRegularExpression class]
              callback:^(NSRegularExpression *oldValue, NSRegularExpression *newValue) {
                if ((!newValue && !oldValue) ||
                    ([newValue.pattern isEqualToString:oldValue.pattern])) {
                  return;
                }

                LOGI(@"AllowedPathRegex changed. Flushing caches.");
                auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                              FlushCacheReason::kPathRegexChanged);
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(blockedPathRegex)
                  type:[NSRegularExpression class]
              callback:^(NSRegularExpression *oldValue, NSRegularExpression *newValue) {
                if ((!newValue && !oldValue) ||
                    ([newValue.pattern isEqualToString:oldValue.pattern])) {
                  return;
                }

                LOGI(@"BlockedPathRegex changed. Flushing caches.");
                auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                              FlushCacheReason::kPathRegexChanged);
              }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(blockUSBMount)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   BOOL oldBool = [oldValue boolValue];
                                   BOOL newBool = [newValue boolValue];

                                   if (oldBool == newBool) {
                                     return;
                                   }

                                   LOGI(@"BlockUSBMount changed: %d -> %d", oldBool, newBool);
                                   device_client.blockUSBMount = newBool;
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(remountUSBMode)
                                     type:[NSArray class]
                                 callback:^(NSArray *oldValue, NSArray *newValue) {
                                   if (!oldValue && !newValue) {
                                     return;
                                   }

                                   // Ensure the arrays are composed of strings
                                   for (id element in oldValue) {
                                     if (![element isKindOfClass:[NSString class]]) {
                                       return;
                                     }
                                   }

                                   for (id element in newValue) {
                                     if (![element isKindOfClass:[NSString class]]) {
                                       return;
                                     }
                                   }

                                   if ([oldValue isEqualToArray:newValue]) {
                                     return;
                                   }

                                   LOGI(@"RemountArgs changed: %@ -> %@",
                                        [oldValue componentsJoinedByString:@","],
                                        [newValue componentsJoinedByString:@","]);
                                   device_client.remountArgs = newValue;
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(staticRules)
                                     type:[NSArray class]
                                 callback:^(NSArray *oldValue, NSArray *newValue) {
                                   if ([oldValue isEqualToArray:newValue]) {
                                     return;
                                   }

                                   [exec_controller.ruleTable updateStaticRules:newValue];

                                   LOGI(@"StaticRules changed. Flushing caches.");
                                   auth_result_cache->FlushCache(
                                       FlushCacheMode::kAllCaches,
                                       FlushCacheReason::kStaticRulesChanged);
                                 }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(eventLogType)
                  type:[NSNumber class]
              callback:^(NSNumber *oldValue, NSNumber *newValue) {
                NSInteger oldLogType = [oldValue integerValue];
                NSInteger newLogType = [newValue integerValue];

                if (oldLogType == newLogType) {
                  return;
                }

                LOGW(@"EventLogType config changed: %ld -> %ld. Restarting...", oldLogType,
                     newLogType);

                dispatch_semaphore_t sema = dispatch_semaphore_create(0);

                dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                  logger->Flush();
                  metrics->Export();

                  dispatch_semaphore_signal(sema);
                });

                // Wait for a short amount of time for outstanding data to flush
                dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

                // Forcefully exit. The daemon will be restarted immediately.
                exit(EXIT_SUCCESS);
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(entitlementsTeamIDFilter)
                  type:[NSArray class]
              callback:^(NSArray<NSString *> *oldValue, NSArray<NSString *> *newValue) {
                if ((!oldValue && !newValue) || [oldValue isEqualToArray:newValue]) {
                  return;
                }

                LOGI(@"EntitlementsTeamIDFilter changed: '%@' -> '%@'. Flushing caches.", oldValue,
                     newValue);

                // Get the value from the configurator since it ensures proper types
                entitlements_filter->UpdateTeamIDFilter([configurator entitlementsTeamIDFilter]);

                // Clear the AuthResultCache, then clear the ES cache to ensure
                // future execs get SNTCachedDecision entitlement values filtered
                // with the new settings.
                auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                              FlushCacheReason::kEntitlementsTeamIDFilterChanged);
                [authorizer_client clearCache];
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(entitlementsPrefixFilter)
                  type:[NSArray class]
              callback:^(NSArray<NSString *> *oldValue, NSArray<NSString *> *newValue) {
                if ((!oldValue && !newValue) || [oldValue isEqualToArray:newValue]) {
                  return;
                }

                LOGI(@"EntitlementsPrefixFilter changed: '%@' -> '%@'. Flushing caches.", oldValue,
                     newValue);

                // Get the value from the configurator since it ensures proper types
                entitlements_filter->UpdatePrefixFilter([configurator entitlementsPrefixFilter]);

                // Clear the AuthResultCache, then clear the ES cache to ensure
                // future execs get SNTCachedDecision entitlement values filtered
                // with the new settings.
                auth_result_cache->FlushCache(FlushCacheMode::kAllCaches,
                                              FlushCacheReason::kEntitlementsPrefixFilterChanged);
                [authorizer_client clearCache];
              }],
    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(telemetry)
                  type:[NSArray class]
              callback:^(NSArray *oldValue, NSArray *newValue) {
                if (!oldValue && !newValue) {
                  return;
                }

                // Ensure the new array is composed of strings
                for (id element in newValue) {
                  if (![element isKindOfClass:[NSString class]]) {
                    LOGW(@"Expected type in Telemetry config. Want String. Got: %@: value: %@",
                         [element class], element);
                    return;
                  }
                }

                if ([oldValue isEqualToArray:newValue]) {
                  return;
                }

                LOGI(@"Telemetry changed: %@ -> %@", [oldValue componentsJoinedByString:@","],
                     [newValue componentsJoinedByString:@","]);
                logger->SetTelemetryMask(santa::TelemetryConfigToBitmask(newValue));
              }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(enableSilentTTYMode)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   BOOL oldBool = [oldValue boolValue];
                                   BOOL newBool = [newValue boolValue];

                                   if (oldBool == newBool) {
                                     return;
                                   }

                                   LOGI(@"EnableSilentTTYMode changed: %d -> %d", oldBool, newBool);

                                   tty_writer->EnableSilentTTYMode(newBool);
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(enableMachineIDDecoration)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   BOOL oldBool = [oldValue boolValue];
                                   BOOL newBool = [newValue boolValue];

                                   if (oldBool == newBool) {
                                     return;
                                   }

                                   LOGI(@"EnableMachineIDDecoration changed: %d -> %d", oldBool,
                                        newBool);

                                   logger->UpdateMachineIDLogging();
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(machineID)
                                     type:[NSString class]
                                 callback:^(NSString *oldValue, NSString *newValue) {
                                   if ((!newValue && !oldValue) ||
                                       ([newValue isEqualToString:oldValue])) {
                                     return;
                                   }

                                   LOGI(@"MachineID changed: %@ -> %@", oldValue, newValue);

                                   logger->UpdateMachineIDLogging();
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(enableTelemetryExport)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   BOOL oldBool = [oldValue boolValue];
                                   BOOL newBool = [newValue boolValue];

                                   if (oldBool == newBool) {
                                     return;
                                   }

                                   LOGI(@"EnableTelemetryExport changed: %d -> %d", oldBool,
                                        newBool);

                                   [syncd_queue reassessSyncServiceConnection];

                                   if (newBool) {
                                     LOGW(@"WARNING - Telemetry export is currently in beta. "
                                          @"Configuration and format are subject to change.");
                                     logger->StartTimer();
                                   } else {
                                     logger->StopTimer();
                                   }
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(telemetryExportIntervalSec)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldInterval = [oldValue unsignedIntValue];
                                   uint32_t newInterval = [newValue unsignedIntValue];

                                   if (oldInterval == newInterval) {
                                     return;
                                   }

                                   LOGI(@"TelemetryExportIntervalSec changed: %u -> %u",
                                        oldInterval, newInterval);

                                   logger->SetTimerInterval(newInterval);
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(telemetryExportTimeoutSec)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldInterval = [oldValue unsignedIntValue];
                                   uint32_t newInterval = [newValue unsignedIntValue];

                                   if (oldInterval == newInterval) {
                                     return;
                                   }

                                   LOGI(@"TelemetryExportTimeoutSec changed: %u -> %u", oldInterval,
                                        newInterval);

                                   logger->SetTelmetryExportTimeoutSecs(newInterval);
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(telemetryExportBatchThresholdSizeMB)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldInterval = [oldValue unsignedIntValue];
                                   uint32_t newInterval = [newValue unsignedIntValue];

                                   if (oldInterval == newInterval) {
                                     return;
                                   }

                                   LOGI(@"TelemetryExportBatchThresholdSizeMB changed: %u -> %u",
                                        oldInterval, newInterval);

                                   logger->SetBatchThresholdSizeMB(newInterval);
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(telemetryExportMaxFilesPerBatch)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldInterval = [oldValue unsignedIntValue];
                                   uint32_t newInterval = [newValue unsignedIntValue];

                                   if (oldInterval == newInterval) {
                                     return;
                                   }

                                   LOGI(@"TelemetryExportMaxFilesPerBatch changed: %u -> %u",
                                        oldInterval, newInterval);

                                   logger->SetMaxFilesPerBatch(newInterval);
                                 }],

    [[SNTKVOManager alloc]
        initWithObject:configurator
              selector:@selector(fileAccessPolicyPlist)
                  type:[NSString class]
              callback:^(NSString *oldValue, NSString *newValue) {
                if ((oldValue && !newValue) || (newValue && ![oldValue isEqualToString:newValue])) {
                  if ([configurator fileAccessPolicy]) {
                    LOGI(@"Ignoring change to FileAccessPolicyPlist "
                         @"because FileAccessPolicy is set");
                    return;
                  }

                  if ([[SNTDatabaseController ruleTable] fileAccessRuleCount] > 0) {
                    LOGI(@"Ignoring change to FileAccessPolicyPlist because file "
                         @"access rules exist from the sync server");
                    return;
                  }

                  LOGI(@"FileAccessPolicyPlist changed: %@ -> %@", oldValue, newValue);
                  watch_items->SetConfigPath(newValue);
                }
              }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(fileAccessPolicy)
                                     type:[NSDictionary class]
                                 callback:^(NSDictionary *oldValue, NSDictionary *newValue) {
                                   if ((oldValue && !newValue) ||
                                       (newValue && ![oldValue isEqualToDictionary:newValue])) {
                                     if ([[SNTDatabaseController ruleTable] fileAccessRuleCount] >
                                         0) {
                                       LOGI(@"Ignoring change to FileAccessPolicy because file "
                                            @"access rules exist from the sync server");
                                       return;
                                     }

                                     LOGI(@"FileAccessPolicy changed");
                                     watch_items->SetConfig(newValue);
                                   }
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(fileAccessPolicyUpdateIntervalSec)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldInterval = [oldValue unsignedIntValue];
                                   uint32_t newInterval = [newValue unsignedIntValue];

                                   if (oldInterval == newInterval) {
                                     return;
                                   }

                                   LOGI(@"FileAccessPolicyUpdateIntervalSec changed: %u -> %u",
                                        oldInterval, newInterval);

                                   watch_items->SetTimerInterval(newInterval);
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(fileAccessGlobalLogsPerSec)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldLogPerSec = [oldValue unsignedIntValue];
                                   uint32_t newLogPerSec = [newValue unsignedIntValue];

                                   if ((!oldValue && !newValue) || (oldLogPerSec == newLogPerSec)) {
                                     return;
                                   }

                                   LOGI(@"FileAccessGlobalLogsPerSec changed: %u -> %u",
                                        oldLogPerSec, newLogPerSec);
                                   faaPolicyProcessor->ModifyRateLimiterSettings(
                                       newLogPerSec, configurator.fileAccessGlobalWindowSizeSec);
                                 }],
    [[SNTKVOManager alloc] initWithObject:configurator
                                 selector:@selector(fileAccessGlobalWindowSizeSec)
                                     type:[NSNumber class]
                                 callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                   uint32_t oldWindowSizeSec = [oldValue unsignedIntValue];
                                   uint32_t newWindowSizeSec = [newValue unsignedIntValue];

                                   if ((!oldValue && !newValue) ||
                                       (oldWindowSizeSec == newWindowSizeSec)) {
                                     return;
                                   }

                                   LOGI(@"FileAccessGlobalWindowSizeSec changed: %u -> %u",
                                        oldWindowSizeSec, newWindowSizeSec);
                                   faaPolicyProcessor->ModifyRateLimiterSettings(
                                       configurator.fileAccessGlobalLogsPerSec, newWindowSizeSec);
                                 }],

  ]];

  // Make the compiler happy. The variable is only used to ensure proper lifetime
  // of the SNTKVOManager objects it contains.
  (void)kvoObservers;

  if (process_tree) {
    if (absl::Status status = process_tree->Backfill(); !status.ok()) {
      std::string err = status.ToString();
      LOGE(@"Failed to backfill process tree: %@", @(err.c_str()));
    }
  }

  // IMPORTANT: ES will hold up third party execs until early boot clients make
  // their first subscription. Ensuring the `Authorizer` client is enabled first
  // means that the AUTH EXEC event is subscribed first and Santa can apply
  // execution policy appropriately.
  [authorizer_client enable];

  // Tamper protection is not enabled on debug builds.
#ifndef DEBUG
  [tamper_client enable];
#else
  (void)tamper_client;  // Prevent unused variable issues in debug builds
#endif  // DEBUG

  // Kickoff pre-populating the decision cache. This is done after the Authorizer ES client
  // is enabled to ensure that there is no gap between getting the list of processes to
  // backill and the authorizer handling new execs.
  [[SNTDecisionCache sharedCache]
      backfillDecisionCacheAsyncWithEntitlementsFilter:entitlements_filter];

  // Start monitoring any watched items
  watch_items->StartTimer();

  [monitor_client enable];
  [device_client enable];

  if ([configurator enableTelemetryExport]) {
    // Delay initial start to allow Santa to stabilize
    LOGW(@"WARNING - Telemetry export is currently in beta. Configuration and format are subject "
         @"to change.");
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                     logger->StartTimer();
                   });
  }

  [[NSRunLoop mainRunLoop] run];
}
