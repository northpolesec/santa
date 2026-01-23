/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import "Source/santad/SNTDaemonControlController.h"

#import <Foundation/Foundation.h>

#include <memory>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#include "Source/common/Pinning.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTFileAccessRule.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTTimer.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/common/String.h"
#include "Source/common/faa/WatchItems.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/KillingMachine.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTNetworkExtensionQueue.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#include "Source/santad/TemporaryMonitorMode.h"

using santa::AuthResultCache;
using santa::FlushCacheMode;
using santa::FlushCacheReason;
using santa::Logger;
using santa::WatchItems;
using santa::WatchItemsState;

// Globals used by the santad watchdog thread
uint64_t watchdogCPUEvents = 0;
uint64_t watchdogRAMEvents = 0;
double watchdogCPUPeak = 0;
double watchdogRAMPeak = 0;

@interface SNTDaemonControlController ()
@property SNTNotificationQueue *notQueue;
@property SNTSyncdQueue *syncdQueue;
@property SNTNetworkExtensionQueue *netExtQueue;
@property dispatch_queue_t commandQ;
@end

@implementation SNTDaemonControlController {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
  std::shared_ptr<santa::TemporaryMonitorMode> _temporaryMonitorMode;
}

- (instancetype)initWithAuthResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
                      notificationQueue:(SNTNotificationQueue *)notQueue
                             syncdQueue:(SNTSyncdQueue *)syncdQueue
                      netExtensionQueue:(SNTNetworkExtensionQueue *)netExtQueue
                                 logger:(std::shared_ptr<Logger>)logger
                             watchItems:(std::shared_ptr<WatchItems>)watchItems {
  self = [super init];
  if (self) {
    _logger = logger;
    _authResultCache = authResultCache;
    _watchItems = std::move(watchItems);
    _notQueue = notQueue;
    _syncdQueue = syncdQueue;
    _netExtQueue = netExtQueue;

    _commandQ = dispatch_queue_create("com.northpolesec.santa.cmdq", DISPATCH_QUEUE_SERIAL);
    dispatch_set_target_queue(_commandQ, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0));

    _temporaryMonitorMode = santa::TemporaryMonitorMode::Create(
        [SNTConfigurator configurator], _notQueue,
        ^(SNTStoredTemporaryMonitorModeAuditEvent *auditEvent) {
          [[SNTDatabaseController eventTable] addStoredEvent:auditEvent];
          [syncdQueue addStoredEvent:auditEvent];
        });
  }
  return self;
}

#pragma mark Cache ops

- (void)cacheCounts:(void (^)(uint64_t, uint64_t))reply {
  NSArray<NSNumber *> *counts = self->_authResultCache->CacheCounts();
  reply([counts[0] unsignedLongLongValue], [counts[1] unsignedLongLongValue]);
}

- (void)flushCache:(void (^)(BOOL))reply {
  self->_authResultCache->FlushCache(FlushCacheMode::kAllCaches,
                                     FlushCacheReason::kExplicitCommand);
  reply(YES);
}

- (void)checkCacheForVnodeID:(SantaVnode)vnodeID withReply:(void (^)(SNTAction))reply {
  reply(self->_authResultCache->CheckCache(vnodeID));
}

#pragma mark Database ops

- (void)databaseRuleCounts:(void (^)(RuleCounts ruleTypeCounts))reply {
  SNTRuleTable *rdb = [SNTDatabaseController ruleTable];
  __block RuleCounts ruleCounts{
      .binary = [rdb binaryRuleCount],
      .certificate = [rdb certificateRuleCount],
      .compiler = [rdb compilerRuleCount],
      .transitive = [rdb transitiveRuleCount],
      .teamID = [rdb teamIDRuleCount],
      .signingID = [rdb signingIDRuleCount],
      .cdhash = [rdb cdhashRuleCount],
      .fileAccess = [rdb fileAccessRuleCount],
  };

  // Update counts with data from StaticRules configuration
  [[rdb cachedStaticRules]
      enumerateKeysAndObjectsUsingBlock:^(NSString *key, SNTRule *rule, BOOL *stop) {
        switch (rule.type) {
          case SNTRuleTypeCDHash: ruleCounts.cdhash++; break;
          case SNTRuleTypeBinary: ruleCounts.binary++; break;
          case SNTRuleTypeSigningID: ruleCounts.signingID++; break;
          case SNTRuleTypeCertificate: ruleCounts.certificate++; break;
          case SNTRuleTypeTeamID: ruleCounts.teamID++; break;
          default: break;
        }

        // Note: Transitive rules cannot come from static rules
        switch (rule.state) {
          case SNTRuleStateAllowCompiler: ruleCounts.compiler++; break;
          default: break;
        }
      }];

  reply(ruleCounts);
}

- (void)databaseRuleAddExecutionRules:(NSArray<SNTRule *> *)executionRules
                      fileAccessRules:(NSArray<SNTFileAccessRule *> *)fileAccessRules
                          ruleCleanup:(SNTRuleCleanup)cleanupType
                               source:(SNTRuleAddSource)source
                                reply:(void (^)(BOOL, NSArray<NSError *> *error))reply {
#ifndef DEBUG
  SNTConfigurator *config = [SNTConfigurator configurator];
  if (source == SNTRuleAddSourceSantactl && (config.syncBaseURL || config.staticRules.count > 0)) {
    NSError *error;
    [SNTError populateError:&error
                   withCode:SNTErrorCodeManualRulesDisabled
                    message:@"Rejected by the Santa daemon"
                     detail:@"SyncBaseURL or StaticRules are set"];
    reply(NO, @[ error ]);
    return;
  }
#endif

  SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];

  // If any rules are added that are not plain allowlist rules, then flush decision cache.
  // In particular, the addition of allowlist compiler rules should cause a cache flush.
  // We also flush cache if a allowlist compiler rule is replaced with a allowlist rule.
  BOOL flushCache = ((cleanupType != SNTRuleCleanupNone) || (fileAccessRules.count > 0) ||
                     [ruleTable addedRulesShouldFlushDecisionCache:executionRules]);

  NSArray<NSError *> *errors;
  BOOL success = [ruleTable addExecutionRules:executionRules
                              fileAccessRules:fileAccessRules
                                  ruleCleanup:cleanupType
                                       errors:&errors];

  // Whenever we add rules, we can also check for and remove outdated transitive rules.
  [ruleTable removeOutdatedTransitiveRules];

  // The actual cache flushing happens after the new rules have been added to the database.
  if (flushCache) {
    LOGI(@"Flushing caches");
    self->_authResultCache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);
  }

  reply(success, errors);
}

- (void)databaseEventCount:(void (^)(int64_t count))reply {
  reply([[SNTDatabaseController eventTable] pendingEventsCount]);
}

- (void)databaseEventsPending:(void (^)(NSArray<SNTStoredEvent *> *events))reply {
  reply([[SNTDatabaseController eventTable] pendingEvents]);
}

- (void)databaseRemoveEventsWithIDs:(NSArray *)ids {
  [[SNTDatabaseController eventTable] deleteEventsWithIds:ids];
}

- (void)databaseRuleForIdentifiers:(SNTRuleIdentifiers *)identifiers
                             reply:(void (^)(SNTRule *))reply {
  reply([[SNTDatabaseController ruleTable] executionRuleForIdentifiers:[identifiers toStruct]]);
}

- (void)dataFileAccessRuleForTarget:(NSString *)path reply:(void (^)(NSString *, NSString *))reply {
  __block NSString *ruleName;
  __block NSString *ruleVersion;

  _watchItems->FindPoliciesForTargets(^(santa::LookupPolicyBlock lookup_policy_block) {
    std::optional<std::shared_ptr<santa::WatchItemPolicyBase>> policy =
        lookup_policy_block(path.UTF8String);
    if (policy.has_value()) {
      ruleName = santa::StringToNSString((*policy)->name);
      ruleVersion = santa::StringToNSString((*policy)->version);
    }
  });

  reply(ruleName, ruleVersion);
}

- (void)staticRuleCount:(void (^)(int64_t count))reply {
  reply([SNTConfigurator configurator].staticRules.count);
}

- (void)retrieveAllExecutionRules:(void (^)(NSArray<SNTRule *> *, NSError *))reply {
#ifndef DEBUG
  SNTConfigurator *config = [SNTConfigurator configurator];
  // Do not return any rules if syncBaseURL or static rules are set and return an error.
  if (config.syncBaseURL || config.staticRules.count) {
    NSError *error;
    [SNTError populateError:&error
                   withCode:SNTErrorCodeManualRulesDisabled
                     format:@"SyncBaseURL is set"];
    reply(@[], error);
    return;
  }
#endif

  NSArray<SNTRule *> *rules = [[SNTDatabaseController ruleTable] retrieveAllExecutionRules];
  reply(rules, nil);
}

- (void)retrieveAllFileAccessRules:
    (void (^)(NSDictionary<NSString *, NSDictionary *> *fileAccessRules, NSError *error))reply {
#ifdef DEBUG
  reply([[SNTDatabaseController ruleTable] retrieveAllFileAccessRules], nil);
#else
  NSError *err = [SNTError
      createErrorWithFormat:@"File access rule retrieval not supported in release builds."];
  reply(nil, err);

#endif
}

- (void)databaseRulesHash:(void (^)(NSString *, NSString *))reply {
  SNTRuleTableRulesHash *rulesHash = [[SNTDatabaseController ruleTable] hashOfHashes];
  reply(rulesHash.executionRulesHash, rulesHash.fileAccessRulesHash);
}

#pragma mark Config Ops

- (void)isSyncV2Enabled:(void (^)(BOOL))reply {
  reply([[SNTConfigurator configurator] isSyncV2Enabled]);
}

- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply {
  reply(watchdogCPUEvents, watchdogRAMEvents, watchdogCPUPeak, watchdogRAMPeak);
}

- (void)watchItemsState:(void (^)(BOOL, uint64_t, NSString *,
                                  santa::WatchItems::DataSource dataSource, NSString *,
                                  NSTimeInterval))reply {
  std::optional<WatchItemsState> optionalState = self->_watchItems->State();

  if (!optionalState.has_value()) {
    reply(NO, 0, nil, santa::WatchItems::DataSource::kUnknown, nil, 0);
  } else {
    WatchItemsState state = optionalState.value();

    reply(YES, state.rule_count, state.policy_version, state.data_source, state.config_path,
          state.last_config_load_epoch);
  }
}

- (void)clientMode:(void (^)(SNTClientMode))reply {
  reply([[SNTConfigurator configurator] clientMode]);
}

- (void)fullSyncLastSuccess:(void (^)(NSDate *))reply {
  reply([[SNTConfigurator configurator] fullSyncLastSuccess]);
}

- (void)ruleSyncLastSuccess:(void (^)(NSDate *))reply {
  reply([[SNTConfigurator configurator] ruleSyncLastSuccess]);
}

- (void)syncTypeRequired:(void (^)(SNTSyncType))reply {
  reply([[SNTConfigurator configurator] syncTypeRequired]);
}

- (void)blockUSBMount:(void (^)(BOOL))reply {
  reply([[SNTConfigurator configurator] blockUSBMount]);
}

- (void)remountUSBMode:(void (^)(NSArray<NSString *> *))reply {
  reply([[SNTConfigurator configurator] remountUSBMode]);
}

- (void)blockNetworkMount:(void (^)(NSNumber *))reply {
  // If blocking network mounts is enabled, respond with the number of
  // host exceptions, otherwise nil.
  SNTConfigurator *configurator = [SNTConfigurator configurator];
  reply(configurator.blockNetworkMount ? @(configurator.allowedNetworkMountHosts.count) : nil);
}

- (void)enableBundles:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableBundles);
}

- (void)enableTransitiveRules:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableTransitiveRules);
}

- (void)enableAllEventUpload:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableAllEventUpload);
}

- (void)disableUnknownEventUpload:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].disableUnknownEventUpload);
}

- (void)updateSyncSettings:(SNTConfigBundle *)result reply:(void (^)(void))reply {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  [result clientMode:^(SNTClientMode m) {
    [configurator setSyncServerClientMode:m];
  }];

  [result syncType:^(SNTSyncType val) {
    [configurator setSyncTypeRequired:val];
  }];

  [result allowlistRegex:^(NSString *val) {
    [configurator
        setSyncServerAllowedPathRegex:[NSRegularExpression regularExpressionWithPattern:val
                                                                                options:0
                                                                                  error:NULL]];
  }];

  [result blocklistRegex:^(NSString *val) {
    [configurator
        setSyncServerBlockedPathRegex:[NSRegularExpression regularExpressionWithPattern:val
                                                                                options:0
                                                                                  error:NULL]];
  }];

  [result blockUSBMount:^(BOOL val) {
    [configurator setSyncServerBlockUSBMount:val];
  }];

  [result remountUSBMode:^(NSArray *val) {
    [configurator setRemountUSBMode:val];
  }];

  [result blockNetworkMount:^(BOOL val) {
    [configurator setSyncServerBlockNetworkMount:val];
  }];

  [result bannedNetworkMountBlockMessage:^(NSString *val) {
    [configurator setSyncServerBannedNetworkMountBlockMessage:val];
  }];

  [result allowedNetworkMountHosts:^(NSArray<NSString *> *val) {
    [configurator setSyncServerAllowedNetworkMountHosts:val];
  }];

  [result enableBundles:^(BOOL val) {
    [configurator setEnableBundles:val];
  }];

  [result enableTransitiveRules:^(BOOL val) {
    [configurator setEnableTransitiveRules:val];
  }];

  [result enableAllEventUpload:^(BOOL val) {
    [configurator setEnableAllEventUpload:val];
  }];

  [result disableUnknownEventUpload:^(BOOL val) {
    [configurator setDisableUnknownEventUpload:val];
  }];

  [result overrideFileAccessAction:^(NSString *val) {
    [configurator setSyncServerOverrideFileAccessAction:val];
  }];

  [result exportConfiguration:^(SNTExportConfiguration *val) {
    LOGD(@"Received export configuration: %@", val);
    [configurator setSyncServerExportConfig:val];
  }];

  [result fullSyncLastSuccess:^(NSDate *val) {
    [configurator setFullSyncLastSuccess:val];
  }];

  [result ruleSyncLastSuccess:^(NSDate *val) {
    [configurator setFullSyncLastSuccess:val];
  }];

  [result modeTransition:^(SNTModeTransition *val) {
    // The _temporaryMonitorMode object is responsible for updating configurator as appropriate
    _temporaryMonitorMode->NewModeTransitionReceived(val);
  }];

  [result networkExtensionSettings:^(SNTNetworkExtensionSettings *val) {
    [configurator setSyncServerNetworkExtensionSettings:val];
  }];

  [result eventDetailURL:^(NSString *val) {
    [configurator setSyncServerEventDetailURL:val];
  }];

  [result eventDetailText:^(NSString *val) {
    [configurator setSyncServerEventDetailText:val];
  }];

  reply();
}

- (void)retrieveStatsState:(void (^)(NSDate *, NSString *))reply {
  reply([[SNTConfigurator configurator] lastStatsSubmissionTimestamp],
        [[SNTConfigurator configurator] lastStatsSubmissionVersion]);
}

- (void)saveStatsSubmissionAttemptTime:(NSDate *)timestamp version:(NSString *)version {
  [[SNTConfigurator configurator] saveStatsSubmissionAttemptTime:timestamp version:version];
}

#pragma mark Command Ops

- (void)killProcesses:(SNTKillRequest *)killRequest reply:(void (^)(SNTKillResponse *))reply {
  // Perform work asynchronously to not hold up processing other XPC messages
  dispatch_async(self.commandQ, ^{
    reply(santa::KillingMachine(killRequest));
  });
}

#pragma mark Metrics Ops

- (void)metrics:(void (^)(NSDictionary *))reply {
  SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
  reply([metricSet export]);
}

#pragma mark GUI Ops

- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener {
  // This will leak the underlying NSXPCConnection when "fast user switching" occurs.
  // It is not worth the trouble to fix. Maybe future self will feel differently.
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithListener:listener];
  c.remoteInterface = [SNTXPCNotifierInterface notifierInterface];
  [c resume];
  self.notQueue.notifierConnection = c;
}

#pragma mark syncd Ops

- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply {
  // This message should be handled in a timely manner, santactl status waits for the response.
  // Instead of reusing the existing connection, create a new connection to the sync service.
  // Otherwise, the isFCMListening message would potentially be queued behind various long lived
  // sync operations.
  MOLXPCConnection *conn = [SNTXPCSyncServiceInterface configuredConnection];
  [conn resume];
  [conn.remoteObjectProxy pushNotificationStatus:^(SNTPushNotificationStatus response) {
    reply(response);
  }];
}

- (void)pushNotificationServerAddress:(void (^)(NSString *))reply {
  // This message should be handled in a timely manner, santactl status waits for the response.
  // Instead of reusing the existing connection, create a new connection to the sync service.
  // Otherwise, the message would potentially be queued behind various long lived sync operations.
  MOLXPCConnection *conn = [SNTXPCSyncServiceInterface configuredConnection];
  [conn resume];
  [conn.remoteObjectProxy pushNotificationServerAddress:^(NSString *serverAddress) {
    reply(serverAddress);
  }];
}

- (void)postRuleSyncNotificationForApplication:(NSString *)app reply:(void (^)(void))reply {
  [[self.notQueue.notifierConnection remoteObjectProxy] postRuleSyncNotificationForApplication:app];
  reply();
}

///
///  Used by SantaGUI sync the offending event and potentially all the related events,
///  if the sync server has not seen them before.
///
///  @param event The offending event, fileBundleHash & fileBundleBinaryCount need to be populated.
///  @param events Next bundle events.
///
- (void)syncBundleEvent:(SNTStoredExecutionEvent *)event
          relatedEvents:(NSArray<SNTStoredExecutionEvent *> *)events {
  SNTEventTable *eventTable = [SNTDatabaseController eventTable];

  // Delete the event cached by the execution controller.
  [eventTable deleteEventWithId:event.idx];

  // Add the updated event.
  [eventTable addStoredEvent:event];

  // Log all of the generated bundle events.
  self->_logger->LogBundleHashingEvents(events);

  WEAKIFY(self);

  // Sync the updated event. If the sync server needs the related events, add them to the eventTable
  // and upload them too.
  [self.syncdQueue addBundleEvent:event
                            reply:^(SNTBundleEventAction action) {
                              STRONGIFY(self);
                              switch (action) {
                                case SNTBundleEventActionDropEvents: break;
                                case SNTBundleEventActionStoreEvents:
                                  [eventTable addStoredEvents:events];
                                  break;
                                case SNTBundleEventActionSendEvents:
                                  [eventTable addStoredEvents:events];
                                  [self.syncdQueue
                                      addBundleEvents:events
                                       withBundleHash:events.firstObject.fileBundleHash];
                                  break;
                              }
                            }];
}

#pragma mark Control Ops

- (BOOL)verifyPathIsSanta:(NSString *)path {
  if (path.length == 0) {
    LOGE(@"No path provided");
    return NO;
  }

  BOOL isDir;
  if (![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir] || !isDir) {
    LOGE(@"Installation path is not a directory: %@", path);
    return NO;
  }

  NSError *err;
  MOLCodesignChecker *cc = [[MOLCodesignChecker alloc] initWithBinaryPath:path error:&err];

  if (err) {
    LOGE(@"Failed to validate install path: %@", err);
    return NO;
  }

  if (![cc.teamID isEqualToString:@"ZMCG7MLDV9"] ||
      ![cc.signingID isEqualToString:@"com.northpolesec.santa"]) {
    LOGE(@"Unexpected application: %@:%@", cc.teamID, cc.signingID);
    return NO;
  }

  return YES;
}

- (void)setAppOwnershipAndPermissions:(NSString *)path {
  NSFileManager *fm = [NSFileManager defaultManager];
  NSDirectoryEnumerator<NSURL *> *dirEnumerator = [fm enumeratorAtURL:[NSURL fileURLWithPath:path]
                                           includingPropertiesForKeys:nil
                                                              options:0
                                                         errorHandler:nil];

  NSDictionary<NSFileAttributeKey, id> *attrs = @{
    NSFileOwnerAccountID : @(0),       // root
    NSFileGroupOwnerAccountID : @(0),  // wheel
  };

  void (^SetAttrs)(NSString *) = ^void(NSString *filePath) {
    NSError *error;
    if (![fm setAttributes:attrs ofItemAtPath:filePath error:&error]) {
      LOGW(@"Unable to set ownership: %@: %@", filePath, error);
    }
  };

  for (NSURL *file in dirEnumerator) {
    SetAttrs(file.path);
  }

  SetAttrs(path);
}

- (void)reloadSystemExtension {
  LOGI(@"Trigger SystemExtension activation");
  NSTask *t = [[NSTask alloc] init];
  t.launchPath = [@(kSantaAppPath) stringByAppendingString:@"/Contents/MacOS/Santa"];
  t.arguments = @[ @"--load-system-extension" ];
  [t launch];
}

- (void)installSantaApp:(NSString *)tempPath reply:(void (^)(BOOL))reply {
  LOGI(@"Trigger Santa installation from: %@", tempPath);

  if (![self verifyPathIsSanta:tempPath]) {
    LOGE(@"Unable to verify Santa for installation: %@", tempPath);
    reply(NO);
    return;
  }

  [self setAppOwnershipAndPermissions:tempPath];

  NSString *installPath = @(kSantaAppPath);
  NSFileManager *fm = [NSFileManager defaultManager];
  NSError *error;

  if (![fm removeItemAtPath:installPath error:&error]) {
    LOGE(@"Failed to remove %@: %@", installPath, error);
    reply(NO);
    return;
  }

  if (![fm moveItemAtPath:tempPath toPath:installPath error:&error]) {
    LOGE(@"Failed to remove %@: %@", installPath, error);
    reply(NO);
    return;
  }

  reply(YES);

  [self reloadSystemExtension];
}

- (void)reloadNetworkExtension {
  LOGI(@"Trigger Santa Network Extension (Content Filter) activation");
  NSTask *t = [[NSTask alloc] init];
  t.launchPath = [@(kSantaAppPath) stringByAppendingString:@"/Contents/MacOS/Santa"];
  t.arguments = @[ @"--load-network-extension" ];
  [t launch];
}

- (void)installNetworkExtension:(void (^)(BOOL))reply {
  LOGI(@"Trigger santanetd (network extension) installation");

  // Verify the network extension bundle exists
  NSString *netdBundlePath =
      [@(kSantaAppPath) stringByAppendingString:@"/Contents/Library/SystemExtensions/"
                                                @"com.northpolesec.santa.netd.systemextension"];

  NSFileManager *fm = [NSFileManager defaultManager];
  BOOL isDir;
  if (![fm fileExistsAtPath:netdBundlePath isDirectory:&isDir] || !isDir) {
    LOGE(@"Network extension bundle not found at: %@", netdBundlePath);
    reply(NO);
    return;
  }

  reply(YES);

  [self reloadNetworkExtension];
}

- (void)registerNetworkExtensionWithProtocolVersion:(NSString *)protocolVersion
                                              reply:(void (^)(NSDictionary *settings,
                                                              NSString *santaProtocolVersion,
                                                              NSError *error))reply {
  NSError *error;

  if (![[SNTConfigurator configurator] isSyncV2Enabled]) {
    [SNTError populateError:&error
                   withCode:SNTErrorCodeNetworkExtensionNotAuthorized
                     format:@"Network extension registration is not authorized."];
    reply(nil, nil, error);
    return;
  }

  NSDictionary *settings = [self.netExtQueue handleRegistrationWithProtocolVersion:protocolVersion
                                                                             error:&error];
  reply(settings, kSantaNetworkExtensionProtocolVersion, error);
}

- (void)exportTelemetryWithReply:(void (^)(BOOL))reply {
  _logger->ExportTelemetry();
  reply(YES);
}

- (void)requestTemporaryMonitorModeWithDurationMinutes:(NSNumber *)requestedDuration
                                                 reply:(void (^)(uint32_t, NSError *))reply {
  NSError *err;
  uint32_t duration = _temporaryMonitorMode->RequestMinutes(requestedDuration, &err);
  reply(duration, err);
}

- (void)temporaryMonitorModeSecondsRemaining:(void (^)(NSNumber *))reply {
  std::optional<uint64_t> secsRemaining = _temporaryMonitorMode->SecondsRemaining();
  reply(secsRemaining.has_value() ? @(*secsRemaining) : nil);
}

- (void)cancelTemporaryMonitorMode:(void (^)(NSError *))reply {
  NSError *err;
  if (!_temporaryMonitorMode->Cancel()) {
    err = [SNTError createErrorWithFormat:@"Machine is not currently in temporary Monitor Mode"];
  }
  reply(err);
}

- (void)checkTemporaryMonitorModePolicyAvailable:(void (^)(BOOL))reply {
  reply(_temporaryMonitorMode->Available(nil));
}

@end
