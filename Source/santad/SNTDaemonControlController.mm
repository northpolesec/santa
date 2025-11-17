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
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTFileAccessRule.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTTimer.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/common/faa/WatchItems.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTPolicyProcessor.h"
#import "Source/santad/SNTSyncdQueue.h"

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
@property SNTPolicyProcessor *policyProcessor;
@property SNTNotificationQueue *notQueue;
@property SNTSyncdQueue *syncdQueue;
@property SNTTimer *tempMonitorMode;
@end

@implementation SNTDaemonControlController {
  std::shared_ptr<AuthResultCache> _authResultCache;
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
}

- (instancetype)initWithAuthResultCache:(std::shared_ptr<AuthResultCache>)authResultCache
                      notificationQueue:(SNTNotificationQueue *)notQueue
                             syncdQueue:(SNTSyncdQueue *)syncdQueue
                                 logger:(std::shared_ptr<Logger>)logger
                             watchItems:(std::shared_ptr<WatchItems>)watchItems {
  self = [super init];
  if (self) {
    _logger = logger;
    _policyProcessor =
        [[SNTPolicyProcessor alloc] initWithRuleTable:[SNTDatabaseController ruleTable]];
    _authResultCache = authResultCache;
    _watchItems = std::move(watchItems);
    _notQueue = notQueue;
    _syncdQueue = syncdQueue;

    _tempMonitorMode =
        [[SNTTimer alloc] initWithMinInterval:kMinTemporaryMonitorModeMinutes * 60
                                  maxInterval:kMaxTemporaryMonitorModeMinutes * 60
                                         name:@"Temporary Monitor Mode"
                                  fireOnStart:NO
                               rescheduleMode:SNTTimerRescheduleModeTrailingEdge
                                     qosClass:QOS_CLASS_USER_INITIATED
                                     callback:^bool {
                                       [[SNTConfigurator configurator] leaveTemporaryMonitorMode];

                                       // Don't restart the timer
                                       return false;
                                     }];

    [self enterTemporaryMonitorModeOnInitIfRequired];
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
                                reply:(void (^)(NSError *error))reply {
#ifndef DEBUG
  SNTConfigurator *config = [SNTConfigurator configurator];
  if (source == SNTRuleAddSourceSantactl && (config.syncBaseURL || config.staticRules.count > 0)) {
    NSError *error;
    [SNTError populateError:&error
                   withCode:SNTErrorCodeManualRulesDisabled
                    message:@"Rejected by the Santa daemon"
                     detail:@"SyncBaseURL or StaticRules are set"];
    reply(error);
    return;
  }
#endif

  SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];

  // If any rules are added that are not plain allowlist rules, then flush decision cache.
  // In particular, the addition of allowlist compiler rules should cause a cache flush.
  // We also flush cache if a allowlist compiler rule is replaced with a allowlist rule.
  BOOL flushCache = ((cleanupType != SNTRuleCleanupNone) || (fileAccessRules.count > 0) ||
                     [ruleTable addedRulesShouldFlushDecisionCache:executionRules]);

  NSError *error;
  [ruleTable addExecutionRules:executionRules
               fileAccessRules:fileAccessRules
                   ruleCleanup:cleanupType
                         error:&error];

  // Whenever we add rules, we can also check for and remove outdated transitive rules.
  [ruleTable removeOutdatedTransitiveRules];

  // The actual cache flushing happens after the new rules have been added to the database.
  if (flushCache) {
    LOGI(@"Flushing caches");
    self->_authResultCache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);
  }

  reply(error);
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

- (void)databaseRulesHash:(void (^)(NSString *, NSString *))reply {
  SNTRuleTableRulesHash *rulesHash = [[SNTDatabaseController ruleTable] hashOfHashes];
  reply(rulesHash.executionRulesHash, rulesHash.fileAccessRulesHash);
}

#pragma mark Config Ops

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
    [configurator setBlockUSBMount:val];
  }];

  [result remountUSBMode:^(NSArray *val) {
    [configurator setRemountUSBMode:val];
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
    if (val.type == SNTModeTransitionTypeRevoke) {
      if (self.tempMonitorMode.isStarted) {
        [self.tempMonitorMode stop];
        [[SNTConfigurator configurator] leaveTemporaryMonitorMode];
      }
    }
    [configurator setSyncServerModeTransition:val];
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

- (void)requestAPNSToken:(void (^)(NSString *))reply {
  // Simply forward request to the active GUI (if any).
  [self.notQueue.notifierConnection.remoteObjectProxy requestAPNSToken:reply];
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

- (void)exportTelemetryWithReply:(void (^)(BOOL))reply {
  _logger->ExportTelemetry();
  reply(YES);
}

- (void)enterTemporaryMonitorModeOnInitIfRequired {
  // Require at least 30 seconds left of Monitor Mode, otherwise don't bother.
  static constexpr uint64_t kMinRemainingSeconds = 30;
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  uint32_t secsRemaining =
      [[configurator temporaryMonitorModeStateSecondsRemaining] unsignedIntValue];

  if (secsRemaining < kMinRemainingSeconds) {
    // Let configurator do any necessary cleanup
    [configurator leaveTemporaryMonitorMode];
    return;
  }

  [self.tempMonitorMode startWithInterval:secsRemaining];
  [configurator enterTemporaryMonitorModeForSeconds:secsRemaining];
}

- (void)requestTemporaryMonitorModeWithDuration:(NSNumber *)requestedDuration
                                          reply:(void (^)(uint32_t, NSError *))reply {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  SNTModeTransition *modeTransition = [configurator modeTransition];
  if (modeTransition.type != SNTModeTransitionTypeOnDemand) {
    reply(0,
          [SNTError createErrorWithFormat:@"Machine is not eligible for temporary Monitor Mode"]);
    return;
  }

  SNTClientMode clientMode = [configurator clientMode];
  if (!(clientMode == SNTClientModeLockdown ||
        (clientMode == SNTClientModeMonitor && [configurator inTemporaryMonitorMode]))) {
    reply(0, [SNTError createErrorWithFormat:@"Machine must be in Lockdown Mode in order to "
                                             @"transition to temporary Monitor Mode"]);
    return;
  }

  __block BOOL authSuccess = NO;
  [self.notQueue authorizeTemporaryMonitorMode:^(BOOL authenticated) {
    authSuccess = authenticated;
  }];

  if (!authSuccess) {
    reply(0, [SNTError createErrorWithFormat:@"User authorization failed"]);
    return;
  }

  uint32_t durationMin = [modeTransition getDurationMinutes:requestedDuration];

  [self.tempMonitorMode startWithInterval:(durationMin * 60)];
  [configurator enterTemporaryMonitorModeForSeconds:(durationMin * 60)];

  reply(durationMin, nil);
}

- (void)temporaryMonitorModeSecondsRemaining:(void (^)(NSNumber *))reply {
  reply([[SNTConfigurator configurator] temporaryMonitorModeStateSecondsRemaining]);
}

- (void)cancelTemporaryMonitorMode:(void (^)(NSError *))reply {
  SNTConfigurator *configurator = [SNTConfigurator configurator];
  NSError *err;

  if ([configurator inTemporaryMonitorMode]) {
    [self.tempMonitorMode stop];
    [configurator leaveTemporaryMonitorMode];
  } else {
    err = [SNTError createErrorWithFormat:@"Machine is not currently in temporary Monitor Mode"];
  }

  reply(err);
}

@end
