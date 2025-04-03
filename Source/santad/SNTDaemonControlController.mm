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

#include <Foundation/Foundation.h>

#include <memory>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTPostflightResult.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
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
  RuleCounts ruleCounts{
      .binary = [rdb binaryRuleCount],
      .certificate = [rdb certificateRuleCount],
      .compiler = [rdb compilerRuleCount],
      .transitive = [rdb transitiveRuleCount],
      .teamID = [rdb teamIDRuleCount],
      .signingID = [rdb signingIDRuleCount],
      .cdhash = [rdb cdhashRuleCount],
  };

  reply(ruleCounts);
}

- (void)databaseRuleAddRules:(NSArray *)rules
                 ruleCleanup:(SNTRuleCleanup)cleanupType
                      source:(SNTRuleAddSource)source
                       reply:(void (^)(NSError *error))reply {
#ifndef DEBUG
  SNTConfigurator *config = [SNTConfigurator configurator];
  if (source == SNTRuleAddSourceSantactl && (config.syncBaseURL || config.staticRules.count > 0)) {
    NSError *error =
        [NSError errorWithDomain:@"com.northpolesec.santad.ruletable"
                            code:42
                        userInfo:@{
                          NSLocalizedDescriptionKey : @"Rejected by the Santa daemon",
                          NSLocalizedFailureReasonErrorKey : @"SyncBaseURL or StaticRules are set",
                        }];
    reply(error);
  }
#endif

  SNTRuleTable *ruleTable = [SNTDatabaseController ruleTable];

  // If any rules are added that are not plain allowlist rules, then flush decision cache.
  // In particular, the addition of allowlist compiler rules should cause a cache flush.
  // We also flush cache if a allowlist compiler rule is replaced with a allowlist rule.
  BOOL flushCache =
      ((cleanupType != SNTRuleCleanupNone) || [ruleTable addedRulesShouldFlushDecisionCache:rules]);

  NSError *error;
  [ruleTable addRules:rules ruleCleanup:cleanupType error:&error];

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

- (void)databaseEventsPending:(void (^)(NSArray *events))reply {
  reply([[SNTDatabaseController eventTable] pendingEvents]);
}

- (void)databaseRemoveEventsWithIDs:(NSArray *)ids {
  [[SNTDatabaseController eventTable] deleteEventsWithIds:ids];
}

- (void)databaseRuleForIdentifiers:(SNTRuleIdentifiers *)identifiers
                             reply:(void (^)(SNTRule *))reply {
  reply([[SNTDatabaseController ruleTable] ruleForIdentifiers:[identifiers toStruct]]);
}

- (void)staticRuleCount:(void (^)(int64_t count))reply {
  reply([SNTConfigurator configurator].staticRules.count);
}

- (void)retrieveAllRules:(void (^)(NSArray<SNTRule *> *, NSError *))reply {
  SNTConfigurator *config = [SNTConfigurator configurator];

  // Do not return any rules if syncBaseURL is set and return an error.
  if (config.syncBaseURL) {
    reply(@[], [NSError errorWithDomain:@"com.northpolesec.santad"
                                   code:403  // (TODO) define error code
                               userInfo:@{NSLocalizedDescriptionKey : @"SyncBaseURL is set"}]);
    return;
  }

  NSArray<SNTRule *> *rules = [[SNTDatabaseController ruleTable] retrieveAllRules];
  reply(rules, nil);
}

#pragma mark Decision Ops

- (void)decisionForFilePath:(NSString *)filePath
                identifiers:(SNTRuleIdentifiers *)identifiers
                      reply:(void (^)(SNTEventState))reply {
  reply([self.policyProcessor decisionForFilePath:filePath identifiers:identifiers].decision);
}

#pragma mark Config Ops

- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply {
  reply(watchdogCPUEvents, watchdogRAMEvents, watchdogCPUPeak, watchdogRAMPeak);
}

- (void)watchItemsState:(void (^)(BOOL, uint64_t, NSString *, NSString *, NSTimeInterval))reply {
  std::optional<WatchItemsState> optionalState = self->_watchItems->State();

  if (!optionalState.has_value()) {
    reply(NO, 0, nil, nil, 0);
  } else {
    WatchItemsState state = optionalState.value();

    reply(YES, state.rule_count, state.policy_version, state.config_path,
          state.last_config_load_epoch);
  }
}

- (void)clientMode:(void (^)(SNTClientMode))reply {
  reply([[SNTConfigurator configurator] clientMode]);
}

- (void)setClientMode:(SNTClientMode)mode reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setSyncServerClientMode:mode];
  reply();
}

- (void)fullSyncLastSuccess:(void (^)(NSDate *))reply {
  reply([[SNTConfigurator configurator] fullSyncLastSuccess]);
}

- (void)setFullSyncLastSuccess:(NSDate *)date reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setFullSyncLastSuccess:date];
  reply();
}

- (void)ruleSyncLastSuccess:(void (^)(NSDate *))reply {
  reply([[SNTConfigurator configurator] ruleSyncLastSuccess]);
}

- (void)setRuleSyncLastSuccess:(NSDate *)date reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setRuleSyncLastSuccess:date];
  reply();
}

- (void)syncTypeRequired:(void (^)(SNTSyncType))reply {
  reply([[SNTConfigurator configurator] syncTypeRequired]);
}

- (void)setSyncTypeRequired:(SNTSyncType)syncType reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setSyncTypeRequired:syncType];
  reply();
}

- (void)setAllowedPathRegex:(NSString *)pattern reply:(void (^)(void))reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setSyncServerAllowedPathRegex:re];
  reply();
}

- (void)setBlockedPathRegex:(NSString *)pattern reply:(void (^)(void))reply {
  NSRegularExpression *re = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                      options:0
                                                                        error:NULL];
  [[SNTConfigurator configurator] setSyncServerBlockedPathRegex:re];
  reply();
}

- (void)blockUSBMount:(void (^)(BOOL))reply {
  reply([[SNTConfigurator configurator] blockUSBMount]);
}

- (void)setBlockUSBMount:(BOOL)enabled reply:(void (^)(void))reply {
  [[SNTConfigurator configurator] setBlockUSBMount:enabled];
  reply();
}

- (void)remountUSBMode:(void (^)(NSArray<NSString *> *))reply {
  reply([[SNTConfigurator configurator] remountUSBMode]);
}

// - (void)setRemountUSBMode:(NSArray *)remountUSBMode reply:(void (^)(void))reply {
//   [[SNTConfigurator configurator] setRemountUSBMode:remountUSBMode];
//   reply();
// }

// - (void)setOverrideFileAccessAction:(NSString *)action reply:(void (^)(void))reply {
//   [[SNTConfigurator configurator] setSyncServerOverrideFileAccessAction:action];
//   reply();
// }

- (void)enableBundles:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableBundles);
}

// - (void)setEnableBundles:(BOOL)enableBundles reply:(void (^)(void))reply {
//   [[SNTConfigurator configurator] setEnableBundles:enableBundles];
//   reply();
// }

- (void)enableTransitiveRules:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableTransitiveRules);
}

// - (void)setEnableTransitiveRules:(BOOL)enabled reply:(void (^)(void))reply {
//   [[SNTConfigurator configurator] setEnableTransitiveRules:enabled];
//   reply();
// }

- (void)enableAllEventUpload:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].enableAllEventUpload);
}

// - (void)setEnableAllEventUpload:(BOOL)enabled reply:(void (^)(void))reply {
//   [[SNTConfigurator configurator] setEnableAllEventUpload:enabled];
//   reply();
// }

- (void)disableUnknownEventUpload:(void (^)(BOOL))reply {
  reply([SNTConfigurator configurator].disableUnknownEventUpload);
}

// - (void)setDisableUnknownEventUpload:(BOOL)enabled reply:(void (^)(void))reply {
//   [[SNTConfigurator configurator] setDisableUnknownEventUpload:enabled];
//   reply();
// }

- (void)postflightResult:(SNTPostflightResult *)result reply:(void (^)(void))reply {
  SNTConfigurator *configurator = [SNTConfigurator configurator];

  [result clientMode:^(SNTClientMode m) {
    LOGE(@"Set config from sync server: clientMode");
    [configurator setSyncServerClientMode:m];
  }];

  [result syncType:^(SNTSyncType val) {
    LOGE(@"Set config from sync server: syncType");
    [configurator setSyncTypeRequired:val];
  }];

  [result allowlistRegex:^(NSString *val) {
  LOGE(@"Set config from sync server: allowRegex");
    [configurator
        setSyncServerAllowedPathRegex:[NSRegularExpression regularExpressionWithPattern:val
                                                                                options:0
                                                                                  error:NULL]];
  }];

  [result blocklistRegex:^(NSString *val) {
  LOGE(@"Set config from sync server: blockRegex");
    [configurator
        setSyncServerBlockedPathRegex:[NSRegularExpression regularExpressionWithPattern:val
                                                                                options:0
                                                                                  error:NULL]];
  }];

  [result blockUSBMount:^(BOOL val) {
    LOGE(@"Set config from sync server: block usb mount");
    [configurator setBlockUSBMount:val];
  }];

  [result remountUSBMode:^(NSArray *val) {
    LOGE(@"Set config from sync server: remount usb mode");
    [configurator setRemountUSBMode:val];
  }];

  [result enableBundles:^(BOOL val) {
    LOGE(@"Set config from sync server: enable bundles");
    [configurator setEnableBundles:val];
  }];

  [result enableTransitiveRules:^(BOOL val) {
    LOGE(@"Set config from sync server: enable transitive rules");
    [configurator setEnableTransitiveRules:val];
  }];

  [result enableAllEventUpload:^(BOOL val) {
    LOGE(@"Set config from sync server: enable all event upload");
    [configurator setEnableAllEventUpload:val];
  }];

  [result disableUnknownEventUpload:^(BOOL val) {
    LOGE(@"Set config from sync server: disable unknown event upload");
    [configurator setDisableUnknownEventUpload:val];
  }];

  [result overrideFileAccessAction:^(NSString *val) {
  LOGE(@"Set config from sync server: override file access");
    [configurator setSyncServerOverrideFileAccessAction:val];
  }];

  [configurator setFullSyncLastSuccess:[NSDate now]];

  // Vacuum the event databases when postflight is
  // complete since it has just been drained.
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
    LOGE(@"Do vacuum");
    [[SNTDatabaseController eventTable] vacuum];
  });

  reply();
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
- (void)syncBundleEvent:(SNTStoredEvent *)event relatedEvents:(NSArray<SNTStoredEvent *> *)events {
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
                                  [self.syncdQueue addEvents:events isFromBundle:YES];
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

@end
