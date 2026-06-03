/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/santad/SNTNetworkExtensionQueue.h"

#import <Foundation/Foundation.h>

#include <utility>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTNetworkFlowRule.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/ne/SNDXPCNetworkExtensionInterface.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"
#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"
#import "Source/common/ne/SNTXPCNetworkExtensionInterface.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#import "src/santanetd/SNDProcessFlows.h"

NSString* const kSantaNetworkExtensionProtocolVersion = @"1.0";

@interface SNTNetworkExtensionQueue () {
  std::shared_ptr<santa::Logger> _logger;
}
@property MOLXPCConnection* netExtConnection;
@property(readwrite) NSString* connectedProtocolVersion;
@property NSArray<SNTKVOManager*>* kvoWatchers;
@property(weak) SNTNotificationQueue* notifierQueue;
@property(weak) SNTSyncdQueue* syncdQueue;
@property SNTRuleTable* ruleTable;
// What santanetd was last told. Reset when the connection drops so a fresh santanetd
// (which persists nothing) is re-seeded with the full config on its next registration.
@property SNTNetworkExtensionSettings* lastPushedSettings;
@property NSString* lastPushedNetworkFlowRulesHash;
@end

@implementation SNTNetworkExtensionQueue

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                           syncdQueue:(SNTSyncdQueue*)syncdQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                               logger:(std::shared_ptr<santa::Logger>)logger {
  self = [super init];
  if (self) {
    _notifierQueue = notifierQueue;
    _syncdQueue = syncdQueue;
    _ruleTable = ruleTable;
    _logger = std::move(logger);

    WEAKIFY(self);

    // Sync-path settings changes reach santanetd via the postflight marker reconcile in
    // SNTDaemonControlController.updateSyncSettings:, so we don't observe
    // syncNetworkExtensionSettings directly — that would double-fire and race with the
    // marker reconcile. The only non-sync mutation is the syncBaseURL-driven revoke below,
    // which clears settings and triggers a reconcile explicitly.
    _kvoWatchers = @[
      [[SNTKVOManager alloc]
          initWithObject:[SNTConfigurator configurator]
                selector:@selector(syncBaseURL)
                    type:[NSURL class]
                callback:^(NSURL* oldValue, NSURL* newValue) {
                  if ((!newValue && !oldValue) ||
                      ([newValue.absoluteString isEqualToString:oldValue.absoluteString])) {
                    return;
                  }

                  // Always clear settings, but only log a message if settings previously existed.
                  if ([[SNTConfigurator configurator] syncNetworkExtensionSettings]) {
                    LOGI(@"Network Extension settings revoked due to SyncBaseURL changing.");
                  }

                  [[SNTConfigurator configurator] setSyncServerSyncNetworkExtensionSettings:nil];

                  STRONGIFY(self);
                  [self reconcileNetworkExtensionConfig];
                }],
    ];
  }
  return self;
}

- (void)reconcileNetworkExtensionConfig {
  // Serialize the read-compare-dispatch-update sequence so concurrent triggers (e.g. the
  // postflight marker on the controller's XPC thread vs. the syncBaseURL revoke on the
  // configurator's KVO thread) don't see stale lastPushed and emit duplicate pushes.
  @synchronized(self) {
    MOLXPCConnection* conn = self.netExtConnection;
    if (!conn) {
      // santanetd isn't connected; it will be re-seeded in full when it next registers.
      return;
    }

    SNTNetworkExtensionSettings* settings =
        [self generateSettingsForProtocolVersion:self.connectedProtocolVersion];
    if (!settings) {
      LOGW(@"Failed to generate settings for protocol version %@", self.connectedProtocolVersion);
      return;
    }

    // Fast-path hash check: cheap (cached) and avoids materializing the ruleset when nothing
    // changed. Uses the narrow network-flow getter rather than hashOfHashes so we don't
    // recompute the execution + file-access digests we don't need here.
    NSString* currentHash = [self.ruleTable networkFlowRulesHash];
    BOOL settingsChanged = ![settings isEqual:self.lastPushedSettings];
    BOOL rulesChanged = ![currentHash isEqualToString:self.lastPushedNetworkFlowRulesHash];
    if (!settingsChanged && !rulesChanged) {
      return;
    }

    // When rules changed, take an atomic snapshot so the array and the hash we record both
    // correspond to the same DB state (a concurrent sync could commit between the fast-path
    // read above and the materialization below). `nil` rules means "rules unchanged" to
    // santanetd, so settings-only changes skip the snapshot allocation entirely.
    NSArray<SNTNetworkFlowRule*>* rules = nil;
    NSString* hashToRecord = currentHash;
    if (rulesChanged) {
      SNTNetworkFlowRulesSnapshot* snapshot = [self.ruleTable retrieveAllNetworkFlowRulesSnapshot];
      rules = snapshot.rules;
      hashToRecord = snapshot.networkFlowRulesHash;
    }
    // The wire object carries the scalar settings plus the rules delta (nil rules == "unchanged").
    // lastPushedSettings stays the scalar `settings` object below; networkFlowRules is excluded
    // from -isEqual:/-hash so it never perturbs the settings delta, and the rules delta is tracked
    // separately via lastPushedNetworkFlowRulesHash.
    SNTNetworkExtensionSettings* wireSettings =
        [settings settingsByAttachingNetworkFlowRules:rules];

    // Record lastPushed only on a successful reply, so a netd-side rejection leaves our
    // recorded state matching netd's actual state and the next reconcile retries. The reply
    // block fires asynchronously off this lock, so it re-enters @synchronized for the write;
    // WEAKIFY/STRONGIFY breaks the transient self <-> connection <-> reply-block cycle.
    WEAKIFY(self);
    [(id<SNDNetworkExtensionXPC>)[conn remoteObjectProxy]
        updateNetworkExtensionSettings:wireSettings
                                 reply:^(BOOL success) {
                                   if (!success) {
                                     LOGW(@"Failed to update network extension settings");
                                     return;
                                   }
                                   STRONGIFY(self);
                                   @synchronized(self) {
                                     self.lastPushedSettings = settings;
                                     self.lastPushedNetworkFlowRulesHash = hashToRecord;
                                   }
                                 }];
  }
}

- (void)handleNetworkFlows:(NSArray<SNDProcessFlows*>*)processFlows
               windowStart:(NSDate*)windowStart
                 windowEnd:(NSDate*)windowEnd {
  if (![self shouldInstallNetworkExtension] || !processFlows.count) {
    return;
  }

  NSTimeInterval startSecs = windowStart.timeIntervalSince1970;
  NSTimeInterval endSecs = windowEnd.timeIntervalSince1970;
  struct timespec windowStartTS = {
      .tv_sec = static_cast<time_t>(startSecs),
      .tv_nsec = static_cast<long>((startSecs - static_cast<time_t>(startSecs)) * NSEC_PER_SEC),
  };
  struct timespec windowEndTS = {
      .tv_sec = static_cast<time_t>(endSecs),
      .tv_nsec = static_cast<long>((endSecs - static_cast<time_t>(endSecs)) * NSEC_PER_SEC),
  };

  for (SNDProcessFlows* pf in processFlows) {
    _logger->LogNetworkFlows(pf, windowStartTS, windowEndTS);
  }
}

- (SNTNetworkExtensionSettings*)handleRegistrationWithProtocolVersion:(NSString*)protocolVersion
                                                                error:(NSError**)error {
  if (self.netExtConnection) {
    LOGW(@"Network extension attempting to register but already connected, clearing stale "
         @"connection");
    // Clear the existing connection since it may be stale
    [self clearNetworkExtensionConnection];
  }

  if (protocolVersion.length == 0) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeNetworkExtensionProtocolVersionInvalid
                    message:@"Invalid protocol version"
                     detail:@"Protocol version cannot be nil or empty"];
    return nil;
  }

  // Validate protocol version matches "major.minor" format
  NSString* pattern = @"^\\d+\\.\\d+$";
  NSRegularExpression* regex = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                         options:0
                                                                           error:nil];
  NSRange range = NSMakeRange(0, protocolVersion.length);
  NSTextCheckingResult* match = [regex firstMatchInString:protocolVersion options:0 range:range];

  if (!match) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeNetworkExtensionProtocolVersionInvalid
                    message:@"Invalid protocol version format"
                     detail:[NSString stringWithFormat:@"Protocol version must be in 'major.minor' "
                                                       @"format (e.g., '1.0'), received: '%@'",
                                                       protocolVersion]];
    return nil;
  }

  // Extract the major version now that it has been validated.
  // Note: Minor version not currently used
  auto [majorVersion, _] = [self protocolVersionComponents:protocolVersion];

  if (majorVersion < 1) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeNetworkExtensionProtocolVersionBad
                    message:@"Unsupported protocol version"
                     detail:[NSString stringWithFormat:@"Unsupported protocol version '%@'",
                                                       protocolVersion]];
    return nil;
  }

  // At this point we've successfully validated the client. Store important information
  // and go ahead and establish a connection back to the network extension daemon (used for
  // runtime config updates after registration).
  //
  // Same monitor as reconcileNetworkExtensionConfig: a concurrent reconcile must not see a
  // half-set-up state (connection established but lastPushed not yet recorded), which would
  // emit a redundant push of the values we're about to seed in the reply.
  @synchronized(self) {
    self.connectedProtocolVersion = protocolVersion;
    [self establishNetworkExtensionConnection];

    // santanetd persists nothing, so a registration means it just (re)started empty. Seed it
    // with the full current settings + ruleset in the registration reply (returned here),
    // letting it apply both atomically. The snapshot reads rules + hash in one DB transaction
    // so a concurrent sync can't desync what we put in the reply from what we record as
    // last-pushed.
    SNTNetworkExtensionSettings* settings =
        [self generateSettingsForProtocolVersion:self.connectedProtocolVersion];
    SNTNetworkFlowRulesSnapshot* snapshot = [self.ruleTable retrieveAllNetworkFlowRulesSnapshot];
    self.lastPushedSettings = settings;
    self.lastPushedNetworkFlowRulesHash = snapshot.networkFlowRulesHash;

    // The reply carries the scalar settings plus the full ruleset in networkFlowRules. We keep
    // lastPushedSettings as the scalar `settings`; since networkFlowRules is excluded from
    // -isEqual:, the rules-bearing wire object still compares equal to it.
    return [settings settingsByAttachingNetworkFlowRules:snapshot.rules];
  }
}

- (void)establishNetworkExtensionConnection {
  LOGI(@"Establishing connection to network extension");

  WEAKIFY(self);

  MOLXPCConnection* conn = [SNTXPCNetworkExtensionInterface configuredConnection];
  conn.invalidationHandler = ^{
    STRONGIFY(self);
    LOGI(@"Network extension connection invalidated, clearing state");
    [self clearNetworkExtensionConnection];
  };
  [conn resume];

  self.netExtConnection = conn;
}

- (void)clearNetworkExtensionConnection {
  // Holds the same monitor as reconcileNetworkExtensionConfig so the {connection, lastPushed}
  // pair stays consistent — reconcile never sees a non-nil connection paired with
  // already-cleared lastPushed (or vice versa).
  @synchronized(self) {
    self.netExtConnection.invalidationHandler = nil;
    [self.netExtConnection invalidate];
    self.netExtConnection = nil;
    self.connectedProtocolVersion = nil;
    // Forget what we told the old santanetd; the next one starts empty and must be re-seeded.
    self.lastPushedSettings = nil;
    self.lastPushedNetworkFlowRulesHash = nil;
  }
}

- (std::pair<int, int>)protocolVersionComponents:(NSString*)protocolVersion {
  NSArray<NSString*>* components = [protocolVersion componentsSeparatedByString:@"."];
  return std::make_pair<int, int>([components[0] intValue], [components[1] intValue]);
}

- (BOOL)shouldInstallNetworkExtension {
  SNTConfigurator* configurator = [SNTConfigurator configurator];
  return [configurator isSyncV2Enabled] && [configurator syncNetworkExtensionSettings].enable;
}

- (void)networkExtensionBundleVersionInfo:(void (^)(NSDictionary* bundleInfo))reply {
  if (!self.netExtConnection) {
    reply(nil);
    return;
  }

  [[self.netExtConnection remoteObjectProxy] bundleVersionInfo:^(NSDictionary* bundleInfo) {
    reply(bundleInfo);
  }];
}

- (BOOL)isLoaded {
  return self.netExtConnection != nil;
}

- (BOOL)networkExtensionNeedsUpgrade {
  if (!self.netExtConnection) {
    LOGD(@"Network extension not connected, needs install");
    return YES;
  }

  // Read the on-disk version first. If unreadable, skip install (nothing to install).
  SNTFileInfo* onDiskInfo = [[SNTFileInfo alloc] initWithPath:@(kSantaNetdPath)];
  NSString* onDiskVersion = [onDiskInfo bundleVersion];
  if (!onDiskVersion) {
    LOGD(@"Unable to read on-disk network extension version, skipping install");
    return NO;
  }

  __block NSString* loadedVersion;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [self networkExtensionBundleVersionInfo:^(NSDictionary* bundleInfo) {
    loadedVersion = bundleInfo[@"CFBundleVersion"];
    dispatch_semaphore_signal(sema);
  }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    LOGW(@"Timeout querying loaded network extension version, assuming upgrade needed");
    return YES;
  }

  if (!loadedVersion) {
    LOGD(@"Unable to determine loaded network extension version, needs upgrade");
    return YES;
  }

  if ([loadedVersion isEqualToString:onDiskVersion]) {
    LOGD(@"Network extension version matches (%@), skipping install", loadedVersion);
    return NO;
  }

  LOGD(@"Network extension version mismatch (loaded: %@, on-disk: %@), needs upgrade",
       loadedVersion, onDiskVersion);
  return YES;
}

- (SNTNetworkExtensionSettings*)generateSettingsForProtocolVersion:(NSString*)protocolVersion {
  if (!protocolVersion) {
    return nil;
  }

  auto [majorVersion, _] = [self protocolVersionComponents:protocolVersion];
  SNTSyncNetworkExtensionSettings* syncSettings =
      [[SNTConfigurator configurator] syncNetworkExtensionSettings];

  BOOL enable = NO;
  SNTNetworkFlowDefaultAction flowDefaultAction = SNTNetworkFlowDefaultActionUnspecified;
  NSTimeInterval dnsUpstreamTimeoutSecs = 0;

  if (majorVersion >= 1) {
    enable = syncSettings.enable;
    flowDefaultAction = syncSettings.flowDefaultAction;
    dnsUpstreamTimeoutSecs = syncSettings.dnsUpstreamTimeoutSecs;
  }

  return [[SNTNetworkExtensionSettings alloc] initWithEnable:enable
                                           flowDefaultAction:flowDefaultAction
                                      dnsUpstreamTimeoutSecs:dnsUpstreamTimeoutSecs];
}

@end
