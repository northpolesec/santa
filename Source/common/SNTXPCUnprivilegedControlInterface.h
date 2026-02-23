/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#import "Source/common/MOLCertificate.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SantaVnode.h"
#import "Source/common/faa/WatchItems.h"

@class SNTRule;
@class SNTStoredExecutionEvent;
@class MOLXPCConnection;

struct RuleCounts {
  int64_t binary;
  int64_t certificate;
  int64_t compiler;
  int64_t transitive;
  int64_t teamID;
  int64_t signingID;
  int64_t cdhash;
  int64_t fileAccess;
};

///
///  Protocol implemented by santad and utilized by santactl (unprivileged operations)
///
@protocol SNTUnprivilegedDaemonControlXPC

///
///  Cache Ops
///
- (void)cacheCounts:(void (^)(uint64_t rootCache, uint64_t nonRootCache))reply;
- (void)checkCacheForVnodeID:(SantaVnode)vnodeID withReply:(void (^)(SNTAction))reply;

///
///  Database ops
///
- (void)databaseRuleCounts:(void (^)(struct RuleCounts ruleCounts))reply;
- (void)databaseEventCount:(void (^)(int64_t count))reply;
- (void)staticRuleCount:(void (^)(int64_t count))reply;
- (void)databaseRulesHash:(void (^)(NSString *executionRulesHash,
                                    NSString *fileAccessRulesHash))reply;
- (void)databaseRuleForIdentifiers:(SNTRuleIdentifiers *)identifiers
                             reply:(void (^)(SNTRule *))reply;

///
///  Config ops
///
- (void)isSyncV2Enabled:(void (^)(BOOL))reply;
- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply;
- (void)watchItemsState:(void (^)(BOOL, uint64_t, NSString *,
                                  santa::WatchItems::DataSource dataSource, NSString *,
                                  NSTimeInterval))reply;
- (void)clientMode:(void (^)(SNTClientMode))reply;
- (void)fullSyncLastSuccess:(void (^)(NSDate *))reply;
- (void)ruleSyncLastSuccess:(void (^)(NSDate *))reply;
- (void)syncTypeRequired:(void (^)(SNTSyncType))reply;
- (void)enableBundles:(void (^)(BOOL))reply;
- (void)enableTransitiveRules:(void (^)(BOOL))reply;
- (void)blockUSBMount:(void (^)(BOOL))reply;
- (void)remountUSBMode:(void (^)(NSArray<NSString *> *))reply;
- (void)blockNetworkMount:(void (^)(NSNumber *))reply;

///
/// FAA Retrieval ops
///
- (void)dataFileAccessRuleForTarget:(NSString *)path reply:(void (^)(NSString *, NSString *))reply;

///
/// Metrics ops
///
- (void)metrics:(void (^)(NSDictionary *))reply;

///
///  GUI Ops
///
- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener;

///
///  Syncd Ops
///
- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply;
- (void)pushNotificationServerAddress:(void (^)(NSString *))reply;

///
///  Bundle Ops
///
- (void)syncBundleEvent:(SNTStoredExecutionEvent *)event
          relatedEvents:(NSArray<SNTStoredExecutionEvent *> *)events;

///
///  Telemetry Ops
///
- (void)exportTelemetryWithReply:(void (^)(BOOL))reply;

///
/// Temporary Monitor Mode Ops
///
- (void)requestTemporaryMonitorModeWithDurationMinutes:(NSNumber *)requestedDuration
                                                 reply:(void (^)(uint32_t, NSError *))reply;
- (void)cancelTemporaryMonitorMode:(void (^)(NSError *))reply;
- (void)temporaryMonitorModeSecondsRemaining:(void (^)(NSNumber *))reply;
- (void)checkTemporaryMonitorModePolicyAvailable:(void (^)(BOOL))reply;

///
/// Network Extension Ops
///
/// Returns whether the network extension should be installed.
- (void)shouldInstallNetworkExtension:(void (^)(BOOL))reply;
/// Returns the desired enabled state for the network extension content filter.
/// Returns NO if no settings have been synced yet.
- (void)networkExtensionEnabled:(void (^)(BOOL enabled))reply;
/// Returns bundle version info from the loaded network extension, or nil if not connected.
- (void)networkExtensionLoadedBundleVersionInfo:(void (^)(NSDictionary *bundleInfo))reply;
/// Returns whether the network extension is currently loaded and connected.
- (void)networkExtensionLoaded:(void (^)(BOOL loaded))reply;

@end

@interface SNTXPCUnprivilegedControlInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTUnprivilegedDaemonControlXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)controlInterface;

///
///  Internal method used to initialize the control interface
///
+ (void)initializeControlInterface:(NSXPCInterface *)r;

@end
