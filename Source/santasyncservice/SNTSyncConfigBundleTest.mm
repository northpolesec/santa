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

#import "Source/santasyncservice/SNTSyncConfigBundle.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigBundle.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"
#import "Source/santasyncservice/SNTSyncState.h"

@interface SNTConfigBundle (ConfigBundleCreator)
@property NSNumber *clientMode;
@property NSNumber *syncType;
@property NSString *allowlistRegex;
@property NSString *blocklistRegex;
@property NSNumber *blockUSBMount;
@property NSArray *remountUSBMode;
@property NSNumber *blockNetworkMount;
@property NSString *bannedNetworkMountBlockMessage;
@property NSArray<NSString *> *allowedNetworkMountHosts;
@property NSNumber *enableBundles;
@property NSNumber *enableTransitiveRules;
@property NSNumber *enableAllEventUpload;
@property NSNumber *disableUnknownEventUpload;
@property NSString *overrideFileAccessAction;
@property SNTExportConfiguration *exportConfiguration;
@property NSDate *fullSyncLastSuccess;
@property NSDate *ruleSyncLastSuccess;
@property SNTModeTransition *modeTransition;
@property NSString *eventDetailURL;
@property NSString *eventDetailText;
@property NSString *fileAccessEventDetailURL;
@property NSString *fileAccessEventDetailText;
@property SNTSyncNetworkExtensionSettings *networkExtensionSettings;
@property NSArray<NSString *> *pushTokenChain;
@property NSArray<NSString *> *telemetryFilterExpressions;
@end

@interface SNTSyncConfigBundleTest : XCTestCase
@end

@implementation SNTSyncConfigBundleTest

- (void)testPreflightConfigBundle {
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushIssuerJWT = @"issuerToken";
  syncState.pushJWT = @"userToken";

  SNTConfigBundle *bundle = PreflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.pushTokenChain, (@[ @"issuerToken", @"userToken" ]));

  XCTAssertNil(bundle.clientMode);
  XCTAssertNil(bundle.syncType);
  XCTAssertNil(bundle.allowlistRegex);
  XCTAssertNil(bundle.blocklistRegex);
  XCTAssertNil(bundle.blockUSBMount);
  XCTAssertNil(bundle.remountUSBMode);
  XCTAssertNil(bundle.blockNetworkMount);
  XCTAssertNil(bundle.bannedNetworkMountBlockMessage);
  XCTAssertNil(bundle.allowedNetworkMountHosts);
  XCTAssertNil(bundle.enableBundles);
  XCTAssertNil(bundle.enableTransitiveRules);
  XCTAssertNil(bundle.enableAllEventUpload);
  XCTAssertNil(bundle.disableUnknownEventUpload);
  XCTAssertNil(bundle.overrideFileAccessAction);
  XCTAssertNil(bundle.exportConfiguration);
  XCTAssertNil(bundle.fullSyncLastSuccess);
  XCTAssertNil(bundle.ruleSyncLastSuccess);
  XCTAssertNil(bundle.modeTransition);
  XCTAssertNil(bundle.eventDetailURL);
  XCTAssertNil(bundle.eventDetailText);
  XCTAssertNil(bundle.networkExtensionSettings);
  XCTAssertNil(bundle.telemetryFilterExpressions);
}

- (void)testPostflightConfigBundle {
  SNTConfigBundle *bundle;
  SNTSyncState *syncState = [[SNTSyncState alloc] init];

  syncState.clientMode = SNTClientModeUnknown;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertNil(bundle.clientMode);

  syncState.clientMode = SNTClientModeMonitor;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.clientMode, @(SNTClientModeMonitor));

  syncState.syncType = SNTSyncTypeNormal;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertNil(bundle.syncType);

  syncState.syncType = SNTSyncTypeClean;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeNormal));

  syncState.syncType = SNTSyncTypeCleanAll;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeNormal));

  syncState.modeTransition = [[SNTModeTransition alloc] initRevocation];
  bundle = PostflightConfigBundle(syncState);
  XCTAssertNotNil(bundle.modeTransition);
  XCTAssertEqual(bundle.modeTransition.type, SNTModeTransitionTypeRevoke);

  syncState.eventDetailURL = @"my://url";
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.eventDetailURL, syncState.eventDetailURL);

  syncState.eventDetailText = @"Click Button";
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.eventDetailText, syncState.eventDetailText);

  syncState.fileAccessEventDetailURL = @"my://faa-url";
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.fileAccessEventDetailURL, syncState.fileAccessEventDetailURL);

  syncState.fileAccessEventDetailText = @"View FAA Details";
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.fileAccessEventDetailText, syncState.fileAccessEventDetailText);

  syncState.blockNetworkMount = @(YES);
  syncState.bannedNetworkMountBlockMessage = @"banban";
  syncState.allowedNetworkMountHosts = @[ @"0.0.0.0", @"localhost" ];
  bundle = PostflightConfigBundle(syncState);
  XCTAssertTrue([bundle.blockNetworkMount boolValue]);
  XCTAssertEqualObjects(bundle.bannedNetworkMountBlockMessage,
                        syncState.bannedNetworkMountBlockMessage);
  XCTAssertEqualObjects(bundle.allowedNetworkMountHosts, syncState.allowedNetworkMountHosts);

  syncState.networkExtensionSettings = [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES];
  bundle = PostflightConfigBundle(syncState);
  XCTAssertNotNil(bundle.networkExtensionSettings);
  XCTAssertTrue(bundle.networkExtensionSettings.enable);

  syncState.telemetryFilterExpressions = @[ @"expr1", @"expr2" ];
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.telemetryFilterExpressions, syncState.telemetryFilterExpressions);
}

- (void)testRuleSyncConfigBundle {
  NSDate *curTime = [NSDate now];
  SNTConfigBundle *bundle = RuleSyncConfigBundle();
  XCTAssertGreaterThanOrEqual([bundle.ruleSyncLastSuccess timeIntervalSince1970],
                              [curTime timeIntervalSince1970]);

  XCTAssertNil(bundle.clientMode);
  XCTAssertNil(bundle.syncType);
  XCTAssertNil(bundle.allowlistRegex);
  XCTAssertNil(bundle.blocklistRegex);
  XCTAssertNil(bundle.blockUSBMount);
  XCTAssertNil(bundle.remountUSBMode);
  XCTAssertNil(bundle.blockNetworkMount);
  XCTAssertNil(bundle.bannedNetworkMountBlockMessage);
  XCTAssertNil(bundle.allowedNetworkMountHosts);
  XCTAssertNil(bundle.enableBundles);
  XCTAssertNil(bundle.enableTransitiveRules);
  XCTAssertNil(bundle.enableAllEventUpload);
  XCTAssertNil(bundle.disableUnknownEventUpload);
  XCTAssertNil(bundle.overrideFileAccessAction);
  XCTAssertNil(bundle.exportConfiguration);
  XCTAssertNil(bundle.fullSyncLastSuccess);
  XCTAssertNil(bundle.modeTransition);
  XCTAssertNil(bundle.eventDetailURL);
  XCTAssertNil(bundle.eventDetailText);
  XCTAssertNil(bundle.fileAccessEventDetailURL);
  XCTAssertNil(bundle.fileAccessEventDetailText);
  XCTAssertNil(bundle.networkExtensionSettings);
  XCTAssertNil(bundle.pushTokenChain);
  XCTAssertNil(bundle.telemetryFilterExpressions);
}

- (void)testSyncTypeConfigBundle {
  SNTConfigBundle *bundle;

  bundle = SyncTypeConfigBundle(SNTSyncTypeNormal);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeNormal));

  bundle = SyncTypeConfigBundle(SNTSyncTypeCleanAll);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeCleanAll));

  bundle = SyncTypeConfigBundle(SNTSyncTypeClean);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeClean));

  XCTAssertNil(bundle.clientMode);
  XCTAssertNil(bundle.allowlistRegex);
  XCTAssertNil(bundle.blocklistRegex);
  XCTAssertNil(bundle.blockUSBMount);
  XCTAssertNil(bundle.remountUSBMode);
  XCTAssertNil(bundle.blockNetworkMount);
  XCTAssertNil(bundle.bannedNetworkMountBlockMessage);
  XCTAssertNil(bundle.allowedNetworkMountHosts);
  XCTAssertNil(bundle.enableBundles);
  XCTAssertNil(bundle.enableTransitiveRules);
  XCTAssertNil(bundle.enableAllEventUpload);
  XCTAssertNil(bundle.disableUnknownEventUpload);
  XCTAssertNil(bundle.overrideFileAccessAction);
  XCTAssertNil(bundle.exportConfiguration);
  XCTAssertNil(bundle.fullSyncLastSuccess);
  XCTAssertNil(bundle.ruleSyncLastSuccess);
  XCTAssertNil(bundle.modeTransition);
  XCTAssertNil(bundle.eventDetailURL);
  XCTAssertNil(bundle.eventDetailText);
  XCTAssertNil(bundle.fileAccessEventDetailURL);
  XCTAssertNil(bundle.fileAccessEventDetailText);
  XCTAssertNil(bundle.networkExtensionSettings);
  XCTAssertNil(bundle.pushTokenChain);
  XCTAssertNil(bundle.telemetryFilterExpressions);
}

@end
