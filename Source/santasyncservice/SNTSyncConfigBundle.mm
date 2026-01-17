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

#import <Foundation/Foundation.h>

#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"
#import "Source/santasyncservice/SNTSyncConfigBundle.h"

// Expose necessary setters for SNTConfigBundle properties related to Postflight
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
@property SNTNetworkExtensionSettings *networkExtensionSettings;
@end

SNTConfigBundle *PostflightConfigBundle(SNTSyncState *syncState) {
  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];

  bundle.clientMode = syncState.clientMode ? @(syncState.clientMode) : nil;
  bundle.syncType = syncState.syncType != SNTSyncTypeNormal ? @(SNTSyncTypeNormal) : nil;
  bundle.allowlistRegex = syncState.allowlistRegex;
  bundle.blocklistRegex = syncState.blocklistRegex;
  bundle.blockUSBMount = syncState.blockUSBMount;
  bundle.remountUSBMode = syncState.remountUSBMode;
  bundle.blockNetworkMount = syncState.blockNetworkMount;
  bundle.bannedNetworkMountBlockMessage = syncState.bannedNetworkMountBlockMessage;
  bundle.allowedNetworkMountHosts = syncState.allowedNetworkMountHosts;
  bundle.enableBundles = syncState.enableBundles;
  bundle.enableTransitiveRules = syncState.enableTransitiveRules;
  bundle.enableAllEventUpload = syncState.enableAllEventUpload;
  bundle.disableUnknownEventUpload = syncState.disableUnknownEventUpload;
  bundle.overrideFileAccessAction = syncState.overrideFileAccessAction;
  bundle.exportConfiguration = syncState.exportConfig;
  bundle.modeTransition = syncState.modeTransition;
  bundle.eventDetailURL = syncState.eventDetailURL;
  bundle.eventDetailText = syncState.eventDetailText;
  bundle.networkExtensionSettings = syncState.networkExtensionSettings;

  bundle.fullSyncLastSuccess = [NSDate now];

  return bundle;
}

SNTConfigBundle *RuleSyncConfigBundle() {
  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];

  bundle.ruleSyncLastSuccess = [NSDate now];

  return bundle;
}

SNTConfigBundle *SyncTypeConfigBundle(SNTSyncType syncType) {
  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];

  bundle.syncType = @(syncType);

  return bundle;
}
