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

#import "Source/common/SNTConfigBundle.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"

@interface SNTConfigBundle ()
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
@property NSNumber *enableNotificationSilences;
@property SNTSyncNetworkExtensionSettings *networkExtensionSettings;
@property NSArray<NSString *> *pushTokenChain;
@property NSArray<NSString *> *telemetryFilterExpressions;
@end

@implementation SNTConfigBundle

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, clientMode);
  ENCODE(coder, syncType);
  ENCODE(coder, allowlistRegex);
  ENCODE(coder, blocklistRegex);
  ENCODE(coder, blockUSBMount);
  ENCODE(coder, remountUSBMode);
  ENCODE(coder, blockNetworkMount);
  ENCODE(coder, bannedNetworkMountBlockMessage);
  ENCODE(coder, allowedNetworkMountHosts);
  ENCODE(coder, enableBundles);
  ENCODE(coder, enableTransitiveRules);
  ENCODE(coder, enableAllEventUpload);
  ENCODE(coder, disableUnknownEventUpload);
  ENCODE(coder, overrideFileAccessAction);
  ENCODE(coder, exportConfiguration);
  ENCODE(coder, fullSyncLastSuccess);
  ENCODE(coder, ruleSyncLastSuccess);
  ENCODE(coder, modeTransition);
  ENCODE(coder, eventDetailURL);
  ENCODE(coder, eventDetailText);
  ENCODE(coder, fileAccessEventDetailURL);
  ENCODE(coder, fileAccessEventDetailText);
  ENCODE(coder, enableNotificationSilences);
  ENCODE(coder, networkExtensionSettings);
  ENCODE(coder, pushTokenChain);
  ENCODE(coder, telemetryFilterExpressions);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, clientMode, NSNumber);
    DECODE(decoder, syncType, NSNumber);
    DECODE(decoder, allowlistRegex, NSString);
    DECODE(decoder, blocklistRegex, NSString);
    DECODE(decoder, blockUSBMount, NSNumber);
    DECODE_ARRAY(decoder, remountUSBMode, NSString);
    DECODE(decoder, blockNetworkMount, NSNumber);
    DECODE(decoder, bannedNetworkMountBlockMessage, NSString);
    DECODE_ARRAY(decoder, allowedNetworkMountHosts, NSString);
    DECODE(decoder, enableBundles, NSNumber);
    DECODE(decoder, enableTransitiveRules, NSNumber);
    DECODE(decoder, enableAllEventUpload, NSNumber);
    DECODE(decoder, disableUnknownEventUpload, NSNumber);
    DECODE(decoder, overrideFileAccessAction, NSString);
    DECODE(decoder, exportConfiguration, SNTExportConfiguration);
    DECODE(decoder, fullSyncLastSuccess, NSDate);
    DECODE(decoder, ruleSyncLastSuccess, NSDate);
    DECODE(decoder, modeTransition, SNTModeTransition);
    DECODE(decoder, eventDetailURL, NSString);
    DECODE(decoder, eventDetailText, NSString);
    DECODE(decoder, fileAccessEventDetailURL, NSString);
    DECODE(decoder, fileAccessEventDetailText, NSString);
    DECODE(decoder, enableNotificationSilences, NSNumber);
    DECODE(decoder, networkExtensionSettings, SNTSyncNetworkExtensionSettings);
    DECODE_ARRAY(decoder, pushTokenChain, NSString);
    DECODE_ARRAY(decoder, telemetryFilterExpressions, NSString);
  }
  return self;
}

- (void)clientMode:(void (^)(SNTClientMode))block {
  if (self.clientMode) {
    block((SNTClientMode)[self.clientMode integerValue]);
  }
}

- (void)syncType:(void (^)(SNTSyncType))block {
  if (self.syncType) {
    block((SNTSyncType)[self.syncType integerValue]);
  }
}

- (void)allowlistRegex:(void (^)(NSString *))block {
  if (self.allowlistRegex) {
    block(self.allowlistRegex);
  }
}

- (void)blocklistRegex:(void (^)(NSString *))block {
  if (self.blocklistRegex) {
    block(self.blocklistRegex);
  }
}

- (void)blockUSBMount:(void (^)(BOOL))block {
  if (self.blockUSBMount) {
    block([self.blockUSBMount boolValue]);
  }
}

- (void)remountUSBMode:(void (^)(NSArray *))block {
  if (self.remountUSBMode) {
    block(self.remountUSBMode);
  }
}

- (void)blockNetworkMount:(void (^)(BOOL))block {
  if (self.blockNetworkMount) {
    block([self.blockNetworkMount boolValue]);
  }
}

- (void)bannedNetworkMountBlockMessage:(void (^)(NSString *))block {
  if (self.bannedNetworkMountBlockMessage) {
    block(self.bannedNetworkMountBlockMessage);
  }
}

- (void)allowedNetworkMountHosts:(void (^)(NSArray<NSString *> *))block {
  if (self.allowedNetworkMountHosts) {
    block(self.allowedNetworkMountHosts);
  }
}

- (void)enableBundles:(void (^)(BOOL))block {
  if (self.enableBundles) {
    block([self.enableBundles boolValue]);
  }
}

- (void)enableTransitiveRules:(void (^)(BOOL))block {
  if (self.enableTransitiveRules) {
    block([self.enableTransitiveRules boolValue]);
  }
}

- (void)enableAllEventUpload:(void (^)(BOOL))block {
  if (self.enableAllEventUpload) {
    block([self.enableAllEventUpload boolValue]);
  }
}

- (void)disableUnknownEventUpload:(void (^)(BOOL))block {
  if (self.disableUnknownEventUpload) {
    block([self.disableUnknownEventUpload boolValue]);
  }
}

- (void)overrideFileAccessAction:(void (^)(NSString *))block {
  if (self.overrideFileAccessAction) {
    block(self.overrideFileAccessAction);
  }
}

- (void)exportConfiguration:(void (^)(SNTExportConfiguration *))block {
  if (self.exportConfiguration) {
    block(self.exportConfiguration);
  }
}

- (void)fullSyncLastSuccess:(void (^)(NSDate *))block {
  if (self.fullSyncLastSuccess) {
    block(self.fullSyncLastSuccess);
  }
}
- (void)ruleSyncLastSuccess:(void (^)(NSDate *))block {
  if (self.ruleSyncLastSuccess) {
    block(self.ruleSyncLastSuccess);
  }
}

- (void)modeTransition:(void (^)(SNTModeTransition *))block {
  if (self.modeTransition) {
    block(self.modeTransition);
  }
}

- (void)eventDetailURL:(void (^)(NSString *))block {
  if (self.eventDetailURL) {
    block(self.eventDetailURL);
  }
}

- (void)eventDetailText:(void (^)(NSString *))block {
  if (self.eventDetailText) {
    block(self.eventDetailText);
  }
}

- (void)fileAccessEventDetailURL:(void (^)(NSString *))block {
  if (self.fileAccessEventDetailURL) {
    block(self.fileAccessEventDetailURL);
  }
}

- (void)fileAccessEventDetailText:(void (^)(NSString *))block {
  if (self.fileAccessEventDetailText) {
    block(self.fileAccessEventDetailText);
  }
}

- (void)enableNotificationSilences:(void (^)(BOOL))block {
  if (self.enableNotificationSilences) {
    block([self.enableNotificationSilences boolValue]);
  }
}

- (void)networkExtensionSettings:(void (^)(SNTSyncNetworkExtensionSettings *))block {
  if (self.networkExtensionSettings) {
    block(self.networkExtensionSettings);
  }
}

- (void)pushTokenChain:(void (^)(NSArray<NSString *> *))block {
  if (self.pushTokenChain) {
    block(self.pushTokenChain);
  }
}

- (void)telemetryFilterExpressions:(void (^)(NSArray<NSString *> *))block {
  if (self.telemetryFilterExpressions) {
    block(self.telemetryFilterExpressions);
  }
}

@end
