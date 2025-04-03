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

#import "Source/common/SNTPostflightResult.h"

#import "Source/santasyncservice/SNTSyncState.h"
#import "Source/common/CoderMacros.h"

@interface SNTPostflightResult ()
@property NSNumber *clientMode;
@property NSNumber *syncType;
@property NSString *allowlistRegex;
@property NSString *blocklistRegex;
@property NSNumber *blockUSBMount;
@property NSArray *remountUSBMode;
@property NSNumber *enableBundles;
@property NSNumber *enableTransitiveRules;
@property NSNumber *enableAllEventUpload;
@property NSNumber *disableUnknownEventUpload;
@property NSString *overrideFileAccessAction;
@end

@implementation SNTPostflightResult

- (instancetype)initWithSyncState:(SNTSyncState *)syncState {
  self = [super init];
  if (self) {
    _clientMode = syncState.clientMode ? @(syncState.clientMode) : nil;
    _syncType = syncState.syncType != SNTSyncTypeNormal ? @(SNTSyncTypeNormal) : nil;

    _allowlistRegex = syncState.allowlistRegex;
    _blocklistRegex = syncState.blocklistRegex;
    _blockUSBMount = syncState.blockUSBMount;
    _remountUSBMode = syncState.remountUSBMode;
    _enableBundles = syncState.enableBundles;
    _enableTransitiveRules = syncState.enableTransitiveRules;
    _enableAllEventUpload = syncState.enableAllEventUpload;
    _disableUnknownEventUpload = syncState.disableUnknownEventUpload;
    _overrideFileAccessAction = syncState.overrideFileAccessAction;
  }
  return self;
}

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
  ENCODE(coder, enableBundles);
  ENCODE(coder, enableTransitiveRules);
  ENCODE(coder, enableAllEventUpload);
  ENCODE(coder, disableUnknownEventUpload);
  ENCODE(coder, overrideFileAccessAction);
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
    DECODE(decoder, enableBundles, NSNumber);
    DECODE(decoder, enableTransitiveRules, NSNumber);
    DECODE(decoder, enableAllEventUpload, NSNumber);
    DECODE(decoder, disableUnknownEventUpload, NSNumber);
    DECODE(decoder, overrideFileAccessAction, NSString);
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

- (void)enableBundles:(void (^)(BOOL))block {
  if (self.enableBundles) {
    block(self.enableBundles);
  }
}

- (void)enableTransitiveRules:(void (^)(BOOL))block {
  if (self.enableTransitiveRules) {
    block(self.enableTransitiveRules);
  }
}

- (void)enableAllEventUpload:(void (^)(BOOL))block {
  if (self.enableAllEventUpload) {
    block(self.enableAllEventUpload);
  }
}

- (void)disableUnknownEventUpload:(void (^)(BOOL))block {
  if (self.disableUnknownEventUpload) {
    block(self.disableUnknownEventUpload);
  }
}

- (void)overrideFileAccessAction:(void (^)(NSString *))block {
  if (self.overrideFileAccessAction) {
    block(self.overrideFileAccessAction);
  }
}

@end
