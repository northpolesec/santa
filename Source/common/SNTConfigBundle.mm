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

@interface SNTConfigBundle ()
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

@end
