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

#import <Foundation/Foundation.h>

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTExecAuthConfigState.h"

@implementation SNTExecAuthConfigState

- (instancetype)initWithConfig:(SNTConfigurator *)config {
  self = [super init];
  if (self) {
    _clientMode = config.clientMode;
    _disableUnknownEventUpload = config.disableUnknownEventUpload;
    _dismissText = config.dismissText;
    _enableAllEventUpload = config.enableAllEventUpload;
    _enableBundles = config.enableBundles;
    _eventDetailText = config.eventDetailText;
    _eventDetailURL = config.eventDetailURL;
    _failClosed = config.failClosed;
    _syncBaseURL = config.syncBaseURL;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, clientMode);
  ENCODE_BOXABLE(coder, disableUnknownEventUpload);
  ENCODE(coder, dismissText);
  ENCODE_BOXABLE(coder, enableAllEventUpload);
  ENCODE_BOXABLE(coder, enableBundles);
  ENCODE(coder, eventDetailText);
  ENCODE(coder, eventDetailURL);
  ENCODE_BOXABLE(coder, failClosed);
  ENCODE(coder, syncBaseURL);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, clientMode, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, disableUnknownEventUpload, NSNumber, boolValue);
    DECODE(decoder, dismissText, NSString);
    DECODE_SELECTOR(decoder, enableAllEventUpload, NSNumber, boolValue);
    DECODE_SELECTOR(decoder, enableBundles, NSNumber, boolValue);
    DECODE(decoder, eventDetailText, NSString);
    DECODE(decoder, eventDetailURL, NSString);
    DECODE_SELECTOR(decoder, failClosed, NSNumber, boolValue);
    DECODE(decoder, syncBaseURL, NSURL);
  }
  return self;
};

@end
