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

#import "src/common/CoderMacros.h"
#import "src/common/SNTConfigState.h"

@implementation SNTConfigState

- (instancetype)initWithConfig:(SNTConfigurator *)config {
  self = [super init];
  if (self) {
    _clientMode = config.clientMode;
    _enableNotificationSilences = config.enableNotificationSilences;
    _eventDetailText = config.eventDetailText;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, clientMode);
  ENCODE_BOXABLE(coder, enableNotificationSilences);
  ENCODE(coder, eventDetailText);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, clientMode, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, enableNotificationSilences, NSNumber, boolValue);
    DECODE(decoder, eventDetailText, NSString);
  }
  return self;
};

@end
