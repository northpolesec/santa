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

#include "Source/common/SNTFileAccessRule.h"

#import "Source/common/CoderMacros.h"

@implementation SNTFileAccessRule

- (instancetype)initWithState:(SNTFileAccessRuleState)state {
  if (state != SNTFileAccessRuleStateAdd && state != SNTFileAccessRuleStateRemove) {
    return nil;
  }

  self = [super init];
  if (self) {
    _state = state;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, state);
  ENCODE(coder, name);
  ENCODE(coder, details);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, state, NSNumber, intValue);
    DECODE(decoder, name, NSString);
    DECODE(decoder, details, NSData);
  }
  return self;
}

@end
