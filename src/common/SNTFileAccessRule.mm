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

#include "src/common/SNTFileAccessRule.h"

#import "src/common/CoderMacros.h"

@implementation SNTFileAccessRule

- (instancetype)initWithStates:(SNTFileAccessRuleState)state
                          name:(NSString *)name
                       details:(NSDictionary *)details {
  if (state != SNTFileAccessRuleStateAdd && state != SNTFileAccessRuleStateRemove) {
    return nil;
  }

  if (!name) {
    return nil;
  }

  self = [super init];
  if (self) {
    _state = state;
    _name = name;

    if (details) {
      NSData *detailsData = [NSKeyedArchiver archivedDataWithRootObject:details
                                                  requiringSecureCoding:YES
                                                                  error:nil];
      if (!detailsData) {
        return nil;
      }

      _details = detailsData;
    }
  }
  return self;
}
- (instancetype)initAddRuleWithName:(NSString *)name details:(NSDictionary *)details {
  if (!details) {
    return nil;
  }
  return [self initWithStates:SNTFileAccessRuleStateAdd name:name details:details];
}

- (instancetype)initRemoveRuleWithName:(NSString *)name {
  return [self initWithStates:SNTFileAccessRuleStateRemove name:name details:nil];
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
