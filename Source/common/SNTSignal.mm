/// Copyright 2026 North Pole Security, Inc.
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

#import "Source/common/SNTSignal.h"

#import "Source/common/CoderMacros.h"

@implementation SNTSignal

- (instancetype)initWithState:(SNTSignalState)state name:(NSString*)name data:(NSData*)data {
  if (state != SNTSignalStateAdd && state != SNTSignalStateRemove) {
    return nil;
  }
  if (!name) {
    return nil;
  }
  self = [super init];
  if (self) {
    _state = state;
    _name = [name copy];
    _data = [data copy];
  }
  return self;
}

- (instancetype)initAddRuleWithName:(NSString*)name data:(NSData*)data {
  if (!data) {
    return nil;
  }
  return [self initWithState:SNTSignalStateAdd name:name data:data];
}

- (instancetype)initRemoveRuleWithName:(NSString*)name {
  return [self initWithState:SNTSignalStateRemove name:name data:nil];
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, state);
  ENCODE(coder, name);
  ENCODE(coder, data);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, state, NSNumber, intValue);
    DECODE(decoder, name, NSString);
    DECODE(decoder, data, NSData);
    // Maintain the same invariant as the designated initializers: the state must be a valid
    // add/remove, a name is always required, and an add rule must carry data.
    if ((_state != SNTSignalStateAdd && _state != SNTSignalStateRemove) || !_name ||
        (_state == SNTSignalStateAdd && !_data)) {
      return nil;
    }
  }
  return self;
}

@end
