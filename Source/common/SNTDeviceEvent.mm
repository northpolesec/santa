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

#import "Source/common/SNTDeviceEvent.h"

#import "Source/common/CoderMacros.h"

@implementation SNTDeviceEvent

- (instancetype)initWithOnName:(NSString *)mntonname fromName:(NSString *)mntfromname {
  self = [super init];
  if (self) {
    _mntonname = mntonname;
    _mntfromname = mntfromname;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE(coder, mntonname);
  ENCODE(coder, mntfromname);
  ENCODE(coder, remountArgs);
  ENCODE_BOXABLE(coder, isEncrypted);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE(decoder, mntonname, NSString);
    DECODE(decoder, mntfromname, NSString);
    DECODE_ARRAY(decoder, remountArgs, NSString);
    DECODE_SELECTOR(decoder, isEncrypted, NSNumber, boolValue);
  }
  return self;
}
- (NSString *)description {
  return [NSString stringWithFormat:@"SNTDeviceEvent '%@' -> '%@' (with permissions: [%@]",
                                    self.mntfromname, self.mntonname,
                                    [self.remountArgs componentsJoinedByString:@", "]];
}

- (NSString *)readableRemountArgs {
  NSMutableArray<NSString *> *readable = [NSMutableArray array];
  for (NSString *arg in self.remountArgs) {
    if ([arg isEqualToString:@"rdonly"]) {
      [readable addObject:@"read-only"];
    } else if ([arg isEqualToString:@"noexec"]) {
      [readable addObject:@"block executables"];
    } else {
      [readable addObject:arg];
    }
  }
  return [readable componentsJoinedByString:@", "];
}

@end
