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

#import "Source/common/SNTStoredNetworkMountEvent.h"

#include "Source/common/CoderMacros.h"

@implementation SNTStoredNetworkMountEvent

- (instancetype)init {
  self = [super init];
  if (self) {
    _process = [[SNTProcessChain alloc] init];
  }
  return self;
}
+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, mountFromName);
  ENCODE(coder, mountOnName);
  ENCODE(coder, fsType);
  ENCODE(coder, process);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, mountFromName, NSString);
    DECODE(decoder, mountOnName, NSString);
    DECODE(decoder, fsType, NSString);
    DECODE(decoder, process, SNTProcessChain);
  }
  return self;
}

- (NSString *)uniqueID {
  // Dedupe on URL / mountFromName
  return [NSString stringWithFormat:@"%@", self.mountFromName];
}

- (BOOL)unactionableEvent {
  // OK to be part of the backoff cache
  return YES;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"SNTStoredNetworkMountEvent[%@]: %@, By: %@", self.idx,
                                    self.mountFromName, self.process];
}

@end
