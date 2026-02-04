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

#import "Source/common/SNTStoredUSBMountEvent.h"

#include <Foundation/Foundation.h>

#import "Source/common/CoderMacros.h"

@implementation SNTStoredUSBMountEvent

- (instancetype)initWithDeviceModel:(NSString *)deviceModel
                       deviceVendor:(NSString *)deviceVendor
                        mountOnName:(NSString *)mountOnName {
  self = [super init];
  if (self) {
    _uuid = [[NSUUID UUID] UUIDString];
    _deviceModel = deviceModel;
    _deviceVendor = deviceVendor;
    _mountOnName = mountOnName;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, uuid);
  ENCODE(coder, deviceModel);
  ENCODE(coder, deviceVendor);
  ENCODE(coder, mountOnName);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, uuid, NSString);
    DECODE(decoder, deviceModel, NSString);
    DECODE(decoder, deviceVendor, NSString);
    DECODE(decoder, mountOnName, NSString);
  }
  return self;
}

- (NSString *)description {
  return [NSString stringWithFormat:@"SNTStoredUSBMountEvent[%@]: %@ %@ on: %@", self.idx,
                                    self.deviceVendor, self.deviceModel, self.mountOnName];
}

- (BOOL)unactionableEvent {
  return YES;
}

- (NSString *)uniqueID {
  // Dedupe on URL / mountOnName
  return [NSString stringWithFormat:@"%@", self.mountOnName];
}

@end
