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

#import <Foundation/Foundation.h>

#import "Source/common/SNTStoredEvent.h"

// The decision matrix for USB mount events
typedef NS_ENUM(NSInteger, SNTStoredUSBMountEventDecision) {
  SNTStoredUSBMountEventDecisionBlocked,
  SNTStoredUSBMountEventDecisionAllowedWithRemount,
};

/// Represents a USB Mount Event
@interface SNTStoredUSBMountEvent : SNTStoredEvent <NSSecureCoding>

/// The UUID of the event
@property(readonly) NSString *uuid;

/// The Device Model string as reported by DiskArbitration framework
@property(readonly) NSString *deviceModel;

/// The Device Vendor string as reported by DiskArbitration framework
@property(readonly) NSString *deviceVendor;

/// The mount on path
@property(readonly) NSString *mountOnName;

/// The protocol string as reported by DiskArbitration framework
@property(readonly) NSString *protocol;

/// The remount flags
@property(readonly) NSArray<NSString *> *remountArgs;

/// The decision on whether the mount was blocked, or allowed with remount
@property(readonly) SNTStoredUSBMountEventDecision decision;

- (instancetype)initWithDeviceModel:(NSString *)deviceModel
                       deviceVendor:(NSString *)deviceVendor
                        mountOnName:(NSString *)mountOnName
                           protocol:(NSString *)protocol
                           decision:(SNTStoredUSBMountEventDecision)decision
                        remountArgs:(NSArray<NSString *> *)remountArgs;

@end
