/// Copyright 2022 Google Inc. All rights reserved.
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

@interface SNTDeviceEvent : NSObject <NSSecureCoding>

- (instancetype)initWithOnName:(NSString*)mntonname fromName:(NSString*)mntfromname;

@property NSString* mntonname;
@property NSString* mntfromname;
@property NSArray<NSString*>* remountArgs;
@property BOOL isEncrypted;

// The device's model name, as reported by DiskArbitration.
@property NSString* deviceModel;

// The DiskArbitration media UUID, formatted as a string.
//
// Not a hardware serial number: it is derived from filesystem metadata, so
// it is stable across unmount/remount and mount-path changes for the same
// partition, but is reset if the volume is reformatted. The true USB serial
// number is only reachable via IOKit (kUSBSerialNumberString); we use the
// media UUID instead because it is cheap to obtain from the existing
// DiskArbitration disk description and is "stable enough" for matching the
// same physical media across mount cycles (its intended use as a silence
// key for repeat-block notifications).
@property NSString* mediaUUID;

- (NSString*)readableRemountArgs;

@end
