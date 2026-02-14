/// Copyright 2026 North Pole Security, Inc.
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

/// Helper class for FIDO2 hardware security key authorization.
@interface SNTFido2Helper : NSObject

/// Check if any FIDO2 device is currently connected.
+ (BOOL)isFido2DeviceAvailable;

/// Authorize an action using a FIDO2 security key.
/// The user will be prompted to touch their security key.
/// @param reason Localized reason string displayed to the user.
/// @param replyBlock Called on completion with success status and whether a device was found.
///        When deviceWasFound is YES, the caller should not fall back to other auth methods.
+ (void)authorizeWithReason:(NSString*)reason
                 replyBlock:(void (^)(BOOL success, BOOL deviceWasFound))replyBlock;

@end
