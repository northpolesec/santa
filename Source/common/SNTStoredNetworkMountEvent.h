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

#import <Foundation/Foundation.h>

#import "Source/common/SNTProcessChain.h"
#import "Source/common/SNTStoredEvent.h"

@interface SNTStoredNetworkMountEvent : SNTStoredEvent <NSSecureCoding>

@property NSString *uuid;
@property NSString *mountFromName;
@property NSString *mountOnName;
@property NSString *fsType;

@property SNTProcessChain *process;

// Returns a sanitized version of mountFromName with both username and password removed.
// If mountFromName is not a valid URL or contains no credentials, returns the original string.
//
// Example: "//admin:password@192.168.64.2:445/share" -> "//192.168.64.2:445/share"
- (NSString *)sanitizedMountFromRemovingCredentials;

// Returns a sanitized version of mountFromName with only the password removed (username preserved).
// If mountFromName is not a valid URL or contains no password, returns the original string.
//
// Example: "//admin:password@192.168.64.2:445/share" -> "//admin@192.168.64.2:445/share"
- (NSString *)sanitizedMountFromRemovingPassword;

@end
