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

@class SNTStoredExecutionEvent;

/// Helper class for TouchID/LocalAuthentication and FIDO2 authorization.
@interface SNTAuthorizationHelper : NSObject

/// Authorize temporary monitor mode via TouchID or FIDO2 security key.
+ (void)authorizeTemporaryMonitorModeWithReplyBlock:(void (^)(BOOL success))replyBlock;

/// Authorize execution of a binary via TouchID or FIDO2 security key.
+ (void)authorizeExecutionForEvent:(SNTStoredExecutionEvent*)event
                        replyBlock:(void (^)(BOOL success))replyBlock;

/// Build the localized reason string for an execution authorization prompt.
+ (NSString*)executionAuthorizationReasonForEvent:(SNTStoredExecutionEvent*)event;

/// Check if TouchID authorization is available on this device.
+ (BOOL)canAuthorizeWithTouchID:(NSError**)error;

/// Check if a FIDO2 security key is available for authorization.
+ (BOOL)canAuthorizeWithFido2;

/// Check if any authorization method (TouchID or FIDO2) is available.
+ (BOOL)canAuthorize:(NSError**)error;

@end
