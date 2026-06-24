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

/// Helper class for TouchID/LocalAuthentication authorization.
@interface SNTAuthorizationHelper : NSObject

/// Authorize temporary monitor mode via TouchID.
+ (void)authorizeTemporaryMonitorModeWithReplyBlock:(void (^)(BOOL success))replyBlock;

/// Authorize temporary admin mode via TouchID, optionally collecting a justification string first.
/// If requireJustification is YES, an alert with a text field is presented before the Touch ID
/// prompt; if the user cancels that alert replyBlock is called with (NO, @"") and no LA prompt is
/// shown. replyBlock is always called exactly once with (authenticated, justification).
+ (void)authorizeTemporaryAdminModeRequiringJustification:(BOOL)requireJustification
                                               replyBlock:
                                                   (void (^)(BOOL authenticated,
                                                             NSString* justification))replyBlock;

/// Authorize execution of a binary via TouchID.
+ (void)authorizeExecutionForEvent:(SNTStoredExecutionEvent*)event
                        replyBlock:(void (^)(BOOL success))replyBlock;

/// Build the localized reason string for an execution authorization prompt.
+ (NSString*)executionAuthorizationReasonForEvent:(SNTStoredExecutionEvent*)event;

/// Check if TouchID authorization is available on this device.
+ (BOOL)canAuthorizeWithTouchID:(NSError**)error;

@end
