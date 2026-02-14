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

#import "Source/gui/SNTAuthorizationHelper.h"

#import <LocalAuthentication/LocalAuthentication.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/gui/SNTFido2Helper.h"

@implementation SNTAuthorizationHelper

+ (LAPolicy)authorizationPolicy {
  return [SNTConfigurator configurator].enableStandalonePasswordFallback
             ? LAPolicyDeviceOwnerAuthentication
             : LAPolicyDeviceOwnerAuthenticationWithBiometrics;
}

+ (void)authorizeWithTouchIDReason:(NSString*)reason replyBlock:(void (^)(BOOL success))replyBlock {
  LAContext* context = [[LAContext alloc] init];
  [context evaluatePolicy:[self authorizationPolicy]
          localizedReason:reason
                    reply:^(BOOL success, NSError* _Nullable error) {
                      replyBlock(success);
                    }];
}

+ (void)authorizeWithReason:(NSString*)reason replyBlock:(void (^)(BOOL success))replyBlock {
  // Try FIDO2 first. The device check happens on a background thread inside
  // SNTFido2Helper. If FIDO2 succeeds, we're done. If it fails (no device
  // connected, or auth error), fall back to TouchID.
  [SNTFido2Helper authorizeWithReason:reason
                           replyBlock:^(BOOL success, BOOL deviceWasFound) {
                             if (success) {
                               replyBlock(YES);
                               return;
                             }
                             if (deviceWasFound) {
                               // A device was found but auth failed (cancel, timeout, etc.)
                               // — don't fall back to TouchID.
                               replyBlock(NO);
                               return;
                             }
                             // No FIDO2 device found — try TouchID as fallback.
                             NSError* err;
                             if ([self canAuthorizeWithTouchID:&err]) {
                               [self authorizeWithTouchIDReason:reason replyBlock:replyBlock];
                             } else {
                               replyBlock(NO);
                             }
                           }];
}

+ (void)authorizeTemporaryMonitorModeWithReplyBlock:(void (^)(BOOL success))replyBlock {
  NSString* reason = NSLocalizedString(@"authorize temporary Monitor Mode",
                                       @"Authorize temporary Monitor Mode exception");
  [self authorizeWithReason:reason replyBlock:replyBlock];
}

+ (void)authorizeExecutionForEvent:(SNTStoredExecutionEvent*)event
                        replyBlock:(void (^)(BOOL success))replyBlock {
  NSString* reason = [self executionAuthorizationReasonForEvent:event];
  [self authorizeWithReason:reason replyBlock:replyBlock];
}

+ (NSString*)executionAuthorizationReasonForEvent:(SNTStoredExecutionEvent*)event {
  NSString* bundleName = event.fileBundleName ?: @"";
  NSString* filePath = event.filePath ?: @"";

  if (bundleName.length > 0) {
    return
        [NSString localizedStringWithFormat:NSLocalizedString(
                                                @"authorize execution of the application %@",
                                                @"Authorize execution of an application with name"),
                                            bundleName];
  } else if (filePath.length > 0) {
    return [NSString
        localizedStringWithFormat:NSLocalizedString(
                                      @"authorize execution of %@",
                                      @"Authorize execution of an application with file name"),
                                  filePath.lastPathComponent];
  } else {
    return NSLocalizedString(@"authorize execution", @"Authorize execution");
  }
}

+ (BOOL)canAuthorizeWithTouchID:(NSError**)error {
  LAContext* context = [[LAContext alloc] init];
  return [context canEvaluatePolicy:[self authorizationPolicy] error:error];
}

+ (BOOL)canAuthorizeWithFido2 {
  return [SNTFido2Helper isFido2DeviceAvailable];
}

+ (BOOL)canAuthorize:(NSError**)error {
  if ([self canAuthorizeWithFido2]) {
    return YES;
  }
  return [self canAuthorizeWithTouchID:error];
}

@end
