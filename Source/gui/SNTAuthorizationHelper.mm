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

#import "Source/gui/SNTAuthorizationHelper.h"

#import <LocalAuthentication/LocalAuthentication.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"

@implementation SNTAuthorizationHelper

+ (LAPolicy)authorizationPolicy {
  return [SNTConfigurator configurator].enableStandalonePasswordFallback
             ? LAPolicyDeviceOwnerAuthentication
             : LAPolicyDeviceOwnerAuthenticationWithBiometrics;
}

+ (void)authorizeWithReason:(NSString *)reason replyBlock:(void (^)(BOOL success))replyBlock {
  LAContext *context = [[LAContext alloc] init];
  [context evaluatePolicy:[self authorizationPolicy]
          localizedReason:reason
                    reply:^(BOOL success, NSError *_Nullable error) {
                      replyBlock(success);
                    }];
}

+ (void)authorizeTemporaryMonitorModeWithReplyBlock:(void (^)(BOOL success))replyBlock {
  NSString *reason = NSLocalizedString(@"authorize temporary Monitor Mode",
                                       @"Authorize temporary Monitor Mode exception");
  [self authorizeWithReason:reason replyBlock:replyBlock];
}

+ (void)authorizeExecutionForEvent:(SNTStoredExecutionEvent *)event
                        replyBlock:(void (^)(BOOL success))replyBlock {
  NSString *reason = [self executionAuthorizationReasonForEvent:event];
  [self authorizeWithReason:reason replyBlock:replyBlock];
}

+ (NSString *)executionAuthorizationReasonForEvent:(SNTStoredExecutionEvent *)event {
  NSString *bundleName = event.fileBundleName ?: @"";
  NSString *filePath = event.filePath ?: @"";

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

+ (BOOL)canAuthorizeWithTouchID:(NSError **)error {
  LAContext *context = [[LAContext alloc] init];
  return [context canEvaluatePolicy:[self authorizationPolicy] error:error];
}

@end
