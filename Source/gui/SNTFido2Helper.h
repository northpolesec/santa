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

NS_ASSUME_NONNULL_BEGIN

/// The outcome of a security key authorization attempt.
typedef NS_ENUM(NSInteger, SNTFido2Result) {
  /// A key attached to this Mac was touched.
  SNTFido2ResultApproved,
  /// A key was attached but nothing approved: the touch timed out, the user
  /// cancelled, or every device reported an error.
  SNTFido2ResultDenied,
  /// No FIDO2 device is attached, so the user was never asked. A caller that
  /// accepts more than one method should try another rather than deny.
  SNTFido2ResultNoDevice,
  /// The user asked to authorize with Touch ID instead.
  SNTFido2ResultUseTouchID,
};

/// Helper class for FIDO2 hardware security key authorization.
///
/// This checks user presence only: that someone touched a FIDO2 key attached to
/// this Mac. It does not establish which key, or whose. Verifying a registered
/// credential needs an assertion checked against a public key the client holds,
/// and there is nowhere to enroll one yet.
@interface SNTFido2Helper : NSObject

/// Authorize an action with a FIDO2 security key. Every attached key is asked
/// for a touch at once, and the first one touched wins.
///
/// The reply block is called exactly once, never on the main thread. No prompt
/// is shown when no device is attached.
///
/// @param reason Localized reason string displayed to the user.
/// @param offerTouchID Whether to offer "Use Touch ID instead" on the prompt.
+ (void)authorizeWithReason:(NSString*)reason
        offerTouchIDInstead:(BOOL)offerTouchID
                 replyBlock:(void (^)(SNTFido2Result result))replyBlock;

@end

NS_ASSUME_NONNULL_END
