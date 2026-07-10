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

#import <Cocoa/Cocoa.h>
#import <LocalAuthentication/LocalAuthentication.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"

// Upper bound on how long the interactive Temporary Admin Mode justification
// prompt may stay open. santad reaches this prompt over a synchronous XPC proxy
// and holds grant_mutex_ plus a request-handler thread until the reply runs, so
// an abandoned dialog must not wait on the user indefinitely. On timeout the
// prompt is dismissed and authorization fails closed.
static const NSTimeInterval kAdminJustificationPromptTimeoutSeconds = 120;

@implementation SNTAuthorizationHelper

+ (LAPolicy)authorizationPolicy {
  return [SNTConfigurator configurator].enableStandalonePasswordFallback
             ? LAPolicyDeviceOwnerAuthentication
             : LAPolicyDeviceOwnerAuthenticationWithBiometrics;
}

+ (void)authorizeWithReason:(NSString*)reason replyBlock:(void (^)(BOOL success))replyBlock {
  LAContext* context = [[LAContext alloc] init];
  [context evaluatePolicy:[self authorizationPolicy]
          localizedReason:reason
                    reply:^(BOOL success, NSError* _Nullable error) {
                      replyBlock(success);
                    }];
}

+ (void)authorizeTemporaryMonitorModeWithReplyBlock:(void (^)(BOOL success))replyBlock {
  NSString* reason = NSLocalizedString(@"authorize temporary Monitor Mode",
                                       @"Authorize temporary Monitor Mode exception");
  [self authorizeWithReason:reason replyBlock:replyBlock];
}

+ (void)authorizeTemporaryAdminModeRequiringJustification:(BOOL)requireJustification
                                               replyBlock:
                                                   (void (^)(BOOL authenticated,
                                                             NSString* justification))replyBlock {
  dispatch_async(dispatch_get_main_queue(), ^{
    NSString* capturedJustification = @"";

    if (requireJustification) {
      NSAlert* alert = [[NSAlert alloc] init];
      alert.messageText =
          NSLocalizedString(@"Request Admin Privileges", @"Temporary admin mode alert title");
      alert.informativeText =
          NSLocalizedString(@"Enter a justification for requesting admin privileges:",
                            @"Temporary admin mode alert body");
      [alert addButtonWithTitle:NSLocalizedString(@"OK", @"OK button")];
      [alert addButtonWithTitle:NSLocalizedString(@"Cancel", @"Cancel button")];

      NSTextField* justificationField =
          [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 300, 22)];
      justificationField.placeholderString =
          NSLocalizedString(@"Justification", @"Temporary admin mode justification placeholder");
      alert.accessoryView = justificationField;

      // The GUI is a background agent (LSUIElement). SNTAppDelegate promotes the app to
      // .regular whenever it becomes active with a visible window and restores .accessory
      // on NSWindowWillCloseNotification -- but a modal alert does not post that
      // notification (see -[SNTStatusItemManager resetSilencesMenuItemClicked:]), so the
      // policy is restored by hand once the alert dismisses. Otherwise the app lingers in
      // the Dock and Cmd-Tab switcher. Only undo our own promotion: if another window
      // already required .regular, leave it.
      //
      // Bring the alert to the front and activate the app so the user sees the prompt and
      // can type into it. -activateIgnoringOtherApps: alone is a no-op for a backgrounded
      // agent: the window must be ordered to the front regardless of activation policy
      // first, and only then does activation take hold. Center before ordering front so
      // the window is not displayed off-center.
      BOOL restoreAccessoryPolicy =
          (NSApp.activationPolicy == NSApplicationActivationPolicyAccessory);
      [alert layout];
      [alert.window center];
      [alert.window orderFrontRegardless];
      [NSApp activateIgnoringOtherApps:YES];

      // NSAlert makes the OK button the first responder; move focus to the justification
      // field once the modal loop is running. runModal services only
      // NSModalPanelRunLoopMode, so schedule the focus change -- and the fail-closed
      // timeout below -- in that mode. On timeout, -stopModalWithCode: cancels the prompt
      // so santad's synchronous auth call is not pinned by an abandoned dialog (see
      // kAdminJustificationPromptTimeoutSeconds above).
      //
      // Focus is cycled through nil rather than set once: this prompt is presented on
      // the heels of a status-menu click (menu item -> santad XPC -> back here), and on
      // macOS 26 a field editor that becomes first responder that soon after menu
      // tracking inherits the system text cursor's "hidden during tracking" state -- the
      // insertion point never appears, even though focus and key state are correct, and
      // a presentation delay does not help. Resigning and re-becoming first responder
      // rebuilds the insertion indicator in the normal state so the caret blinks.
      NSTimer* focusTimer =
          [NSTimer timerWithTimeInterval:0
                                 repeats:NO
                                   block:^(NSTimer* _Nonnull timer) {
                                     [alert.window makeFirstResponder:justificationField];
                                     [alert.window makeFirstResponder:nil];
                                     [alert.window makeFirstResponder:justificationField];
                                   }];
      [[NSRunLoop currentRunLoop] addTimer:focusTimer forMode:NSModalPanelRunLoopMode];

      NSTimer* timeoutTimer =
          [NSTimer timerWithTimeInterval:kAdminJustificationPromptTimeoutSeconds
                                 repeats:NO
                                   block:^(NSTimer* _Nonnull timer) {
                                     [NSApp stopModalWithCode:NSModalResponseCancel];
                                   }];
      [[NSRunLoop currentRunLoop] addTimer:timeoutTimer forMode:NSModalPanelRunLoopMode];

      NSModalResponse response = [alert runModal];
      [focusTimer invalidate];
      [timeoutTimer invalidate];

      if (restoreAccessoryPolicy) {
        NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
      }
      if (response != NSAlertFirstButtonReturn) {
        replyBlock(NO, @"");
        return;
      }
      capturedJustification = [justificationField.stringValue copy] ?: @"";
    }

    NSString* authReason =
        NSLocalizedString(@"request admin privileges", @"Authorize temporary Admin Mode exception");
    // Capture capturedJustification so it is available in the LA reply block.
    NSString* justificationForReply = capturedJustification;
    [self authorizeWithReason:authReason
                   replyBlock:^(BOOL success) {
                     replyBlock(success, justificationForReply);
                   }];
  });
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

@end
