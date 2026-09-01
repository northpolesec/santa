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

#import "Source/gui/SNTTimedRuleKillMessageWindowController.h"

#import "Source/gui/SNTTimedRuleKillMessageWindowView-Swift.h"

#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTTimedRuleKillDetails.h"

@interface SNTTimedRuleKillMessageWindowController ()
// One-shot close at the deadline, held so a dismissal before the deadline can
// cancel it.
@property(atomic, strong) NSTimer* deadlineTimer;
@end

@implementation SNTTimedRuleKillMessageWindowController

- (instancetype)initWithDetails:(SNTTimedRuleKillDetails*)details {
  self = [super init];
  if (self) {
    _details = details;
  }
  return self;
}

- (void)showWindow:(id)sender {
  // A deadline that has already passed makes the warning untrue: the quit it
  // warns about has happened. Showing it anyway orders a dialog in, steals focus,
  // and blips the Dock icon for the few milliseconds before the timer below
  // closes it again, all with nothing readable on screen. Retire it instead.
  //
  // Retired through the delegate rather than by returning: the queue has already
  // made this controller its current window, and that callback is the only thing
  // that clears it, so a bare return would leave this warning holding the one
  // dialog slot and every dialog behind it waiting on it forever. The callback
  // re-enters the queue through dispatch_async, not recursion, so this is safe.
  if (self.details.deadline.timeIntervalSinceNow <= 0) {
    [self.delegate windowDidCloseSilenceHash:nil withInterval:0];
    return;
  }

  if (self.window) [self.window orderOut:sender];

  self.window = [SNTMessageWindowController defaultWindow];

  // No uiStateCallback: this window offers no per-application silence, so there
  // is no UI state to carry back to the notification manager.
  self.window.contentViewController =
      [SNTTimedRuleKillMessageWindowViewFactory createWithWindow:self.window details:self.details];
  self.window.delegate = self;

  [super showWindow:sender];

  // The warning stops being true once the deadline passes, and it holds the one
  // dialog slot until it closes, so a warning nobody dismisses would sit in front
  // of the block dialogs queued behind it, some of which carry reply blocks.
  //
  // Armed here rather than at init because only the window currently on screen
  // can be retired through the delegate that advances the queue; a warning whose
  // deadline passed while it was still queued is handled by the skip above
  // instead, so the interval here is always positive. showWindow: is main-thread
  // only (the queue hops there before calling it), so this lands on the main run
  // loop.
  [self.deadlineTimer invalidate];
  WEAKIFY(self);
  self.deadlineTimer =
      [NSTimer scheduledTimerWithTimeInterval:self.details.deadline.timeIntervalSinceNow
                                      repeats:NO
                                        block:^(NSTimer* timer) {
                                          STRONGIFY(self);
                                          // -close, not -closeWindow:, so the
                                          // window's delegate callback runs
                                          // exactly once and the queue advances
                                          // the same way a dismissal does.
                                          [self.window close];
                                        }];
}

- (void)windowWillClose:(NSNotification*)notification {
  // A warning dismissed before its deadline must not leave a timer holding this
  // controller and waiting to close an already-closed window.
  [self.deadlineTimer invalidate];
  self.deadlineTimer = nil;

  [super windowWillClose:notification];
}

- (NSString*)messageHash {
  // One window per (application, deadline), so a repeated warning for the same
  // deadline collapses in the queue instead of stacking a second window.
  // Return nil rather than a bare prefix when either half is missing, so
  // unidentified warnings do not collapse onto one shared key.
  if (!self.details.application.length || !self.details.deadline) return nil;
  return [NSString stringWithFormat:@"timedrulekill:%@|%f", self.details.application,
                                    self.details.deadline.timeIntervalSince1970];
}

@end
