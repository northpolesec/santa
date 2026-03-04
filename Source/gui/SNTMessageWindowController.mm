/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/gui/SNTMessageWindowController.h"

@interface SNTMessageWindowController ()
@property BOOL hasBeenCentered;
@end

@implementation SNTMessageWindowController

+ (NSWindow *)defaultWindow {
  NSWindow *window =
      [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 0, 0)
                                  styleMask:NSWindowStyleMaskClosable | NSWindowStyleMaskResizable |
                                            NSWindowStyleMaskTitled
                                    backing:NSBackingStoreBuffered
                                      defer:NO];

  window.titlebarAppearsTransparent = YES;
  window.movableByWindowBackground = YES;
  window.releasedWhenClosed = YES;
  [window standardWindowButton:NSWindowZoomButton].hidden = YES;
  [window standardWindowButton:NSWindowCloseButton].hidden = YES;
  [window standardWindowButton:NSWindowMiniaturizeButton].hidden = YES;

  return window;
}

- (IBAction)showWindow:(id)sender {
  [self.window setLevel:NSModalPanelWindowLevel];
  [self.window setMovableByWindowBackground:YES];

  // Force layout so NSHostingController sizes the window to fit the SwiftUI content
  // before it becomes visible. Without this, the window briefly appears too small then
  // snaps to the correct size once SwiftUI layout completes.
  [self.window layoutIfNeeded];
  [self.window center];

  [self.window makeKeyAndOrderFront:sender];
  [NSApp activateIgnoringOtherApps:YES];
}

- (IBAction)closeWindow:(id)sender {
  [self windowWillClose:sender];
  [self.window close];
}

- (void)windowWillClose:(NSNotification *)notification {
  if (!self.delegate) return;

  if (self.silenceFutureNotificationsPeriod) {
    [self.delegate windowDidCloseSilenceHash:[self messageHash]
                                withInterval:self.silenceFutureNotificationsPeriod];
  } else {
    [self.delegate windowDidCloseSilenceHash:nil withInterval:0];
  }
}

- (void)windowDidResize:(NSNotification *)notification {
  if (!self.hasBeenCentered) {
    [self.window center];
    self.hasBeenCentered = YES;
  }
}

- (NSString *)messageHash {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

@end
