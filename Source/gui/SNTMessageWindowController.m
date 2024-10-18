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

@implementation SNTMessageWindowController

- (IBAction)showWindow:(id)sender {
  [self.window setLevel:NSPopUpMenuWindowLevel];
  [self.window setMovableByWindowBackground:YES];
  [self.window makeKeyAndOrderFront:sender];
  [self.window center];
  [NSApp activateIgnoringOtherApps:YES];
}

- (IBAction)closeWindow:(id)sender {
  [self windowWillClose:sender];
  [self.window close];
}

- (void)windowWillClose:(NSNotification *)notification {
  if (!self.delegate) return;

  if (self.silenceFutureNotifications) {
    [self.delegate windowDidCloseSilenceHash:[self messageHash]];
  } else {
    [self.delegate windowDidCloseSilenceHash:nil];
  }
}

- (NSString *)messageHash {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

@end
