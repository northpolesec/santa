/// Copyright 2023 Google LLC
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

#import "Source/gui/SNTFileAccessMessageWindowController.h"
#import "Source/gui/SNTFileAccessMessageWindowView-Swift.h"

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTFileAccessEvent.h"
#import "Source/common/SNTLogging.h"

@interface SNTFileAccessMessageWindowController ()
@property NSString *customMessage;
@property NSString *customURL;
@property NSString *customText;
@property SNTFileAccessEvent *event;
@end

@implementation SNTFileAccessMessageWindowController

- (instancetype)initWithEvent:(SNTFileAccessEvent *)event
                customMessage:(nullable NSString *)message
                    customURL:(nullable NSString *)url
                   customText:(nullable NSString *)text {
  self = [super init];
  if (self) {
    _event = event;
    _customMessage = message;
    _customURL = url;
    _customText = text;
  }
  return self;
}

- (void)windowDidResize:(NSNotification *)notification {
  [self.window center];
}

- (void)showWindow:(id)sender {
  if (self.window) {
    [self.window orderOut:sender];
  }

  self.window =
    [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 0, 0)
                                styleMask:NSWindowStyleMaskClosable | NSWindowStyleMaskResizable |
                                          NSWindowStyleMaskTitled
                                  backing:NSBackingStoreBuffered
                                    defer:NO];
  self.window.titlebarAppearsTransparent = YES;
  self.window.movableByWindowBackground = YES;
  [self.window standardWindowButton:NSWindowZoomButton].hidden = YES;
  [self.window standardWindowButton:NSWindowCloseButton].hidden = YES;
  [self.window standardWindowButton:NSWindowMiniaturizeButton].hidden = YES;

  self.window.contentViewController = [SNTFileAccessMessageWindowViewFactory
    createWithWindow:self.window
               event:self.event
       customMessage:self.customMessage
           customURL:self.customURL
          customText:self.customText
     uiStateCallback:^(NSTimeInterval preventNotificationsPeriod) {
       self.silenceFutureNotificationsPeriod = preventNotificationsPeriod;
     }];

  self.window.delegate = self;

  [super showWindow:sender];
}

- (NSString *)messageHash {
  // The hash for display de-duplication/silencing purposes is a combination of:
  // 1. The current file access rule version
  // 2. The name of the rule that was violated
  // 3. The path of the process
  return [NSString
    stringWithFormat:@"%@|%@|%@", self.event.ruleVersion, self.event.ruleName, self.event.filePath];
}

@end
