/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/gui/SNTBinaryMessageWindowController.h"
#import "Source/gui/SNTBinaryMessageWindowView-Swift.h"

#include <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <SecurityInterface/SFCertificatePanel.h>
#include <dispatch/dispatch.h>

#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredEvent.h"

@interface SNTBinaryMessageWindowController ()

///  The custom message to display for this event
@property(copy) NSString *customMessage;

///  The custom URL to use for this event
@property(copy) NSString *customURL;

@end

@implementation SNTBinaryMessageWindowController

- (instancetype)initWithEvent:(SNTStoredEvent *)event
                    customMsg:(NSString *)message
                    customURL:(NSString *)url
                  configState:(SNTConfigState *)configState
                        reply:(void (^)(BOOL))replyBlock {
  self = [super init];
  if (self) {
    _event = event;
    _customMessage = message;
    _customURL = url;
    _configState = configState;
    _replyBlock = replyBlock;
    _progress = [NSProgress discreteProgressWithTotalUnitCount:1];
    [_progress addObserver:self
                forKeyPath:@"fractionCompleted"
                   options:NSKeyValueObservingOptionNew
                   context:NULL];
    _bundleProgress = [[SNTBundleProgress alloc] init];
  }
  return self;
}

- (void)dealloc {
  [_progress removeObserver:self forKeyPath:@"fractionCompleted"];
}

- (void)observeValueForKeyPath:(NSString *)keyPath
                      ofObject:(id)object
                        change:(NSDictionary *)change
                       context:(void *)context {
  if ([keyPath isEqualToString:@"fractionCompleted"]) {
    dispatch_async(dispatch_get_main_queue(), ^{
      NSProgress *progress = object;
      self.bundleProgress.fractionCompleted = progress.fractionCompleted;
    });
  }
}

- (void)windowDidResize:(NSNotification *)notification {
  [self.window center];
}

- (void)showWindow:(id)sender {
  if (self.window) [self.window orderOut:sender];

  self.window =
      [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 0, 0)
                                  styleMask:NSWindowStyleMaskClosable | NSWindowStyleMaskTitled
                                    backing:NSBackingStoreBuffered
                                      defer:NO];
  self.window.titlebarAppearsTransparent = YES;
  self.window.movableByWindowBackground = YES;
  [self.window standardWindowButton:NSWindowZoomButton].hidden = YES;
  [self.window standardWindowButton:NSWindowCloseButton].hidden = YES;
  [self.window standardWindowButton:NSWindowMiniaturizeButton].hidden = YES;
  self.window.contentViewController = [SNTBinaryMessageWindowViewFactory
      createWithWindow:self.window
                 event:self.event
             customMsg:self.customMessage
             customURL:self.customURL
           configState:self.configState
        bundleProgress:self.bundleProgress
       uiStateCallback:^(NSTimeInterval preventNotificationsPeriod) {
         self.silenceFutureNotificationsPeriod = preventNotificationsPeriod;
       }
         replyCallback:self.replyBlock];

  self.window.delegate = self;

  [super showWindow:sender];
}

- (NSString *)messageHash {
  return self.event.fileSHA256;
}

#pragma mark Generated properties

- (void)updateBlockNotification:(SNTStoredEvent *)event withBundleHash:(NSString *)bundleHash {
  // UI updates must happen on the main thread.
  dispatch_async(dispatch_get_main_queue(), ^{
    if ([self.event.idx isEqual:event.idx]) {
      self.event.fileBundleHash = bundleHash;
      self.bundleProgress.isFinished = YES;
    }
  });
}

@end
