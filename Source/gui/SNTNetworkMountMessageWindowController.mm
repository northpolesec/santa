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

#import "Source/gui/SNTNetworkMountMessageWindowController.h"

#import "Source/gui/SNTNetworkMountMessageWindowView-Swift.h"

#import "Source/common/SNTStrengthify.h"

@implementation SNTNetworkMountMessageWindowController

- (instancetype)initWithEvent:(SNTStoredNetworkMountEvent*)event
                 configBundle:(SNTConfigBundle*)configBundle {
  self = [super init];
  if (self) {
    _event = event;
    _configBundle = configBundle;
  }
  return self;
}

- (void)showWindow:(id)sender {
  if (self.window) [self.window orderOut:sender];

  self.window = [SNTMessageWindowController defaultWindow];

  WEAKIFY(self);
  self.window.contentViewController = [SNTNetworkMountMessageWindowViewFactory
      createWithWindow:self.window
                 event:self.event
          configBundle:self.configBundle
           silenceable:([self messageHash] != nil)
       uiStateCallback:^(NSTimeInterval preventNotificationsPeriod) {
         STRONGIFY(self);
         self.silenceFutureNotificationsPeriod = preventNotificationsPeriod;
       }];
  self.window.delegate = self;

  [super showWindow:sender];
}

- (NSString*)messageHash {
  // Use the full remote host/path with any credentials stripped — same
  // server/share silence regardless of which user supplied the credentials.
  // Return nil rather than a bare "netmount:" prefix when there's no
  // identifier so unidentified events don't collapse onto one shared key.
  NSString* sanitized = [self.event sanitizedMountFromRemovingCredentials];
  if (!sanitized.length) return nil;
  return [@"netmount:" stringByAppendingString:sanitized];
}

@end
