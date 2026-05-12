/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/gui/SNTDeviceMessageWindowController.h"
#import "Source/gui/SNTDeviceMessageWindowView-Swift.h"

#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"

NS_ASSUME_NONNULL_BEGIN

@implementation SNTDeviceMessageWindowController

- (instancetype)initWithEvent:(SNTDeviceEvent*)event configBundle:(SNTConfigBundle*)configBundle {
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

  self.window.contentViewController = [SNTDeviceMessageWindowViewFactory
      createWithWindow:self.window
                 event:self.event
          configBundle:self.configBundle
           silenceable:([self messageHash] != nil)
       uiStateCallback:^(NSTimeInterval preventNotificationsPeriod) {
         self.silenceFutureNotificationsPeriod = preventNotificationsPeriod;
       }];
  self.window.delegate = self;

  [super showWindow:sender];
}

- (NSString*)messageHash {
  // Use model + media UUID — these are stable across re-mounts of the same
  // physical device, unlike the user-controllable mount-on path or the
  // per-mount BSD device path. If neither is available, return nil so no
  // silence entry is recorded (better than silencing by an unstable key).
  NSString* model = self.event.deviceModel;
  NSString* uuid = self.event.mediaUUID;
  if (!model.length && !uuid.length) return nil;
  return [NSString stringWithFormat:@"usb:%@|%@", model ?: @"", uuid ?: @""];
}

@end

NS_ASSUME_NONNULL_END
