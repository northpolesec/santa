/// Copyright 2015 Google Inc. All rights reserved.
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

#import "src/gui/SNTDeviceMessageWindowController.h"
#import "src/gui/SNTDeviceMessageWindowView-Swift.h"

#import "src/common/SNTBlockMessage.h"
#import "src/common/SNTConfigurator.h"
#import "src/common/SNTDeviceEvent.h"

NS_ASSUME_NONNULL_BEGIN

@implementation SNTDeviceMessageWindowController

- (instancetype)initWithEvent:(SNTDeviceEvent *)event {
  self = [super init];
  if (self) {
    _event = event;
  }
  return self;
}

- (void)showWindow:(id)sender {
  if (self.window) [self.window orderOut:sender];

  self.window = [SNTMessageWindowController defaultWindow];

  self.window.contentViewController =
      [SNTDeviceMessageWindowViewFactory createWithWindow:self.window event:self.event];
  self.window.delegate = self;

  [super showWindow:sender];
}

- (NSString *)messageHash {
  return self.event.mntonname;
}

@end

NS_ASSUME_NONNULL_END
