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

#import "Source/gui/SNTNetworkFlowMessageWindowController.h"

#import "Source/gui/SNTNetworkFlowMessageWindowView-Swift.h"

#import "Source/common/SNTConfigBundle.h"
#import "Source/common/SNTStoredNetworkFlowEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SigningIDHelpers.h"

@interface SNTNetworkFlowMessageWindowController ()
@property SNTConfigBundle* configBundle;
@property SNTStoredNetworkFlowEvent* event;
@end

@implementation SNTNetworkFlowMessageWindowController

- (instancetype)initWithEvent:(SNTStoredNetworkFlowEvent*)event
                 configBundle:(SNTConfigBundle*)configBundle {
  self = [super init];
  if (self) {
    _event = event;
    _configBundle = configBundle;
  }
  return self;
}

- (void)showWindow:(id)sender {
  if (self.window) {
    [self.window orderOut:sender];
  }

  self.window = [SNTMessageWindowController defaultWindow];

  WEAKIFY(self);
  self.window.contentViewController = [SNTNetworkFlowMessageWindowViewFactory
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
  // Silence key: app-level and cross-version, so muting an app suppresses its network-block
  // dialogs regardless of destination, rule, or app version. Prefer the team+signing ID (stable
  // across updates), then cdhash, then the best-effort file hash. nil when no stable identity is
  // present so unidentified events don't collapse onto one shared silence key.
  SNTStoredProcess* process = self.event.process;
  NSString* signingID = FormatSigningID(process.signingID, process.teamID, NO);
  if (signingID.length) return [@"netflow:signingid:" stringByAppendingString:signingID];
  if (process.cdhash.length) return [@"netflow:cdhash:" stringByAppendingString:process.cdhash];
  if (process.fileSHA256.length)
    return [@"netflow:sha256:" stringByAppendingString:process.fileSHA256];
  return nil;
}

- (NSString*)queueDedupeHash {
  // Finer-grained than the silence key: the already-queued check should still collapse only exact
  // repeats of the same (process, rule, destination), so distinct flows from one app each get
  // their own dialog. uiDedupeKey encodes that tuple; nil when absent.
  if (!self.event.uiDedupeKey.length) return nil;
  return [@"netflow:" stringByAppendingString:self.event.uiDedupeKey];
}

@end
