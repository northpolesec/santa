/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/gui/SNTStatusItemManager.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTNotificationManager.h"

@interface SNTStatusItemManager ()
@property SNTAboutWindowController *aboutWindowController;
@property(strong, nonatomic, readwrite) NSStatusItem *statusItem;

// Timer for temporary monitor mode countdown
@property(atomic, strong) NSTimer *temporaryMonitorModeTimer;
@property(atomic, strong) NSDate *temporaryMonitorModeExpiration;
@property NSMenuItem *temporaryMonitorModeMenuItem;
@end

@implementation SNTStatusItemManager

- (instancetype)init {
  self = [super init];
  if (self) {
    [self setupStatusBarItem];
  }
  return self;
}

- (void)setupStatusBarItem {
  // Create status bar item
  self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];

  // Set the app icon as the status bar icon
  NSImage *icon = [NSImage imageNamed:@"MenuItem"];
  if (icon) {
    icon.size = NSMakeSize(24.0, 16.0);
    [icon setTemplate:YES];
  }
  self.statusItem.button.image = icon;

  // Create the menu
  NSMenu *menu = [[NSMenu alloc] init];

  // Add About menu item
  NSMenuItem *aboutItem = [[NSMenuItem alloc] initWithTitle:@"About"
                                                     action:@selector(aboutMenuItemClicked:)
                                              keyEquivalent:@""];
  aboutItem.target = self;
  [menu addItem:aboutItem];

  self.temporaryMonitorModeMenuItem = [[NSMenuItem alloc] initWithTitle:@"Enter Temporary Monitor Mode"
                                                                 action:@selector(tmmMenuItemClicked:)
                                                          keyEquivalent:@""];
  self.temporaryMonitorModeMenuItem.target = self;
  [menu addItem:self.temporaryMonitorModeMenuItem];

  self.statusItem.menu = menu;
}

- (void)updateTitle:(NSString *)title {
  self.statusItem.button.title = title ?: @"";
}

- (void)showAboutWindow {
  if (!self.aboutWindowController) {
    self.aboutWindowController = [[SNTAboutWindowController alloc] init];
  }
  [self.aboutWindowController showWindow:self];
  [NSApp activateIgnoringOtherApps:YES];
}

- (void)aboutMenuItemClicked:(id)sender {
  [self showAboutWindow];
}

- (void)tmmMenuItemClicked:(id)sender {
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  if (self.temporaryMonitorModeExpiration) {
    [[daemonConn synchronousRemoteObjectProxy] cancelTemporaryMonitorMode:^(NSError *err) {
      if (err) {
        // TODO: Handle this properly
        NSLog(@"Failed to cancel TMM");
      }
    }];
  } else {
    [[daemonConn synchronousRemoteObjectProxy] requestTemporaryMonitorModeWithDurationMinutes:0 reply:^(uint32 minutes, NSError *err) {
      if (err) {
        // TODO: Handle this properly
        NSLog(@"Failed to request TMM");
      }
    }];

  }
  [daemonConn invalidate];
}

- (void)enterMonitorModeWithExpiration:(NSDate *)expiration {
  self.temporaryMonitorModeExpiration = expiration;

  // Invalidate any existing timer
  [self.temporaryMonitorModeTimer invalidate];

  // Create a timer that fires every second
  dispatch_async(dispatch_get_main_queue(), ^{
    self.temporaryMonitorModeTimer = [NSTimer
        scheduledTimerWithTimeInterval:1.0
                               repeats:YES
                                 block:^(NSTimer *timer) {
                                   if (!self.temporaryMonitorModeExpiration) {
                                     [self leaveMonitorMode];
                                     return;
                                   }

                                   NSTimeInterval remainingSeconds =
                                       [self.temporaryMonitorModeExpiration timeIntervalSinceNow];

                                   // If time has expired, stop the timer
                                   if (remainingSeconds <= 0) {
                                     [self leaveMonitorMode];
                                     return;
                                   }

                                   NSDateComponentsFormatter *dcf =
                                       [[NSDateComponentsFormatter alloc] init];
                                   dcf.allowedUnits = NSCalendarUnitDay | NSCalendarUnitHour |
                                                      NSCalendarUnitMinute;
                                   dcf.unitsStyle = NSDateComponentsFormatterUnitsStyleAbbreviated;
                                   NSString *title = [dcf stringFromDate:[NSDate now]
                                                                  toDate:self.temporaryMonitorModeExpiration];
                                   [self updateTitle:title];
                                   self.temporaryMonitorModeMenuItem.title = @"Leave Temporary Monitor Mode";
                                 }];
  });
}

- (void)leaveMonitorMode {
  [self.temporaryMonitorModeTimer invalidate];
  self.temporaryMonitorModeTimer = nil;
  self.temporaryMonitorModeExpiration = nil;

  [self updateTitle:@""];
  self.temporaryMonitorModeMenuItem.title = @"Enter Temporary Monitor Mode";
}

@end
