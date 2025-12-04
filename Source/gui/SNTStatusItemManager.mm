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
#include <AppKit/AppKit.h>
#include "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTXPCSyncServiceInterface.h"
#include <objc/NSObjCRuntime.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTNotificationManager.h"

@interface SNTStatusItemManager ()
@property SNTAboutWindowController *aboutWindowController;
@property(strong, nonatomic, readwrite) NSStatusItem *statusItem;

// Sync items
@property NSMenuItem *syncMenuItem;

// Temporary monitor mode items
@property(atomic, strong) NSTimer *temporaryMonitorModeTimer;
@property(atomic, strong) NSDate *temporaryMonitorModeExpiration;
@property NSMenuItem *temporaryMonitorModeRefreshItem;
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

  // Add version string and about menu item
  NSString *santaVersionString = [NSString stringWithFormat:@"Santa v%@", [[NSBundle mainBundle] infoDictionary][@"CFBundleShortVersionString"]];
  [menu addItem:[self menuItemWithTitle:santaVersionString andAction:nil]];
  [menu addItem:[self menuItemWithTitle:@"About Santa" andAction:@selector(aboutMenuItemClicked:)]];

  // Add separator
  [menu addItem:[NSMenuItem separatorItem]];

  // Add sync item
  self.syncMenuItem = [self menuItemWithTitle:@"Sync" andAction:@selector(syncMenuItemClicked:)];
  [menu addItem:self.syncMenuItem];

  // Add separator
  [menu addItem:[NSMenuItem separatorItem]];

  // Add temporary monitor mode items
  self.temporaryMonitorModeMenuItem = [self menuItemWithTitle:@"Enter Temporary Monitor Mode" andAction:@selector(tmmMenuItemClicked:)];
  [menu addItem:self.temporaryMonitorModeMenuItem];

  self.temporaryMonitorModeRefreshItem = [self menuItemWithTitle:@"Refresh Temporary Monitor Mode" andAction:@selector(tmmRefreshItemClicked:)];
  self.temporaryMonitorModeRefreshItem.target = nil;
  [menu addItem:self.temporaryMonitorModeRefreshItem];

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

- (void)tmmRefreshItemClicked:(id)sender {
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn synchronousRemoteObjectProxy] requestTemporaryMonitorModeWithDurationMinutes:0 reply:^(uint32 minutes, NSError *err) {
    if (err) {
      // TODO: Handle this properly
      NSLog(@"Failed to refresh TMM");
    }
  }];
  [daemonConn invalidate];
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

- (void)syncMenuItemClicked:(id)sender {
  // Disable the sync menu item until we're done.
  self.syncMenuItem.target = nil;

  MOLXPCConnection *daemonConn = [SNTXPCSyncServiceInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn remoteObjectProxy] syncWithLogListener:nil syncType:SNTSyncTypeNormal reply:^(SNTSyncStatusType status) {
    self.syncMenuItem.target = self;

    if (status == SNTSyncStatusTypeSuccess) {
      NSLog(@"SYNC SUCCESS");
      [self.statusItem.button setSubviews:@[]];
      self.statusItem.button.image  = [NSImage imageNamed:NSImageNameStatusAvailable];
      [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:NO block:^(NSTimer * _Nonnull timer) {
        self.statusItem.button.image = [NSImage imageNamed:@"MenuItem"];
      }];
    } else {
      NSLog(@"SYNC FAIL");
      [self.statusItem.button setSubviews:@[]];
      self.statusItem.button.image  = [NSImage imageNamed:NSImageNameStatusUnavailable];
      [NSTimer scheduledTimerWithTimeInterval:2.0 repeats:NO block:^(NSTimer * _Nonnull timer) {
        self.statusItem.button.image = [NSImage imageNamed:@"MenuItem"];
      }];
    }

    [daemonConn invalidate];
  }];

  NSLog(@"SYNC STARTING");

  NSProgressIndicator *p = [[NSProgressIndicator alloc] init];
  p.indeterminate = YES;
  self.statusItem.button.title = @"";
  [self.statusItem.button addSubview:p];
}

- (void)enterMonitorModeWithExpiration:(NSDate *)expiration {
  self.temporaryMonitorModeExpiration = expiration;

  // Invalidate any existing timer
  [self.temporaryMonitorModeTimer invalidate];

  // Update menu options
  self.temporaryMonitorModeMenuItem.title = @"Leave Temporary Monitor Mode";
  self.temporaryMonitorModeRefreshItem.target = self;

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
                                 }];
  });
}

- (void)leaveMonitorMode {
  [self.temporaryMonitorModeTimer invalidate];
  self.temporaryMonitorModeTimer = nil;
  self.temporaryMonitorModeExpiration = nil;

  [self updateTitle:@""];
  self.temporaryMonitorModeMenuItem.title = @"Enter Temporary Monitor Mode";
  self.temporaryMonitorModeRefreshItem.target = nil;
}

- (NSMenuItem *)menuItemWithTitle:(NSString *)title andAction:(SEL) action {
  NSMenuItem *i = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:@""];
  i.target = self;
  return i;
}

@end
