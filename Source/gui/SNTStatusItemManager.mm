/// Copyright 2026 North Pole Security, Inc.
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

#import <UserNotifications/UserNotifications.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTNotificationManager.h"

@interface SNTStatusItemManager ()
@property SNTAboutWindowController *aboutWindowController;
@property(strong, nonatomic, readwrite) NSStatusItem *statusItem;
@property SNTKVOManager *kvoEnableMenuItem;

// Sync items
@property NSMenuItem *syncMenuItem;

// Temporary monitor mode items
@property(atomic, strong) NSTimer *temporaryMonitorModeTimer;
@property(atomic, strong) NSDate *temporaryMonitorModeExpiration;
@property NSMenuItem *temporaryMonitorModeMenuItem;
@property NSMenuItem *temporaryMonitorModeRefreshItem;

// Reset silences item
@property NSMenuItem *resetSilencesMenuItem;
@end

static NSString *const kNotificationSilencesKey = @"SilencedNotifications";

@implementation SNTStatusItemManager

- (instancetype)init {
  self = [super init];
  if (self) {
    [self setupStatusBarItem];

    // Watch for changes to the EnableMenuItem configuration key
    WEAKIFY(self);
    self.kvoEnableMenuItem =
        [[SNTKVOManager alloc] initWithObject:[SNTConfigurator configurator]
                                     selector:@selector(enableMenuItem)
                                         type:[NSNumber class]
                                     callback:^(NSNumber *oldValue, NSNumber *newValue) {
                                       STRONGIFY(self);
                                       // If user has an override, admin config changes don't affect
                                       // the menu item visibility
                                       if ([self userMenuItemEnabledOverride]) {
                                         return;
                                       }

                                       BOOL oldBool = [oldValue boolValue];
                                       BOOL newBool = newValue ? [newValue boolValue] : YES;

                                       if (oldBool == newBool) {
                                         return;
                                       }

                                       if (newBool) {
                                         [self setupStatusBarItem];
                                       } else {
                                         [self removeStatusBarItem];
                                       }
                                     }];

    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(userMenuItemOverrideChanged:)
                                                 name:NSUserDefaultsDidChangeNotification
                                               object:nil];
  }
  return self;
}

- (void)setMenuItemImageWithTintColor:(NSColor *)tintColor {
  NSImage *original = [NSImage imageNamed:@"MenuItem"];
  if (!original) return;
  [original setTemplate:YES];
  original.size = NSMakeSize(24.0, 16.0);

  if (!tintColor) {
    self.statusItem.button.image = original;
    return;
  }

  NSImage *tinted = [original copy];
  [tinted lockFocus];
  [tintColor set];
  NSRectFillUsingOperation(NSMakeRect(0, 0, tinted.size.width, tinted.size.height),
                           NSCompositingOperationSourceAtop);
  [tinted unlockFocus];
  [tinted setTemplate:NO];
  self.statusItem.button.image = tinted;
}

- (void)setupStatusBarItem {
  // Only create status bar item if enabled (considering user override and admin config)
  if (![self effectiveMenuItemEnabled]) {
    return;
  }

  // Don't create if already exists
  if (self.statusItem) {
    return;
  }

  // Create status bar item
  self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];

  // Set the status bar icon
  [self setMenuItemImageWithTintColor:nil];

  // Create the menu
  NSMenu *menu = [[NSMenu alloc] init];

  // Add version string and about menu item
  NSString *santaVersionString = [NSString
      stringWithFormat:@"Santa v%@",
                       [[NSBundle mainBundle] infoDictionary][@"CFBundleShortVersionString"]];
  [menu addItem:[self menuItemWithTitle:santaVersionString andAction:nil]];
  [menu addItem:[self menuItemWithTitle:@"About Santa" andAction:@selector(aboutMenuItemClicked:)]];

  // Add reset silences item
  self.resetSilencesMenuItem = [self menuItemWithTitle:@"Reset Silenced Notifications"
                                             andAction:@selector(resetSilencesMenuItemClicked:)];
  [menu addItem:self.resetSilencesMenuItem];

  // Add separator
  [menu addItem:[NSMenuItem separatorItem]];

  // Add sync item
  self.syncMenuItem = [self menuItemWithTitle:@"Sync" andAction:@selector(syncMenuItemClicked:)];
  [menu addItem:self.syncMenuItem];

  // Add separator
  [menu addItem:[NSMenuItem separatorItem]];

  // Add temporary monitor mode items (hidden by default until policy is verified)
  self.temporaryMonitorModeMenuItem = [self menuItemWithTitle:@"Enter Temporary Monitor Mode"
                                                    andAction:@selector(tmmMenuItemClicked:)];
  self.temporaryMonitorModeMenuItem.hidden = YES;
  [menu addItem:self.temporaryMonitorModeMenuItem];

  self.temporaryMonitorModeRefreshItem = [self menuItemWithTitle:@"Refresh Temporary Monitor Mode"
                                                       andAction:@selector(tmmRefreshItemClicked:)];
  self.temporaryMonitorModeRefreshItem.target = nil;
  self.temporaryMonitorModeRefreshItem.hidden = YES;
  [menu addItem:self.temporaryMonitorModeRefreshItem];

  self.statusItem.menu = menu;

  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    [self retrieveTMMState];
  });
}

- (void)retrieveTMMState {
  // Check whether temporary monitor mode is available and if we're currently in it.
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn synchronousRemoteObjectProxy]
      checkTemporaryMonitorModePolicyAvailable:^(BOOL available) {
        [self setTemporaryMonitorModePolicyAvailable:available];
      }];
  [[daemonConn synchronousRemoteObjectProxy]
      temporaryMonitorModeSecondsRemaining:^(NSNumber *seconds) {
        if (seconds) {
          NSDate *expiry = [NSDate dateWithTimeIntervalSinceNow:[seconds intValue]];
          [self enterMonitorModeWithExpiration:expiry];
        }
      }];
  [daemonConn invalidate];
}

- (void)removeStatusBarItem {
  if (self.statusItem) {
    [[NSStatusBar systemStatusBar] removeStatusItem:self.statusItem];
    self.statusItem = nil;
    self.syncMenuItem = nil;
    self.resetSilencesMenuItem = nil;
    self.temporaryMonitorModeMenuItem = nil;
    self.temporaryMonitorModeRefreshItem = nil;
  }
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
  [[daemonConn synchronousRemoteObjectProxy]
      requestTemporaryMonitorModeWithDurationMinutes:0
                                               reply:^(uint32 minutes, NSError *err) {
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
        [self notificationWithIdentifier:@"tmm_cancel_failed_notification"
                                 andBody:err.localizedDescription];
      }
    }];
  } else {
    [[daemonConn synchronousRemoteObjectProxy]
        requestTemporaryMonitorModeWithDurationMinutes:0
                                                 reply:^(uint32 minutes, NSError *err) {
                                                   if (err) {
                                                     NSString *failureDescription;
                                                     switch (err.code) {
                                                       case SNTErrorCodeTMMNoPolicy:
                                                         failureDescription = NSLocalizedString(
                                                             @"Failed to enter temporary monitor "
                                                             @"mode: this machine does not "
                                                             @"currently have a policy allowing "
                                                             @"temporary monitor mode",
                                                             @"Error message shown when user tries "
                                                             @"to enter TMM mode without a policy");
                                                         break;
                                                       case SNTErrorCodeTMMNotInLockdown:
                                                         failureDescription = NSLocalizedString(
                                                             @"Failed to enter temporary monitor "
                                                             @"mode: not currently in lockdown",
                                                             @"Error message shown when user tries "
                                                             @"to enter TMM while not in lockdown");
                                                         break;
                                                       case SNTErrorCodeTMMAuthFailed:
                                                         failureDescription = NSLocalizedString(
                                                             @"Failed to enter temporary monitor "
                                                             @"mode: authorization failed",
                                                             @"Error message shown when user tries "
                                                             @"to enter TMM but authorization "
                                                             @"failed");
                                                         break;
                                                       case SNTErrorCodeTMMInvalidSyncServer:
                                                         failureDescription = NSLocalizedString(
                                                             @"Failed to enter temporary monitor "
                                                             @"mode: not using a supported sync "
                                                             @"server",
                                                             @"Error message shown when user tries "
                                                             @"to enter TMM while not using "
                                                             @"Workshop");
                                                         break;
                                                       default:
                                                         failureDescription = NSLocalizedString(
                                                             @"Failed to enter temporary monitor "
                                                             @"mode: an unknown error occurred",
                                                             @"Error shown when user tries to "
                                                             @"enter TMM and an unknown error "
                                                             @"occurred.");
                                                         break;
                                                     }
                                                     [self
                                                         notificationWithIdentifier:
                                                             @"tmm_enter_failed_notification"
                                                                            andBody:
                                                                                failureDescription];
                                                   }
                                                 }];
  }
  [daemonConn invalidate];
}

- (void)resetSilencesMenuItemClicked:(id)sender {
  // Check if we have any visible windows (excluding status bar windows).
  // If not, ensure we stay in accessory mode to avoid a dock icon "blip".
  if (![self hasVisibleWindows]) {
    NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
  }

  NSAlert *alert = [[NSAlert alloc] init];
  alert.messageText = NSLocalizedString(@"Reset Silenced Notifications",
                                        @"Title for reset silences confirmation dialog");
  alert.informativeText =
      NSLocalizedString(@"Are you sure you want to reset all notification silences? "
                        @"You will start receiving notifications for previously silenced events.",
                        @"Message for reset silences confirmation dialog");
  [alert addButtonWithTitle:NSLocalizedString(@"Reset", @"Reset button title")];
  [alert addButtonWithTitle:NSLocalizedString(@"Cancel", @"Cancel button title")];

  // Ensure the alert appears above other app windows (which use NSModalPanelWindowLevel).
  [alert layout];
  alert.window.level = NSPopUpMenuWindowLevel;

  if ([alert runModal] == NSAlertFirstButtonReturn) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud removeObjectForKey:kNotificationSilencesKey];
  }

  // Modal alerts don't trigger NSWindowWillCloseNotification, so manually restore
  // accessory policy after the alert dismisses (if no other windows are visible).
  // Re-check since windows may have opened/closed while the modal was displayed.
  if (![self hasVisibleWindows]) {
    NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
  }
}

- (BOOL)hasVisibleWindows {
  __block BOOL hasVisibleWindows = NO;
  [NSApp enumerateWindowsWithOptions:0
                          usingBlock:^(NSWindow *_Nonnull window, BOOL *_Nonnull stop) {
                            if ([window isKindOfClass:NSClassFromString(@"NSStatusBarWindow")]) {
                              return;
                            }
                            *stop = hasVisibleWindows = window.visible;
                          }];
  return hasVisibleWindows;
}

- (void)syncMenuItemClicked:(id)sender {
  // Disable the sync menu item until we're done.
  self.syncMenuItem.target = nil;

  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    // Connect to sync service and call sync.
    MOLXPCConnection *ss = [SNTXPCSyncServiceInterface configuredConnection];
    ss.invalidationHandler = ^(void) {
      dispatch_async(dispatch_get_main_queue(), ^{
        self.syncMenuItem.target = self;
        // Tint the icon red to indicate failure
        [self setMenuItemImageWithTintColor:[NSColor colorNamed:@"SyncFailureColor"]];
        [NSTimer scheduledTimerWithTimeInterval:2.0
                                        repeats:NO
                                          block:^(NSTimer *_Nonnull timer) {
                                            [self setMenuItemImageWithTintColor:nil];
                                          }];
        [self notificationWithIdentifier:@"sync_result_notification"
                                 andBody:NSLocalizedString(
                                             @"Sync failed",
                                             @"Notification message shown when a sync fails")];
      });
    };
    [ss resume];
    [[ss synchronousRemoteObjectProxy]
        syncWithLogListener:nil
                   syncType:SNTSyncTypeNormal
                      reply:^(SNTSyncStatusType status) {
                        dispatch_async(dispatch_get_main_queue(), ^{
                          self.syncMenuItem.target = self;

                          if (status == SNTSyncStatusTypeSuccess) {
                            // Tint the icon green to indicate success
                            [self
                                setMenuItemImageWithTintColor:[NSColor
                                                                  colorNamed:@"SyncSuccessColor"]];
                            [self notificationWithIdentifier:@"sync_result_notification"
                                                     andBody:NSLocalizedString(
                                                                 @"Sync completed successfully",
                                                                 @"Notification message shown when "
                                                                 @"a sync completes successfully")];
                          } else {
                            // Tint the icon red to indicate failure
                            [self
                                setMenuItemImageWithTintColor:[NSColor
                                                                  colorNamed:@"SyncFailureColor"]];
                            [self notificationWithIdentifier:@"sync_result_notification"
                                                     andBody:NSLocalizedString(
                                                                 @"Sync failed",
                                                                 @"Notification message shown when "
                                                                 @"a sync fails")];
                          }

                          [NSTimer
                              scheduledTimerWithTimeInterval:2.0
                                                     repeats:NO
                                                       block:^(NSTimer *_Nonnull timer) {
                                                         [self setMenuItemImageWithTintColor:nil];
                                                       }];
                        });
                        ss.invalidationHandler = nil;
                        [ss invalidate];
                      }];
  });
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
                                   NSString *title =
                                       [dcf stringFromDate:[NSDate now]
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

- (void)setTemporaryMonitorModePolicyAvailable:(BOOL)available {
  self.temporaryMonitorModeMenuItem.hidden = !available;
  self.temporaryMonitorModeRefreshItem.hidden = !available;
}

- (NSMenuItem *)menuItemWithTitle:(NSString *)title andAction:(SEL)action {
  NSMenuItem *i = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:@""];
  i.target = self;
  return i;
}

- (BOOL)validateMenuItem:(NSMenuItem *)menuItem {
  if (menuItem == self.resetSilencesMenuItem) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSDictionary *silences = [ud objectForKey:kNotificationSilencesKey];
    return silences.count > 0;
  }
  return YES;
}

- (void)notificationWithIdentifier:(NSString *)identifier andBody:(NSString *)body {
  UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
  content.title = @"Santa";
  content.body = body;

  UNNotificationRequest *req = [UNNotificationRequest requestWithIdentifier:identifier
                                                                    content:content
                                                                    trigger:nil];
  [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:req
                                                         withCompletionHandler:nil];
}

#pragma mark - User Menu Item Override

- (NSNumber *)userMenuItemEnabledOverride {
  return [[NSUserDefaults standardUserDefaults] objectForKey:kEnableMenuItemUserOverride];
}

/// Returns YES if the menu item should be enabled, considering user override and admin config.
- (BOOL)effectiveMenuItemEnabled {
  NSNumber *userOverride = [self userMenuItemEnabledOverride];
  return userOverride ? [userOverride boolValue] : [SNTConfigurator configurator].enableMenuItem;
}

/// The override state was changed, re-evaluate whether the menu item should be shown.
- (void)userMenuItemOverrideChanged:(NSNotification *)notification {
  BOOL enabled = [self effectiveMenuItemEnabled];
  if (enabled) {
    [self setupStatusBarItem];
  } else {
    [self removeStatusBarItem];
  }
}

@end
