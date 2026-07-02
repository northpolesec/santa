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

#import "Source/gui/SNTStatusItemManager.h"

#import <UserNotifications/UserNotifications.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLiteDetector.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTNotificationManager.h"

// Per-mode descriptor: the titles, the request/cancel XPC calls, and the
// error-message map that differ between Temporary Monitor Mode and Temporary
// Admin Mode. The shared menu/countdown code is driven by this.
@interface SNTTimedModeDescriptor : NSObject
@property(copy) NSString* enterTitle;
@property(copy) NSString* leaveTitle;
@property(copy) NSString* refreshTitle;
// Short label used to disambiguate this mode's countdown in the status-bar title
// when more than one timed mode is active simultaneously.
@property(copy) NSString* statusLabel;
@property(copy) void (^request)(id proxy, void (^reply)(uint32_t minutes, NSError* err));
@property(copy) void (^cancel)(id proxy, void (^reply)(NSError* err));
@property(copy) NSString* (^messageForError)(NSInteger code);
@end

@implementation SNTTimedModeDescriptor
@end

// Per-mode mutable state: the menu items, the countdown timer, and the current
// expiration. One instance per mode; the shared code operates on whichever state
// corresponds to the menu item that was clicked.
@interface SNTTimedModeState : NSObject
@property(strong) SNTTimedModeDescriptor* descriptor;
@property NSMenuItem* menuItem;
@property NSMenuItem* refreshItem;
@property(atomic, strong) NSTimer* timer;
@property(atomic, strong) NSDate* expiration;
@end

@implementation SNTTimedModeState
@end

@interface SNTStatusItemManager () <NSMenuDelegate>
@property SNTAboutWindowController* aboutWindowController;
@property(strong, nonatomic, readwrite) NSStatusItem* statusItem;
@property SNTKVOManager* kvoEnableMenuItem;

// Sync items
@property NSMenuItem* syncMenuItem;

// Temporary mode (Monitor / Admin) state. One descriptor-backed state per mode;
// the shared menu/countdown code operates on whichever the user interacts with.
@property(strong) SNTTimedModeState* tmmState;
@property(strong) SNTTimedModeState* tamState;
@property(atomic, strong) NSTimer* iconTintTimer;

// Reset silences item
@property NSMenuItem* resetSilencesMenuItem;

// Countdown formatter
@property(nonatomic, strong) NSDateComponentsFormatter* countdownFormatter;

// Last status-bar title pushed via refreshStatusTitle, used to suppress redundant
// updates (the per-mode timers fire every 5s but the displayed units change slowly).
@property(copy) NSString* lastStatusTitle;
@end

static NSString* const kNotificationSilencesKey = @"SilencedNotifications";

@implementation SNTStatusItemManager

- (instancetype)init {
  self = [super init];
  if (self) {
    self.countdownFormatter = [[NSDateComponentsFormatter alloc] init];
    self.countdownFormatter.allowedUnits =
        NSCalendarUnitDay | NSCalendarUnitHour | NSCalendarUnitMinute;
    self.countdownFormatter.unitsStyle = NSDateComponentsFormatterUnitsStyleAbbreviated;

    self.tmmState = [[SNTTimedModeState alloc] init];
    self.tmmState.descriptor = [self monitorModeDescriptor];
    self.tamState = [[SNTTimedModeState alloc] init];
    self.tamState.descriptor = [self adminModeDescriptor];

    [self setupStatusBarItem];

    // Watch for changes to the EnableMenuItem configuration key
    WEAKIFY(self);
    self.kvoEnableMenuItem =
        [[SNTKVOManager alloc] initWithObject:[SNTConfigurator configurator]
                                     selector:@selector(enableMenuItem)
                                         type:[NSNumber class]
                                     callback:^(NSNumber* oldValue, NSNumber* newValue) {
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

- (SNTTimedModeDescriptor*)monitorModeDescriptor {
  SNTTimedModeDescriptor* d = [[SNTTimedModeDescriptor alloc] init];
  d.enterTitle = @"Enter Temporary Monitor Mode";
  d.leaveTitle = @"Leave Temporary Monitor Mode";
  d.refreshTitle = @"Refresh Temporary Monitor Mode";
  d.statusLabel = @"Monitor";
  d.request = ^(id proxy, void (^reply)(uint32_t, NSError*)) {
    [proxy requestTemporaryMonitorModeWithDurationMinutes:0 reply:reply];
  };
  d.cancel = ^(id proxy, void (^reply)(NSError*)) {
    [proxy cancelTemporaryMonitorMode:reply];
  };
  d.messageForError = ^NSString*(NSInteger code) {
    switch (code) {
      case SNTErrorCodeTMMNoPolicy:
        return NSLocalizedString(
            @"Failed to enter temporary monitor mode: this machine does not currently have a "
            @"policy allowing temporary monitor mode",
            @"Error message shown when user tries to enter TMM mode without a policy");
      case SNTErrorCodeTMMNotInLockdown:
        return NSLocalizedString(
            @"Failed to enter temporary monitor mode: not currently in lockdown",
            @"Error message shown when user tries to enter TMM while not in lockdown");
      case SNTErrorCodeTMMAuthFailed:
        return NSLocalizedString(
            @"Failed to enter temporary monitor mode: authorization failed",
            @"Error message shown when user tries to enter TMM but authorization failed");
      case SNTErrorCodeTMMInvalidSyncServer:
        return NSLocalizedString(
            @"Failed to enter temporary monitor mode: not using a supported sync server",
            @"Error message shown when user tries to enter TMM while not using Workshop");
      default:
        return NSLocalizedString(
            @"Failed to enter temporary monitor mode: an unknown error occurred",
            @"Error shown when user tries to enter TMM and an unknown error occurred.");
    }
  };
  return d;
}

- (SNTTimedModeDescriptor*)adminModeDescriptor {
  SNTTimedModeDescriptor* d = [[SNTTimedModeDescriptor alloc] init];
  d.enterTitle = @"Request Admin Privileges";
  d.leaveTitle = @"Leave Admin Privileges";
  d.refreshTitle = @"Refresh Admin Privileges";
  d.statusLabel = @"Admin";
  d.request = ^(id proxy, void (^reply)(uint32_t, NSError*)) {
    [proxy requestTemporaryAdminModeWithDurationMinutes:0 reply:reply];
  };
  d.cancel = ^(id proxy, void (^reply)(NSError*)) {
    [proxy cancelTemporaryAdminMode:reply];
  };
  d.messageForError = ^NSString*(NSInteger code) {
    switch (code) {
      case SNTErrorCodeTAMNoPolicy:
        return NSLocalizedString(
            @"Failed to request admin privileges: this machine does not currently allow "
            @"temporary admin elevation",
            @"Error shown when requesting admin without a policy");
      case SNTErrorCodeTAMAlreadyAdmin:
        return NSLocalizedString(
            @"Failed to request admin privileges: you are already an administrator",
            @"Error shown when a natural admin requests elevation");
      case SNTErrorCodeTAMAuthFailed:
        return NSLocalizedString(@"Failed to request admin privileges: authorization failed",
                                 @"Error shown when admin elevation authorization fails");
      case SNTErrorCodeTAMJustificationRequired:
        return NSLocalizedString(@"Failed to request admin privileges: a justification is required",
                                 @"Error shown when a justification is required but not given");
      case SNTErrorCodeTAMSessionAlreadyActive:
        return NSLocalizedString(
            @"Failed to request admin privileges: a session is already active for another user",
            @"Error shown when another user already has an active session");
      case SNTErrorCodeTAMMembershipChangeFailed:
        return NSLocalizedString(
            @"Failed to request admin privileges: the admin group membership change failed",
            @"Error shown when the group membership change fails");
      default:
        return NSLocalizedString(@"Failed to request admin privileges: an unknown error occurred",
                                 @"Error shown when admin elevation fails with an unknown error");
    }
  };
  return d;
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
  NSMenu* menu = [[NSMenu alloc] init];

  // Add version string and about menu item
  NSString* santaVersionString = [NSString
      stringWithFormat:@"Santa v%@%@",
                       [[NSBundle mainBundle] infoDictionary][@"CFBundleShortVersionString"],
                       santa::SNTIsLiteInstall() ? @" (Lite)" : @""];
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

  // Add temporary-mode (Monitor / Admin) items, hidden by default until
  // availability is verified.
  [self addMenuItemsForState:self.tmmState toMenu:menu];
  [self addMenuItemsForState:self.tamState toMenu:menu];

  menu.delegate = self;
  self.statusItem.menu = menu;

  [self refreshAllTimedModeStateAsync];
}

- (void)addMenuItemsForState:(SNTTimedModeState*)state toMenu:(NSMenu*)menu {
  state.menuItem = [self menuItemWithTitle:state.descriptor.enterTitle
                                 andAction:@selector(timedModeMenuItemClicked:)];
  state.menuItem.hidden = YES;
  [menu addItem:state.menuItem];

  state.refreshItem = [self menuItemWithTitle:state.descriptor.refreshTitle
                                    andAction:@selector(timedModeRefreshItemClicked:)];
  state.refreshItem.target = nil;
  state.refreshItem.hidden = YES;
  [menu addItem:state.refreshItem];
}

// Resolve which mode's state a clicked menu item belongs to.
- (SNTTimedModeState*)stateForSender:(id)sender {
  if (sender == self.tamState.menuItem || sender == self.tamState.refreshItem) {
    return self.tamState;
  }
  return self.tmmState;
}

// Vend a resumed synchronous control proxy to `block`, then invalidate the connection.
// The synchronous proxy blocks until each reply runs, so the connection stays valid for
// the duration of `block`; this centralizes the connect/resume/invalidate lifecycle.
- (void)withControlProxy:(void (^)(id proxy))block {
  MOLXPCConnection* daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  block([daemonConn synchronousRemoteObjectProxy]);
  [daemonConn invalidate];
}

// Re-query the daemon for live Monitor + Admin session/availability state off the main thread.
- (void)refreshAllTimedModeStateAsync {
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    [self retrieveMonitorModeState];
    [self retrieveAdminModeState];
  });
}

- (void)retrieveMonitorModeState {
  // The synchronous control proxy runs these reply blocks on this background queue, so every
  // helper that mutates AppKit state (menu items, the countdown timer, the status title) must be
  // marshaled to the main thread. Each block is enqueued in call order, so main-queue FIFO
  // preserves the ordering the UI depends on.
  [self withControlProxy:^(id proxy) {
    [proxy checkTemporaryMonitorModePolicyAvailable:^(BOOL available) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self setAvailable:available forState:self.tmmState];
      });
    }];
    [proxy temporaryMonitorModeSecondsRemaining:^(NSNumber* seconds) {
      dispatch_async(dispatch_get_main_queue(), ^{
        if (seconds) {
          [self enterModeWithExpiration:[NSDate dateWithTimeIntervalSinceNow:[seconds intValue]]
                               forState:self.tmmState];
        } else if (self.tmmState.expiration) {
          // The daemon reports no active session but the GUI still shows one (a leave
          // notification can be missed while this session is inactive, e.g. fast user
          // switching). Clear the stale countdown.
          [self leaveModeForState:self.tmmState];
        }
      });
    }];
  }];
}

- (void)retrieveAdminModeState {
  // See retrieveMonitorModeState: reply blocks run on a background queue, so AppKit mutations are
  // marshaled to the main queue. Determine the active session first (sets the expiration / "Leave"
  // title), then compute visibility (which depends on whether a session is active) -- main-queue
  // FIFO keeps that ordering.
  [self withControlProxy:^(id proxy) {
    [proxy temporaryAdminModeSecondsRemaining:^(NSNumber* seconds) {
      dispatch_async(dispatch_get_main_queue(), ^{
        if (seconds) {
          [self enterModeWithExpiration:[NSDate dateWithTimeIntervalSinceNow:[seconds intValue]]
                               forState:self.tamState];
        } else if (self.tamState.expiration) {
          // The daemon reports no active session but the GUI still shows one (a leave
          // notification can be missed while this session is inactive, e.g. fast user
          // switching). Clear the stale countdown.
          [self leaveModeForState:self.tamState];
        }
      });
    }];
    [proxy checkTemporaryAdminModeAvailable:^(BOOL available, BOOL alreadyAdmin) {
      dispatch_async(dispatch_get_main_queue(), ^{
        [self setAdminItemVisibleWhenAvailable:available alreadyAdmin:alreadyAdmin];
      });
    }];
  }];
}

// The admin item is visible while a session is active (so it can be left — note an
// active session makes the user a group-80 member, so `alreadyAdmin` is true) or
// when elevation is available and the user is not already an admin.
- (void)setAdminItemVisibleWhenAvailable:(BOOL)available alreadyAdmin:(BOOL)alreadyAdmin {
  BOOL active = (self.tamState.expiration != nil);
  [self setAvailable:(active || (available && !alreadyAdmin)) forState:self.tamState];
}

// Re-query Temporary Admin Mode availability against live state each time the menu
// opens. The user's admin status and policy availability can change after launch
// (e.g. dropping admin) between sync pushes. checkTemporaryAdminModeAvailable: does not
// re-enter the GUI, so a synchronous call here is safe (unlike the request path, which is
// dispatched off the main thread).
- (void)menuNeedsUpdate:(NSMenu*)menu {
  [self withControlProxy:^(id proxy) {
    [proxy checkTemporaryAdminModeAvailable:^(BOOL available, BOOL alreadyAdmin) {
      [self setAdminItemVisibleWhenAvailable:available alreadyAdmin:alreadyAdmin];
    }];
  }];
}

// Re-query the daemon for live Monitor/Admin session + availability state. Called when this
// user's session becomes active again (e.g. returning from fast user switching), where daemon
// push notifications (enter/leave/availability) sent while the session was inactive were missed.
// Uses retrieve*ModeState's own short-lived control connection, so it does not depend on the
// daemon->GUI notifier listener (which is torn down while the session is inactive).
- (void)reconcileTimedModeState {
  if (!self.statusItem) {
    return;
  }
  [self refreshAllTimedModeStateAsync];
}

- (void)removeStatusBarItem {
  if (self.statusItem) {
    [[NSStatusBar systemStatusBar] removeStatusItem:self.statusItem];
    self.statusItem = nil;
    self.syncMenuItem = nil;
    self.resetSilencesMenuItem = nil;
    self.tmmState.menuItem = nil;
    self.tmmState.refreshItem = nil;
    self.tamState.menuItem = nil;
    self.tamState.refreshItem = nil;
  }
}

- (void)updateTitle:(NSString*)title {
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

- (void)timedModeRefreshItemClicked:(id)sender {
  SNTTimedModeState* state = [self stateForSender:sender];
  SNTTimedModeDescriptor* descriptor = state.descriptor;
  // Run off the main thread: the request re-enters the GUI synchronously (the daemon
  // calls back to authorize, which must present UI on the main thread). Blocking the
  // main thread here would deadlock against that callback.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    [self withControlProxy:^(id proxy) {
      descriptor.request(proxy, ^(uint32_t minutes, NSError* err) {
        if (err) {
          NSLog(@"Failed to refresh timed mode: %@", err.localizedDescription);
        }
      });
    }];
  });
}

- (void)timedModeMenuItemClicked:(id)sender {
  SNTTimedModeState* state = [self stateForSender:sender];
  SNTTimedModeDescriptor* descriptor = state.descriptor;
  // Run off the main thread: the request re-enters the GUI synchronously (the daemon
  // calls back to authorize, which must present UI on the main thread). Blocking the
  // main thread here would deadlock against that callback.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    [self withControlProxy:^(id proxy) {
      if (state.expiration) {
        descriptor.cancel(proxy, ^(NSError* err) {
          if (err) {
            [self notificationWithIdentifier:@"timed_mode_cancel_failed_notification"
                                     andBody:err.localizedDescription];
          }
        });
      } else {
        descriptor.request(proxy, ^(uint32_t minutes, NSError* err) {
          if (err) {
            [self temporarilyTintIconWithColor:[NSColor colorNamed:@"SyncFailureColor"]];
            [self notificationWithIdentifier:@"timed_mode_enter_failed_notification"
                                     andBody:descriptor.messageForError(err.code)];
          }
        });
      }
    }];
  });
}

- (void)resetSilencesMenuItemClicked:(id)sender {
  // Check if we have any visible windows (excluding status bar windows).
  // If not, ensure we stay in accessory mode to avoid a dock icon "blip".
  if (![self hasVisibleWindows]) {
    NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
  }

  NSAlert* alert = [[NSAlert alloc] init];
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
    NSUserDefaults* ud = [NSUserDefaults standardUserDefaults];
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
                          usingBlock:^(NSWindow* _Nonnull window, BOOL* _Nonnull stop) {
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
    MOLXPCConnection* ss = [SNTXPCSyncServiceInterface configuredConnection];
    ss.invalidationHandler = ^(void) {
      dispatch_async(dispatch_get_main_queue(), ^{
        self.syncMenuItem.target = self;
        [self temporarilyTintIconWithColor:[NSColor colorNamed:@"SyncFailureColor"]];
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
                            [self temporarilyTintIconWithColor:[NSColor
                                                                   colorNamed:@"SyncSuccessColor"]];
                            [self notificationWithIdentifier:@"sync_result_notification"
                                                     andBody:NSLocalizedString(
                                                                 @"Sync completed successfully",
                                                                 @"Notification message shown when "
                                                                 @"a sync completes successfully")];
                          } else {
                            [self temporarilyTintIconWithColor:[NSColor
                                                                   colorNamed:@"SyncFailureColor"]];
                            [self notificationWithIdentifier:@"sync_result_notification"
                                                     andBody:NSLocalizedString(
                                                                 @"Sync failed",
                                                                 @"Notification message shown when "
                                                                 @"a sync fails")];
                          }
                        });
                        ss.invalidationHandler = nil;
                        [ss invalidate];
                      }];
  });
}

- (void)enterModeWithExpiration:(NSDate*)expiration forState:(SNTTimedModeState*)state {
  state.expiration = expiration;

  // Invalidate any existing timer
  [state.timer invalidate];

  // Update menu options
  state.menuItem.title = state.descriptor.leaveTitle;
  state.refreshItem.target = self;

  // Create a timer that updates the countdown display. Using a 5 second interval is sufficient
  // since the displayed units are days/hours/minutes which change infrequently. The timer only
  // detects this mode's expiry; the title itself is composed from all active modes by
  // refreshStatusTitle so concurrent TMM/TAM sessions are both shown.
  dispatch_async(dispatch_get_main_queue(), ^{
    // Fire immediately to set the initial title, then repeat every 5 seconds.
    state.timer =
        [NSTimer scheduledTimerWithTimeInterval:5.0
                                        repeats:YES
                                          block:^(NSTimer* timer) {
                                            if (!state.expiration ||
                                                [state.expiration timeIntervalSinceNow] <= 0) {
                                              [self leaveModeForState:state];
                                              return;
                                            }
                                            [self refreshStatusTitle];
                                          }];
    [state.timer fire];
  });
}

// Compose the status-bar title from every currently-active timed mode. With a single
// active mode the bare countdown is shown (preserving the original single-mode display);
// with more than one, each countdown is labeled (e.g. "Monitor 4m  ·  Admin 2m") so they
// are distinguishable. This is the single writer of the status-bar title, so concurrent
// modes no longer clobber each other and leaving one mode does not blank the survivor.
- (void)refreshStatusTitle {
  NSMutableArray<SNTTimedModeState*>* active = [NSMutableArray array];
  for (SNTTimedModeState* state in @[ self.tmmState, self.tamState ]) {
    if (state.expiration && [state.expiration timeIntervalSinceNow] > 0) {
      [active addObject:state];
    }
  }

  NSString* title;
  if (active.count == 0) {
    title = @"";
  } else if (active.count == 1) {
    title = [self.countdownFormatter stringFromDate:[NSDate now]
                                             toDate:active.firstObject.expiration];
  } else {
    NSMutableArray<NSString*>* parts = [NSMutableArray array];
    for (SNTTimedModeState* state in active) {
      NSString* countdown = [self.countdownFormatter stringFromDate:[NSDate now]
                                                             toDate:state.expiration];
      [parts
          addObject:[NSString stringWithFormat:@"%@ %@", state.descriptor.statusLabel, countdown]];
    }
    title = [parts componentsJoinedByString:@"  ·  "];
  }

  if (![title isEqualToString:self.lastStatusTitle]) {
    self.lastStatusTitle = title;
    [self updateTitle:title];
  }
}

- (void)leaveModeForState:(SNTTimedModeState*)state {
  [state.timer invalidate];
  state.timer = nil;
  state.expiration = nil;

  // Recompose rather than blanking: another mode may still be active and must keep
  // showing its countdown.
  [self refreshStatusTitle];
  state.menuItem.title = state.descriptor.enterTitle;
  state.refreshItem.target = nil;
}

- (void)setAvailable:(BOOL)available forState:(SNTTimedModeState*)state {
  // Keep the item visible while a session is active so the user always retains an
  // in-menu way to leave, even if a policy update pushes availability=false without
  // cancelling the session (e.g. the policy type drops to Unspecified). The poll path
  // (setAdminItemVisibleWhenAvailable:) already folds `active` into `available`; doing
  // it here too covers the daemon-pushed availability updates, which carry no session
  // state of their own.
  BOOL active = (state.expiration != nil);
  state.menuItem.hidden = !(available || active);
  state.refreshItem.hidden = !(available || active);
}

// Public wrappers used by SNTNotificationManager (daemon-pushed enter/leave/availability).
- (void)enterMonitorModeWithExpiration:(NSDate*)expiration {
  [self enterModeWithExpiration:expiration forState:self.tmmState];
}

- (void)leaveMonitorMode {
  [self leaveModeForState:self.tmmState];
}

- (void)setTemporaryMonitorModePolicyAvailable:(BOOL)available {
  [self setAvailable:available forState:self.tmmState];
}

- (void)enterAdminModeWithExpiration:(NSDate*)expiration {
  [self enterModeWithExpiration:expiration forState:self.tamState];
}

- (void)leaveAdminMode {
  [self leaveModeForState:self.tamState];
}

- (void)setTemporaryAdminModeAvailable:(BOOL)available {
  [self setAvailable:available forState:self.tamState];
}

- (void)temporaryAdminModeSessionResignedActive {
  // Always signal the daemon: the GUI's local view of the session (expiration) can be missing or
  // stale (a leave/enter notification can be dropped while this session is inactive), so it must
  // not gate the resign. The daemon's audit-token uid match against its own active session is
  // authoritative and no-ops if there is nothing to end.
  // Fire-and-forget on a background queue (must not block the main thread, especially during
  // session teardown). The reply is ignored.
  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    [self withControlProxy:^(id proxy) {
      [proxy temporaryAdminModeSessionResignedActive:^(NSError*){
      }];
    }];
  });
}

- (NSMenuItem*)menuItemWithTitle:(NSString*)title andAction:(SEL)action {
  NSMenuItem* i = [[NSMenuItem alloc] initWithTitle:title action:action keyEquivalent:@""];
  i.target = self;
  return i;
}

- (BOOL)validateMenuItem:(NSMenuItem*)menuItem {
  if (menuItem == self.resetSilencesMenuItem) {
    NSUserDefaults* ud = [NSUserDefaults standardUserDefaults];
    NSDictionary* silences = [ud objectForKey:kNotificationSilencesKey];
    return silences.count > 0;
  }
  return YES;
}

- (void)notificationWithIdentifier:(NSString*)identifier andBody:(NSString*)body {
  UNMutableNotificationContent* content = [[UNMutableNotificationContent alloc] init];
  content.title = @"Santa";
  content.body = body;

  UNNotificationRequest* req = [UNNotificationRequest requestWithIdentifier:identifier
                                                                    content:content
                                                                    trigger:nil];
  [[UNUserNotificationCenter currentNotificationCenter] addNotificationRequest:req
                                                         withCompletionHandler:nil];
}

#pragma mark - User Menu Item Override

- (NSNumber*)userMenuItemEnabledOverride {
  return [[NSUserDefaults standardUserDefaults] objectForKey:kEnableMenuItemUserOverride];
}

/// Returns YES if the menu item should be enabled, considering user override and admin config.
- (BOOL)effectiveMenuItemEnabled {
  NSNumber* userOverride = [self userMenuItemEnabledOverride];
  return userOverride ? [userOverride boolValue] : [SNTConfigurator configurator].enableMenuItem;
}

/// The override state was changed, re-evaluate whether the menu item should be shown.
- (void)userMenuItemOverrideChanged:(NSNotification*)notification {
  BOOL enabled = [self effectiveMenuItemEnabled];
  if (enabled) {
    [self setupStatusBarItem];
  } else {
    [self removeStatusBarItem];
  }
}

#pragma mark - Icon Tinting

- (void)temporarilyTintIconWithColor:(NSColor*)color {
  dispatch_async(dispatch_get_main_queue(), ^{
    [self.iconTintTimer invalidate];
    self.iconTintTimer = nil;

    [self setMenuItemImageWithTintColor:color];
    self.iconTintTimer =
        [NSTimer scheduledTimerWithTimeInterval:2.0
                                        repeats:NO
                                          block:^(NSTimer* _Nonnull timer) {
                                            [self setMenuItemImageWithTintColor:nil];
                                            self.iconTintTimer = nil;
                                          }];
  });
}

- (void)setMenuItemImageWithTintColor:(NSColor*)tintColor {
  NSImage* original = [NSImage imageNamed:@"MenuItem"];
  if (!original) return;
  [original setTemplate:YES];
  original.size = NSMakeSize(24.0, 16.0);

  if (!tintColor) {
    self.statusItem.button.image = original;
    return;
  }

  NSImage* tinted = [original copy];
  [tinted lockFocus];
  [tintColor set];
  NSRectFillUsingOperation(NSMakeRect(0, 0, tinted.size.width, tinted.size.height),
                           NSCompositingOperationSourceAtop);
  [tinted unlockFocus];
  [tinted setTemplate:NO];
  self.statusItem.button.image = tinted;
}

@end
