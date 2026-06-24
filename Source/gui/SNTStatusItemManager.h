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

#import <Cocoa/Cocoa.h>

///
/// Manages the status bar item for Santa, including its menu and title updates
///
@interface SNTStatusItemManager : NSObject

/// The status bar item
@property(strong, nonatomic, readonly) NSStatusItem* statusItem;

/// Updates the title displayed in the status bar
/// @param title The new title to display
- (void)updateTitle:(NSString*)title;

- (void)enterMonitorModeWithExpiration:(NSDate*)expiration;
- (void)leaveMonitorMode;

/// Sets whether the temporary monitor mode menu items should be visible
/// @param available YES if a TMM policy is available, NO otherwise
- (void)setTemporaryMonitorModePolicyAvailable:(BOOL)available;

- (void)enterAdminModeWithExpiration:(NSDate*)expiration;
- (void)leaveAdminMode;

/// Sets whether the temporary admin mode menu items should be visible
/// @param available YES if a TAM policy is available and the user is not already an admin
- (void)setTemporaryAdminModeAvailable:(BOOL)available;

/// Notifies the daemon that the current user's session has resigned active (fast user switch).
/// If an admin session is active for this user, asks the daemon to end it with SessionEnded.
- (void)temporaryAdminModeSessionResignedActive;

/// Re-queries the daemon for live Monitor/Admin session and availability state. Called when the
/// user's session becomes active again (e.g. returning from fast user switching) to reconcile any
/// daemon notifications missed while the session was inactive.
- (void)reconcileTimedModeState;

@end
