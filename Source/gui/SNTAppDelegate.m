/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/gui/SNTAppDelegate.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/gui/SNTAboutWindowController.h"
#import "Source/gui/SNTFileInfoView-Swift.h"
#import "Source/gui/SNTNotificationManager.h"

@interface SNTAppDelegate ()
@property SNTAboutWindowController *aboutWindowController;
@property SNTNotificationManager *notificationManager;
@property MOLXPCConnection *daemonListener;
@end

@implementation SNTAppDelegate

#pragma mark App Delegate methods

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
  if ([SNTConfigurator configurator].enableAPNS) {
    [NSApp registerForRemoteNotifications];
  }

  [self setupMenu];
  self.notificationManager = [[SNTNotificationManager alloc] init];

  NSNotificationCenter *workspaceNotifications = [[NSWorkspace sharedWorkspace] notificationCenter];

  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidResignActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
                                    self.daemonListener.invalidationHandler = nil;
                                    [self.daemonListener invalidate];
                                    self.daemonListener = nil;
                                  }];
  [workspaceNotifications addObserverForName:NSWorkspaceSessionDidBecomeActiveNotification
                                      object:nil
                                       queue:[NSOperationQueue currentQueue]
                                  usingBlock:^(NSNotification *note) {
                                    [self attemptDaemonReconnection];
                                  }];

  // Watch for windows being closed, so that we can restore the activation policy to accessory.
  [[NSNotificationCenter defaultCenter] addObserver:self
                                           selector:@selector(aWindowWillClose:)
                                               name:NSWindowWillCloseNotification
                                             object:nil];

  [self createDaemonConnection];
}

- (void)applicationDidBecomeActive:(NSNotification *)notification {
  NSApp.activationPolicy = NSApplicationActivationPolicyRegular;
}

- (void)aWindowWillClose:(NSNotification *)notification {
  NSWindow *closingWindow = notification.object;
  __block BOOL hasVisibleWindows = NO;
  [NSApp enumerateWindowsWithOptions:0
                          usingBlock:^(NSWindow *_Nonnull window, BOOL *_Nonnull stop) {
                            if (window == closingWindow) return;
                            *stop = hasVisibleWindows = window.visible;
                          }];
  if (!hasVisibleWindows) {
    NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
  }
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
  if (!self.aboutWindowController) {
    self.aboutWindowController = [[SNTAboutWindowController alloc] init];
  }
  [self.aboutWindowController showWindow:self];
  return NO;
}

- (void)application:(NSApplication *)sender openURLs:(NSArray<NSURL *> *)urls {
  // Handle requests to open other applications, either by being dropped onto
  // the app's dock icon or dropped onto the About window. Unfortunately,
  // dropping onto the app icon doesn't work.
  for (NSURL *url in urls) {
    SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:url.path];
    if (fileInfo) {
      NSViewController *vc = [SNTFileInfoViewFactory createWithFileInfo:fileInfo];

      NSWindow *window = [[NSWindow alloc]
          initWithContentRect:NSMakeRect(0, 0, 0, 0)
                    styleMask:NSWindowStyleMaskClosable | NSWindowStyleMaskTitled |
                              NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                      backing:NSBackingStoreBuffered
                        defer:NO];
      window.contentViewController = vc;
      window.releasedWhenClosed = NO;
      window.title =
          [NSString stringWithFormat:@"File info for %@",
                                     fileInfo.bundleName ?: fileInfo.path.lastPathComponent];
      [window makeKeyAndOrderFront:nil];
      [window center];
    }
  }
}

#pragma mark Connection handling

- (void)createDaemonConnection {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  WEAKIFY(self);

  // Create listener for return connection from daemon.
  NSXPCListener *listener = [NSXPCListener anonymousListener];
  self.daemonListener = [[MOLXPCConnection alloc] initServerWithListener:listener];
  self.daemonListener.privilegedInterface = [SNTXPCNotifierInterface notifierInterface];
  self.daemonListener.exportedObject = self.notificationManager;
  self.daemonListener.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  self.daemonListener.invalidationHandler = ^{
    STRONGIFY(self);
    [self attemptDaemonReconnection];
  };
  [self.daemonListener resume];

  // This listener will also handle bundle service requests to update the GUI.
  // When initializing connections with santabundleservice, the notification manager
  // will send along the endpoint so santabundleservice knows where to find us.
  self.notificationManager.notificationListener = listener.endpoint;

  // Tell daemon to connect back to the above listener.
  MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
  [daemonConn resume];
  [[daemonConn remoteObjectProxy] setNotificationListener:listener.endpoint];
  [daemonConn invalidate];

  // Now wait for the connection to come in.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [self attemptDaemonReconnection];
  } else {
    // Let the sync service know the APNS token may have changed. The sync service will call back on
    // the above listener to get the updated token.
    [self.notificationManager APNSTokenChanged];
  }
}

- (void)attemptDaemonReconnection {
  self.daemonListener.invalidationHandler = nil;
  [self.daemonListener invalidate];
  [self performSelectorInBackground:@selector(createDaemonConnection) withObject:nil];
}

#pragma mark Menu Management

- (void)setupMenu {
  // Whilst the user will never see the menu, having one with the Copy and Select All options
  // allows the shortcuts for these items to work, which is useful for being able to copy
  // information from notifications. The mainMenu must have a nested menu for this to work properly.
  NSMenu *mainMenu = [[NSMenu alloc] init];
  NSMenu *editMenu = [[NSMenu alloc] init];
  [editMenu addItemWithTitle:@"Copy" action:@selector(copy:) keyEquivalent:@"c"];
  [editMenu addItemWithTitle:@"Select All" action:@selector(selectAll:) keyEquivalent:@"a"];
  NSMenuItem *editMenuItem = [[NSMenuItem alloc] init];
  [editMenuItem setSubmenu:editMenu];
  [mainMenu addItem:editMenuItem];
  [NSApp setMainMenu:mainMenu];
}

#pragma mark Push Notifications

- (void)application:(NSApplication *)application
    didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)tokenData {
  NSMutableString *deviceToken = [NSMutableString stringWithCapacity:tokenData.length * 2];
  const unsigned char *bytes = tokenData.bytes;
  for (NSUInteger i = 0; i < tokenData.length; ++i) {
    [deviceToken appendFormat:@"%02x", bytes[i]];
  }
  LOGD(@"APNS Token: %@", deviceToken);
  [self.notificationManager didRegisterForAPNS:deviceToken];
}

- (void)application:(NSApplication *)application
    didFailToRegisterForRemoteNotificationsWithError:(NSError *)error {
  LOGE(@"Failed to register with APNS: %@", error);
}

- (void)application:(NSApplication *)application
    didReceiveRemoteNotification:(NSDictionary<NSString *, id> *)message {
  LOGD(@"APNS Message: %@", message);
  MOLXPCConnection *syncConn = [SNTXPCSyncServiceInterface configuredConnection];
  [syncConn resume];
  [[syncConn remoteObjectProxy] handleAPNSMessage:message];
  [syncConn invalidate];
}

@end
