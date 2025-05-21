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

#import "Source/gui/SNTNotificationManager.h"

#import <Foundation/Foundation.h>
#import <UserNotifications/UserNotifications.h>

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigState.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeviceEvent.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/gui/SNTAppDelegate.h"
#import "Source/gui/SNTBinaryMessageWindowController.h"
#import "Source/gui/SNTBinaryMessageWindowView-Swift.h"
#import "Source/gui/SNTDeviceMessageWindowController.h"
#import "Source/gui/SNTFileAccessMessageWindowController.h"
#import "Source/gui/SNTMessageWindowController.h"

@interface SNTNotificationManager ()

///  The currently displayed notification
@property SNTMessageWindowController *currentWindowController;

///  The queue of pending notifications
@property(readonly) NSMutableArray *pendingNotifications;

// A serial queue for holding hashBundleBinaries requests
@property dispatch_queue_t hashBundleBinariesQueue;

// The APNS device token. If configured, the GUI app registers with APNS. Once the registration is
// complete, the app delegate will notify this class. Any pending requests for the token will then
// be processed.
@property(atomic) NSString *APNSDeviceToken;

@end

@implementation SNTNotificationManager

static NSString *const silencedNotificationsKey = @"SilencedNotifications";

- (instancetype)init {
  self = [super init];
  if (self) {
    _pendingNotifications = [[NSMutableArray alloc] init];
    _hashBundleBinariesQueue = dispatch_queue_create("com.northpolesec.santagui.hashbundlebinaries",
                                                     DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

- (void)windowDidCloseSilenceHash:(NSString *)hash withInterval:(NSTimeInterval)interval {
  if (hash) {
    NSDate *d = [[NSDate date] dateByAddingTimeInterval:interval];
    [self updateSilenceDate:d forHash:hash];
  }

  [self.pendingNotifications removeObject:self.currentWindowController];
  self.currentWindowController = nil;

  if (self.pendingNotifications.count) {
    [self showQueuedWindow];
  } else {
    MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
    [bc resume];
    [[bc remoteObjectProxy] spindown];
    [bc invalidate];
    // Remove app from Cmd+Tab and Dock.
    NSApp.activationPolicy = NSApplicationActivationPolicyAccessory;
    [NSApp hide:self];
  }
}

- (void)updateSilenceDate:(NSDate *)date forHash:(NSString *)hash {
  NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
  NSMutableDictionary *d = [[ud objectForKey:silencedNotificationsKey] mutableCopy];
  if (!d) d = [NSMutableDictionary dictionary];
  if (date) {
    d[hash] = date;
  } else {
    [d removeObjectForKey:hash];
  }
  [ud setObject:d forKey:silencedNotificationsKey];
}

- (BOOL)notificationAlreadyQueued:(SNTMessageWindowController *)pendingMsg {
  for (SNTMessageWindowController *msg in self.pendingNotifications) {
    if ([[msg messageHash] isEqual:[pendingMsg messageHash]]) return YES;
  }
  return NO;
}

- (void)queueMessage:(SNTMessageWindowController *)pendingMsg enableSilences:(BOOL)enableSilences {
  // Post a distributed notification, regardless of queue state.
  [self postDistributedNotification:pendingMsg];

  // If GUI is in silent mode or if there's already a notification queued for
  // this message, don't do anything else.
  if ([SNTConfigurator configurator].enableSilentMode) return;

  dispatch_async(dispatch_get_main_queue(), ^{
    if ([self notificationAlreadyQueued:pendingMsg]) {
      // Make sure we clear the reply block so we don't leak memory.
      if ([pendingMsg isKindOfClass:[SNTBinaryMessageWindowController class]]) {
        SNTBinaryMessageWindowController *bmwc = (SNTBinaryMessageWindowController *)pendingMsg;
        bmwc.replyBlock(NO);
      }
      return;
    }

    // See if this message has been user-silenced.
    if (enableSilences) {
      NSString *messageHash = [pendingMsg messageHash];
      NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
      NSDate *silenceDate = [ud objectForKey:silencedNotificationsKey][messageHash];
      if ([silenceDate isKindOfClass:[NSDate class]]) {
        switch ([silenceDate compare:[NSDate date]]) {
          case NSOrderedDescending:
            LOGI(@"Notification silence: dropping notification for %@", messageHash);
            return;
          case NSOrderedAscending:
            LOGI(@"Notification silence: silence has expired, deleting");
            [self updateSilenceDate:nil forHash:messageHash];
            break;
          default: break;
        }
      }
    }

    pendingMsg.delegate = self;
    [self.pendingNotifications addObject:pendingMsg];

    if (!self.currentWindowController) {
      // Add app to Cmd+Tab and Dock.
      NSApp.activationPolicy = NSApplicationActivationPolicyRegular;
      [self showQueuedWindow];
    }
  });
}

// For blocked execution notifications, post an NSDistributedNotificationCenter
// notification with the important details from the stored event. Distributed
// notifications are system-wide broadcasts that can be sent by apps and observed
// from separate processes. This allows users of Santa to write tools that
// perform actions when we block execution, such as trigger management tools or
// display an enterprise-specific UI (which is particularly useful when combined
// with the EnableSilentMode configuration option, to disable Santa's standard UI).
- (void)postDistributedNotification:(SNTMessageWindowController *)pendingMsg {
  if (![pendingMsg isKindOfClass:[SNTBinaryMessageWindowController class]]) {
    return;
  }
  SNTBinaryMessageWindowController *wc = (SNTBinaryMessageWindowController *)pendingMsg;
  NSDistributedNotificationCenter *dc = [NSDistributedNotificationCenter defaultCenter];
  NSMutableArray<NSDictionary *> *signingChain =
      [NSMutableArray arrayWithCapacity:wc.event.signingChain.count];
  for (MOLCertificate *cert in wc.event.signingChain) {
    [signingChain addObject:@{
      kCertSHA256 : cert.SHA256 ?: @"",
      kCertCN : cert.commonName ?: @"",
      kCertOrg : cert.orgName ?: @"",
      kCertOU : cert.orgUnit ?: @"",
      kCertValidFrom : @([cert.validFrom timeIntervalSince1970]) ?: @0,
      kCertValidUntil : @([cert.validUntil timeIntervalSince1970]) ?: @0,
    }];
  }
  NSDictionary *userInfo = @{
    kFileSHA256 : wc.event.fileSHA256 ?: @"",
    kFilePath : wc.event.filePath ?: @"",
    kFileBundleName : wc.event.fileBundleName ?: @"",
    kFileBundleID : wc.event.fileBundleID ?: @"",
    kFileBundleVersion : wc.event.fileBundleVersion ?: @"",
    kFileBundleShortVersionString : wc.event.fileBundleVersionString ?: @"",
    kTeamID : wc.event.teamID ?: @"",
    kExecutingUser : wc.event.executingUser ?: @"",
    kExecutionTime : @([wc.event.occurrenceDate timeIntervalSince1970]) ?: @0,
    kPID : wc.event.pid ?: @0,
    kPPID : wc.event.ppid ?: @0,
    kParentName : wc.event.parentName ?: @"",
    kSigningChain : signingChain,
  };

  [dc postNotificationName:@"com.northpolesec.santa.notification.blockedeexecution"
                    object:@"com.northpolesec.santa"
                  userInfo:userInfo
        deliverImmediately:YES];
}

- (void)showQueuedWindow {
  // Notifications arrive on a background thread but UI updates must happen on the main thread.
  // This includes making windows.
  dispatch_async(dispatch_get_main_queue(), ^{
    // If a notification isn't currently being displayed, display the incoming one.
    // This check will generally be redundant, as we'd generally want to check this prior to
    // starting work on the main thread.
    if (!self.currentWindowController) {
      self.currentWindowController = [self.pendingNotifications firstObject];
      [self.currentWindowController showWindow:self];

      if ([self.currentWindowController isKindOfClass:[SNTBinaryMessageWindowController class]]) {
        SNTBinaryMessageWindowController *controller =
            (SNTBinaryMessageWindowController *)self.currentWindowController;
        if (controller.event.needsBundleHash) {
          dispatch_async(self.hashBundleBinariesQueue, ^{
            [self hashBundleBinariesForEvent:controller.event withController:controller];
          });
        }
      }
    }
  });
}

- (void)hashBundleBinariesForEvent:(SNTStoredEvent *)event
                    withController:(SNTBinaryMessageWindowController *)withController {
  withController.bundleProgress.label = @"Searching for files...";

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
  bc.acceptedHandler = ^{
    dispatch_semaphore_signal(sema);
  };
  [bc resume];

  // Wait a max of 5 secs for the bundle service
  // Otherwise abandon bundle hashing and display the blockable event.
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    [withController updateBlockNotification:event withBundleHash:nil];
    LOGE(@"Timeout connecting to bundle service");
    return;
  }

  [[bc remoteObjectProxy] setNotificationListener:self.notificationListener];

  // NSProgress becomes current for this thread. XPC messages vend a child node to the receiver.
  [withController.progress becomeCurrentWithPendingUnitCount:100];

  // Start hashing. Progress is reported to the root NSProgress
  // (currentWindowController.progress).
  [[bc remoteObjectProxy]
      hashBundleBinariesForEvent:event
                           reply:^(NSString *bh, NSArray<SNTStoredEvent *> *events, NSNumber *ms) {
                             // Revert to displaying the blockable event if we fail to calculate the
                             // bundle hash
                             if (!bh)
                               return [withController updateBlockNotification:event
                                                               withBundleHash:nil];

                             event.fileBundleHash = bh;
                             event.fileBundleBinaryCount = @(events.count);
                             event.fileBundleHashMilliseconds = ms;
                             event.fileBundleExecutableRelPath =
                                 [events.firstObject fileBundleExecutableRelPath];
                             for (SNTStoredEvent *se in events) {
                               se.fileBundleHash = bh;
                               se.fileBundleBinaryCount = @(events.count);
                               se.fileBundleHashMilliseconds = ms;
                             }

                             // Send the results to santad. It will decide if they need to be
                             // synced.
                             MOLXPCConnection *daemonConn =
                                 [SNTXPCControlInterface configuredConnection];
                             [daemonConn resume];
                             [[daemonConn remoteObjectProxy] syncBundleEvent:event
                                                               relatedEvents:events];
                             [daemonConn invalidate];

                             // Update the UI with the bundle hash. Also make the openEventButton
                             // available.
                             [withController updateBlockNotification:event withBundleHash:bh];

                             [bc invalidate];
                           }];

  [withController.progress resignCurrent];
}

#pragma mark SNTNotifierXPC protocol methods

- (void)postClientModeNotification:(SNTClientMode)clientmode {
  if ([SNTConfigurator configurator].enableSilentMode) return;

  UNUserNotificationCenter *un = [UNUserNotificationCenter currentNotificationCenter];

  UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
  content.title = @"Santa";

  switch (clientmode) {
    case SNTClientModeMonitor: {
      content.body =
          NSLocalizedString(@"Switching into Monitor mode", @"Client mode change: MONITOR");
      NSString *customMsg = [[SNTConfigurator configurator] modeNotificationMonitor];
      if (!customMsg) break;
      // If a custom message is added but as an empty string, disable notifications.
      if (!customMsg.length) return;

      content.body = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    }
    case SNTClientModeLockdown: {
      content.body =
          NSLocalizedString(@"Switching into Lockdown mode", @"Client mode change: LOCKDOWN");
      NSString *customMsg = [[SNTConfigurator configurator] modeNotificationLockdown];
      if (!customMsg) break;
      // If a custom message is added but as an empty string, disable notifications.
      if (!customMsg.length) return;

      content.body = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    }
    case SNTClientModeStandalone: {
      content.body =
          NSLocalizedString(@"Switching into Standalone mode", @"Client mode change: STANDALONE");
      NSString *customMsg = [[SNTConfigurator configurator] modeNotificationStandalone];
      if (!customMsg) break;
      // If a custom message is added but as an empty string, disable notifications.
      if (!customMsg.length) return;

      content.body = [SNTBlockMessage stringFromHTML:customMsg];
      break;
    }
    default: return;
  }

  UNNotificationRequest *req =
      [UNNotificationRequest requestWithIdentifier:@"clientModeNotification"
                                           content:content
                                           trigger:nil];

  [un addNotificationRequest:req withCompletionHandler:nil];
}

- (void)postRuleSyncNotificationForApplication:(NSString *)app {
  if ([SNTConfigurator configurator].enableSilentMode) return;

  UNUserNotificationCenter *un = [UNUserNotificationCenter currentNotificationCenter];

  UNMutableNotificationContent *content = [[UNMutableNotificationContent alloc] init];
  content.title = @"Santa";
  content.body =
      app ? [NSString stringWithFormat:
                          NSLocalizedString(
                              @"%@ can now be run",
                              @"Notification message shown when a known app has been unblocked"),
                          app]
          : NSLocalizedString(@"Requested application can now be run",
                              @"Notification message shown when an unknown app has been unblocked");

  NSString *identifier = [NSString stringWithFormat:@"ruleSyncNotification_%@", content.body];

  UNNotificationRequest *req = [UNNotificationRequest requestWithIdentifier:identifier
                                                                    content:content
                                                                    trigger:nil];

  [un addNotificationRequest:req withCompletionHandler:nil];
}

- (void)postBlockNotification:(SNTStoredEvent *)event
            withCustomMessage:(NSString *)message
                    customURL:(NSString *)url
                  configState:(SNTConfigState *)configState
                     andReply:(void (^)(BOOL))replyBlock {
  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }

  SNTBinaryMessageWindowController *pendingMsg =
      [[SNTBinaryMessageWindowController alloc] initWithEvent:event
                                                    customMsg:message
                                                    customURL:url
                                                  configState:configState
                                                        reply:replyBlock];

  [self queueMessage:pendingMsg enableSilences:configState.enableNotificationSilences];
}

- (void)postUSBBlockNotification:(SNTDeviceEvent *)event {
  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }
  SNTDeviceMessageWindowController *pendingMsg =
      [[SNTDeviceMessageWindowController alloc] initWithEvent:event];

  [self queueMessage:pendingMsg enableSilences:YES];
}

- (void)postFileAccessBlockNotification:(SNTFileAccessEvent *)event
                          customMessage:(NSString *)message
                              customURL:(NSString *)url
                             customText:(NSString *)text
                            configState:(SNTConfigState *)configState {
  if (!event) {
    LOGI(@"Error: Missing event object in message received from daemon!");
    return;
  }

  SNTFileAccessMessageWindowController *pendingMsg =
      [[SNTFileAccessMessageWindowController alloc] initWithEvent:event
                                                    customMessage:message
                                                        customURL:url
                                                       customText:text
                                                      configState:configState];

  [self queueMessage:pendingMsg enableSilences:YES];
}

// XPC handler. The sync service requests the APNS token, by way of the daemon.
- (void)requestAPNSToken:(void (^)(NSString *))reply {
  if (self.APNSDeviceToken.length) {
    reply(self.APNSDeviceToken);
    return;
  }

  // If APNS is enabled, `-[NSApp registerForRemoteNotifications]` is run when the application
  // finishes launching at startup. If APNS is enabled after startup, register now. Upon successful
  // registration, the sync service will be notified that the token has changed.
  [NSApp registerForRemoteNotifications];
  reply(nil);
}

- (void)didRegisterForAPNS:(NSString *)deviceToken {
  self.APNSDeviceToken = deviceToken;
  [self APNSTokenChanged];
}

- (void)APNSTokenChanged {
  // Only message the sync service if a sync server is configured and APNS is enabled, otherwise the
  // service will needlessly spin up.
  // TODO: To realize changes to EnableAPNS, both the gui and sync service need to be restarted. Add
  // KVO watching to allow APNS to be enabled or disabled without process restarts.
  SNTConfigurator *config = [SNTConfigurator configurator];
  if (!config.syncBaseURL || !config.enableAPNS) return;
  MOLXPCConnection *syncConn = [SNTXPCSyncServiceInterface configuredConnection];
  [syncConn resume];
  [[syncConn remoteObjectProxy] APNSTokenChanged];
  [syncConn invalidate];
}

#pragma mark SNTBundleNotifierXPC protocol methods

- (void)updateCountsForEvent:(SNTStoredEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount {
  if ([self.currentWindowController isKindOfClass:[SNTBinaryMessageWindowController class]]) {
    SNTBinaryMessageWindowController *controller =
        (SNTBinaryMessageWindowController *)self.currentWindowController;

    __block uint64_t guiFileCount = fileCount;
    if ([controller.event.idx isEqual:event.idx]) {
      dispatch_async(dispatch_get_main_queue(), ^{
        // Ensure that the file count is always at least equal the binary count.
        // In rare cases we can receive 1 binary and 0 files, which looks silly.
        if (binaryCount > guiFileCount) {
          guiFileCount = binaryCount;
        }

        NSString *fileLabel =
            [NSString stringWithFormat:@"%llu binaries / %llu files", binaryCount, guiFileCount];
        NSString *hashedLabel =
            [NSString stringWithFormat:@"%llu hashed / %llu binaries", hashedCount, binaryCount];
        controller.bundleProgress.label = hashedCount ? hashedLabel : fileLabel;
      });
    }
  }
}

@end
