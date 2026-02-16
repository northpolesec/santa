/// Copyright 2016 Google Inc. All rights reserved.
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

#import "Source/santasyncservice/SNTSyncManager.h"

#import <Network/Network.h>

#import "Source/common/MOLAuthenticatingURLSession.h"
#import "Source/common/MOLXPCConnection.h"
#include "Source/common/Pinning.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCBundleServiceInterface.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTPushClientFCM.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSyncConfigBundle.h"
#import "Source/santasyncservice/SNTSyncEventUpload.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncPostflight.h"
#import "Source/santasyncservice/SNTSyncPreflight.h"
#import "Source/santasyncservice/SNTSyncRuleDownload.h"
#import "Source/santasyncservice/SNTSyncState.h"

static const uint8_t kMaxEnqueuedSyncs = 2;

@interface SNTSyncManager () <SNTPushNotificationsSyncDelegate>

@property(nonatomic) dispatch_source_t fullSyncTimer;
@property(nonatomic) dispatch_source_t ruleSyncTimer;

@property(nonatomic, readonly) dispatch_queue_t syncQueue;
@property(nonatomic, readonly) dispatch_semaphore_t syncLimiter;

@property(nonatomic) MOLXPCConnection *daemonConn;

@property(nonatomic) BOOL reachable;
@property nw_path_monitor_t pathMonitor;

// If set, push notifications are being used.
@property id<SNTPushNotificationsClientDelegate> pushNotifications;

@property NSUInteger eventBatchSize;

@property NSString *xsrfToken;
@property NSString *xsrfTokenHeader;

@end

@implementation SNTSyncManager

#pragma mark init

- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn {
  self = [super init];
  if (self) {
    _daemonConn = daemonConn;

    SNTConfigurator *config = [SNTConfigurator configurator];

    if (config.fcmEnabled) {
      LOGD(@"Using FCM push notifications");
      _pushNotifications = [[SNTPushClientFCM alloc] initWithSyncDelegate:self];
    } else if (config.enablePushNotifications && santa::IsDomainPinned(config.syncBaseURL)) {
      LOGD(@"Using NATS push notifications");
      // Use NATS this will only work for V2 sync clients.
      _pushNotifications = [[SNTPushClientNATS alloc] initWithSyncDelegate:self];
    }

    _fullSyncTimer = [self createSyncTimerWithBlock:^{
      [self rescheduleTimerQueue:self.fullSyncTimer
                  secondsFromNow:_pushNotifications ? _pushNotifications.fullSyncInterval
                                                    : kDefaultFullSyncInterval];
      [self syncType:SNTSyncTypeNormal withReply:NULL];
    }];
    _ruleSyncTimer = [self createSyncTimerWithBlock:^{
      dispatch_source_set_timer(self.ruleSyncTimer, DISPATCH_TIME_FOREVER, DISPATCH_TIME_FOREVER,
                                0);
      [self ruleSyncImpl];
    }];
    _syncQueue = dispatch_queue_create("com.northpolesec.santa.syncservice", DISPATCH_QUEUE_SERIAL);
    _syncLimiter = dispatch_semaphore_create(kMaxEnqueuedSyncs);

    _eventBatchSize = kDefaultEventBatchSize;
  }
  return self;
}

#pragma mark SNTSyncServiceXPC methods

- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events reply:(void (^)(BOOL))reply {
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    LOGE(@"Events upload failed to create sync state: %ld", status);
    if (reply) reply(NO);
    return;
  }
  syncState.eventBatchSize = self.eventBatchSize;
  SNTSyncEventUpload *p = [[SNTSyncEventUpload alloc] initWithState:syncState];
  BOOL success;
  if (events && [p uploadEvents:events]) {
    LOGD(@"Events upload complete");
    success = YES;
  } else {
    LOGE(@"Events upload failed.  Will retry again once %@ is reachable",
         [[SNTConfigurator configurator] syncBaseURL].absoluteString);
    [self startReachability];
    success = NO;
  }
  self.xsrfToken = syncState.xsrfToken;
  self.xsrfTokenHeader = syncState.xsrfTokenHeader;
  reply(success);
}

- (void)postBundleEventToSyncServer:(SNTStoredExecutionEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply {
  if (!event) {
    reply(SNTBundleEventActionDropEvents);
    return;
  }
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    LOGE(@"Bundle event upload failed to create sync state: %ld", status);
    reply(SNTBundleEventActionDropEvents);
    return;
  }
  SNTSyncEventUpload *p = [[SNTSyncEventUpload alloc] initWithState:syncState];
  if ([p uploadEvents:@[ event ]]) {
    if ([syncState.bundleBinaryRequests containsObject:event.fileBundleHash]) {
      reply(SNTBundleEventActionSendEvents);
      LOGD(@"Needs related events");
    } else {
      reply(SNTBundleEventActionDropEvents);
      LOGD(@"Bundle event upload complete");
    }
  } else {
    // Related bundle events will be stored and eventually synced, whether the server actually
    // wanted them or not.  If they weren't needed the server will simply ignore them.
    reply(SNTBundleEventActionStoreEvents);
    LOGE(@"Bundle event upload failed.  Will retry again once %@ is reachable",
         [[SNTConfigurator configurator] syncBaseURL].absoluteString);
    [self startReachability];
  }
  self.xsrfToken = syncState.xsrfToken;
  self.xsrfTokenHeader = syncState.xsrfTokenHeader;
}

- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply {
  if (!self.pushNotifications) {
    reply(SNTPushNotificationStatusDisabled);
    return;
  }
  if (!self.pushNotifications.isConnected) {
    reply(SNTPushNotificationStatusDisconnected);
    return;
  }
  // Check if using NATS push client
  if ([self.pushNotifications isKindOfClass:[SNTPushClientNATS class]]) {
    reply(SNTPushNotificationStatusConnectedNATS);
    return;
  }
  reply(SNTPushNotificationStatusConnected);
}

- (void)pushNotificationServerAddress:(void (^)(NSString *))reply {
  // Only return server address if using NATS and connected
  if ([self.pushNotifications isKindOfClass:[SNTPushClientNATS class]] &&
      self.pushNotifications.isConnected) {
    SNTPushClientNATS *natsClient = (SNTPushClientNATS *)self.pushNotifications;
    NSString *serverAddress = natsClient.pushServer;
    reply(serverAddress);
    return;
  }
  reply(nil);
}

- (void)pushNotificationReconnect {
  if (!self.pushNotifications) {
    LOGD(@"Push notifications not configured, nothing to reconnect");
    return;
  }

  LOGD(@"Force reconnecting push notification client");

  // First, reset the push client's connection state (cancel retry timers, close connection)
  // Then trigger a sync which will call handlePreflightSyncState with fresh credentials
  // and reconnect the push client. Give a small amount of time before doing another sync
  // since right now the force reconnect happens when enabling the network extension which
  // can cause connections to reset and a flood of network activity.
  if ([self.pushNotifications respondsToSelector:@selector(forceReconnect)]) {
    [self.pushNotifications forceReconnect];
  }
  [self syncSecondsFromNow:2];
}

#pragma mark sync control / SNTPushNotificationsDelegate methods

- (void)sync {
  [self syncSecondsFromNow:0];
}

- (void)syncSecondsFromNow:(uint64_t)seconds {
  [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:seconds];
}

- (void)syncType:(SNTSyncType)syncType withReply:(void (^)(SNTSyncStatusType))reply {
  if (dispatch_semaphore_wait(self.syncLimiter, DISPATCH_TIME_NOW)) {
    if (reply) reply(SNTSyncStatusTypeTooManySyncsInProgress);
    return;
  }
  dispatch_async(self.syncQueue, ^() {
    SLOGI(@"Starting sync...");
    if (syncType != SNTSyncTypeNormal) {
      dispatch_semaphore_t sema = dispatch_semaphore_create(0);
      [[self.daemonConn remoteObjectProxy] updateSyncSettings:SyncTypeConfigBundle(syncType)
                                                        reply:^() {
                                                          dispatch_semaphore_signal(sema);
                                                        }];
      if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC))) {
        SLOGE(@"Timeout waiting for daemon");
        if (reply) reply(SNTSyncStatusTypeDaemonTimeout);
        return;
      }
    }
    if (reply) reply(SNTSyncStatusTypeSyncStarted);
    SNTSyncStatusType status = [self preflight];
    if (reply) reply(status);
    dispatch_semaphore_signal(self.syncLimiter);
  });
}

- (void)ruleSync {
  [self ruleSyncSecondsFromNow:0];
}

- (void)ruleSyncSecondsFromNow:(uint64_t)seconds {
  [self rescheduleTimerQueue:self.ruleSyncTimer secondsFromNow:seconds];
}

- (void)rescheduleTimerQueue:(dispatch_source_t)timerQueue secondsFromNow:(uint64_t)seconds {
  uint64_t interval = seconds * NSEC_PER_SEC;
  uint64_t leeway = 5 * NSEC_PER_SEC;
  dispatch_source_set_timer(timerQueue, dispatch_walltime(NULL, interval), interval, leeway);
}

- (void)ruleSyncImpl {
  // Rule only syncs are exclusively scheduled by self.ruleSyncTimer. We do not need to worry about
  // using self.syncLimiter here. However we do want to do the work on self.syncQueue so we do not
  // overlap with a full sync.
  dispatch_async(self.syncQueue, ^() {
    if (![[SNTConfigurator configurator] syncBaseURL]) return;
    SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
    SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
    if (!syncState) {
      LOGE(@"Rule sync failed to create sync state: %ld", status);
      return;
    }
    SNTSyncRuleDownload *p = [[SNTSyncRuleDownload alloc] initWithState:syncState];
    BOOL ret = [p sync];
    LOGD(@"Rule download %@", ret ? @"complete" : @"failed");
    self.xsrfToken = syncState.xsrfToken;
    self.xsrfTokenHeader = syncState.xsrfTokenHeader;
  });
}

- (void)preflightSync {
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    LOGE(@"Unable to create sync state: %lu", status);
    return;
  }
  syncState.preflightOnly = YES;
  [self preflightWithSyncState:syncState];
}

- (void)pushNotificationSyncSecondsFromNow:(uint64_t)seconds {
  if (seconds > 0) {
    [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:seconds];
    return;
  }

  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    LOGE(@"Unable to create sync state: %lu", status);
    return;
  }
  syncState.pushNotificationSync = YES;
  [self preflightWithSyncState:syncState];
}

- (MOLXPCConnection *)daemonConnection {
  return self.daemonConn;
}

- (void)eventUploadForPath:(NSString *)path reply:(void (^)(NSError *error))reply {
  if (path.length == 0) {
    reply([NSError errorWithDomain:@"com.northpolesec.santa.syncservice"
                              code:1
                          userInfo:@{NSLocalizedDescriptionKey : @"Empty path"}]);
    return;
  }

  // Check enableBundles via daemon XPC
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block BOOL enableBundles = NO;
  [[self.daemonConn remoteObjectProxy] enableBundles:^(BOOL response) {
    enableBundles = response;
    dispatch_semaphore_signal(sema);
  }];
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
    LOGE(@"EventUpload: Timeout checking enableBundles, proceeding without bundles");
  }

  // Connect to bundle service
  MOLXPCConnection *bs = [SNTXPCBundleServiceInterface configuredConnection];
  [bs resume];

  dispatch_semaphore_t eventSema = dispatch_semaphore_create(0);
  __block NSArray<SNTStoredExecutionEvent *> *resultEvents;
  [[bs remoteObjectProxy] generateEventsFromPath:path
                                   enableBundles:enableBundles
                                           reply:^(NSArray<SNTStoredExecutionEvent *> *events) {
                                             resultEvents = events;
                                             dispatch_semaphore_signal(eventSema);
                                           }];

  if (dispatch_semaphore_wait(eventSema, dispatch_time(DISPATCH_TIME_NOW, 600 * NSEC_PER_SEC)) !=
      0) {
    [bs invalidate];
    reply([NSError errorWithDomain:@"com.northpolesec.santa.syncservice"
                              code:2
                          userInfo:@{NSLocalizedDescriptionKey : @"Timeout generating events"}]);
    return;
  }

  if (!resultEvents.count) {
    [bs invalidate];
    reply(nil);
    return;
  }

  // Upload events to sync server
  [self postEventsToSyncServer:resultEvents
                         reply:^(BOOL success) {
                           if (success) {
                             reply(nil);
                           } else {
                             reply([NSError
                                 errorWithDomain:@"com.northpolesec.santa.syncservice"
                                            code:4
                                        userInfo:@{
                                          NSLocalizedDescriptionKey : @"Failed to upload events"
                                        }]);
                           }
                           [bs invalidate];
                         }];
}

#pragma mark syncing chain

- (SNTSyncStatusType)preflight {
  SNTSyncStatusType status = SNTSyncStatusTypeUnknown;
  SNTSyncState *syncState = [self createSyncStateWithStatus:&status];
  if (!syncState) {
    return status;
  }
  return [self preflightWithSyncState:syncState];
}

- (SNTSyncStatusType)preflightWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Preflight starting");
  SNTSyncPreflight *p = [[SNTSyncPreflight alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Preflight complete");
    self.xsrfToken = syncState.xsrfToken;
    self.xsrfTokenHeader = syncState.xsrfTokenHeader;

    // Clean up reachability if it was started for a non-network error
    [self stopReachability];

    self.eventBatchSize = syncState.eventBatchSize;

    // Start listening for push notifications with a full sync every
    // pushNotificationsFullSyncInterval.
    if (self.pushNotifications) {
      NSUInteger oldInterval = self.pushNotifications.fullSyncInterval;
      [self.pushNotifications handlePreflightSyncState:syncState];

      // Clear all push credentials from syncState after handoff to push client
      // These are no longer needed and should not be accessible to other sync stages
      syncState.pushNKey = nil;
      syncState.pushJWT = nil;
      syncState.pushHMACKey = nil;

      // If push interval changed, mark log the difference.
      if (oldInterval != self.pushNotifications.fullSyncInterval) {
        LOGD(
            @"Push notification sync interval changed from %lu to %lu seconds. Rescheduling timer.",
            oldInterval, self.pushNotifications.fullSyncInterval);
      }

      // Always reschedule
      [self rescheduleTimerQueue:self.fullSyncTimer
                  secondsFromNow:self.pushNotifications.fullSyncInterval];
    } else {
      LOGD(@"Push notifications are not enabled. Sync every %lu min.",
           syncState.fullSyncInterval / 60);

      // Always reschedule
      [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:syncState.fullSyncInterval];
    }

    if (syncState.preflightOnly) return SNTSyncStatusTypeSuccess;
    return [self eventUploadWithSyncState:syncState];
  } else if (_pushNotifications) {
    // If preflight failed and push notifications are enabled, force a reschedule for
    // the smaller of the default sync interval (default 10 minutes) and whatever the
    // last push full sync interval was set to (default 4 hours).
    // If push notifications are not enabled, the default sync interval was already set (10m).
    auto interval = std::min(_pushNotifications.fullSyncInterval, kDefaultFullSyncInterval);
    [self rescheduleTimerQueue:self.fullSyncTimer secondsFromNow:interval];
  }

  SLOGE(@"Preflight failed, will try again once %@ is reachable",
        [[SNTConfigurator configurator] syncBaseURL].absoluteString);
  [self startReachability];
  return SNTSyncStatusTypePreflightFailed;
}

- (SNTSyncStatusType)eventUploadWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Event upload starting");
  SNTSyncEventUpload *p = [[SNTSyncEventUpload alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Event upload complete");
    return [self ruleDownloadWithSyncState:syncState];
  }

  SLOGE(@"Event upload failed, aborting run");
  return SNTSyncStatusTypeEventUploadFailed;
}

- (SNTSyncStatusType)ruleDownloadWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Rule download starting");
  SNTSyncRuleDownload *p = [[SNTSyncRuleDownload alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Rule download complete");
    return [self postflightWithSyncState:syncState];
  }

  SLOGE(@"Rule download failed, aborting run");
  return SNTSyncStatusTypeRuleDownloadFailed;
}

- (SNTSyncStatusType)postflightWithSyncState:(SNTSyncState *)syncState {
  SLOGD(@"Postflight starting");
  SNTSyncPostflight *p = [[SNTSyncPostflight alloc] initWithState:syncState];
  if ([p sync]) {
    SLOGD(@"Postflight complete");
    SLOGI(@"Sync completed successfully");
    return SNTSyncStatusTypeSuccess;
  }
  SLOGE(@"Postflight failed");
  return SNTSyncStatusTypePostflightFailed;
}

#pragma mark internal helpers

- (dispatch_source_t)createSyncTimerWithBlock:(void (^)(void))block {
  dispatch_source_t timerQueue =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                             dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
  dispatch_source_set_event_handler(timerQueue, ^{
    // Only trigger the sync event if a syncBaseURL exists
    if ([[SNTConfigurator configurator] syncBaseURL]) {
      block();
    }
  });
  dispatch_resume(timerQueue);
  return timerQueue;
}

- (SNTSyncState *)createSyncStateWithStatus:(SNTSyncStatusType *)status {
  // Gather some data needed during some sync stages
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  SNTConfigurator *config = [SNTConfigurator configurator];

  syncState.syncBaseURL = config.syncBaseURL;
  if (syncState.syncBaseURL.absoluteString.length == 0) {
    SLOGE(@"Missing SyncBaseURL. Can't sync without it.");
    if (*status) *status = SNTSyncStatusTypeMissingSyncBaseURL;
    return nil;
  } else if (![syncState.syncBaseURL.scheme isEqual:@"https"]) {
    SLOGW(@"SyncBaseURL is not over HTTPS!");
  }

  syncState.machineID = config.machineID;
  if (syncState.machineID.length == 0) {
    SLOGE(@"Missing Machine ID. Can't sync without it.");
    if (*status) *status = SNTSyncStatusTypeMissingMachineID;
    return nil;
  }

  syncState.machineOwner = config.machineOwner;
  if (syncState.machineOwner.length == 0) {
    syncState.machineOwner = @"";
    SLOGD(@"Missing Machine Owner.");
  }
  syncState.machineOwnerGroups = config.machineOwnerGroups;

  syncState.xsrfToken = self.xsrfToken;
  syncState.xsrfTokenHeader = self.xsrfTokenHeader;

  NSURLSessionConfiguration *sessConfig = [NSURLSessionConfiguration defaultSessionConfiguration];
  sessConfig.connectionProxyDictionary = [[SNTConfigurator configurator] syncProxyConfig];

  MOLAuthenticatingURLSession *authURLSession =
      [[MOLAuthenticatingURLSession alloc] initWithSessionConfiguration:sessConfig];
  authURLSession.userAgent = @"santactl-sync/";
  NSString *santactlVersion = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
  if (santactlVersion) {
    authURLSession.userAgent = [authURLSession.userAgent stringByAppendingString:santactlVersion];
  }
  authURLSession.refusesRedirects = YES;
  authURLSession.serverHostname = syncState.syncBaseURL.host;
  authURLSession.loggingBlock = ^(NSString *line) {
    SLOGD(@"%@", line);
  };

  // Configure server auth
  if (santa::IsDomainPinned(syncState.syncBaseURL)) {
#ifndef DEBUG
    authURLSession.serverRootsPemString = santa::PinnedCertPEMs();
#endif
    syncState.isSyncV2 = YES;
  } else if ([config syncServerAuthRootsFile]) {
    authURLSession.serverRootsPemFile = [config syncServerAuthRootsFile];
  } else if ([config syncServerAuthRootsData]) {
    authURLSession.serverRootsPemData = [config syncServerAuthRootsData];
  }

// Force sync v2 via compile-time define
#ifdef SANTA_FORCE_SYNC_V2
  syncState.isSyncV2 = YES;
#endif

  SLOGD(@"Using sync protocol version: %d", syncState.isSyncV2 ? 2 : 1);

  // Configure client auth
  if ([config syncClientAuthCertificateFile]) {
    authURLSession.clientCertFile = [config syncClientAuthCertificateFile];
    authURLSession.clientCertPassword = [config syncClientAuthCertificatePassword];
  } else if ([config syncClientAuthCertificateCn]) {
    authURLSession.clientCertCommonName = [config syncClientAuthCertificateCn];
  } else if ([config syncClientAuthCertificateIssuer]) {
    authURLSession.clientCertIssuerCn = [config syncClientAuthCertificateIssuer];
  }

  syncState.session = [authURLSession session];
  syncState.daemonConn = self.daemonConn;
  syncState.contentEncoding = config.syncClientContentEncoding;
  syncState.pushNotificationsToken = self.pushNotifications.token;

  return syncState;
}

#pragma mark reachability methods

- (void)setReachable:(BOOL)reachable {
  _reachable = reachable;
  if (reachable) {
    LOGD(@"Internet connection has been restored, triggering a new sync.");
    [self stopReachability];
    [self sync];
  }
}

// Start listening for network state changes.
- (void)startReachability {
  if (self.pathMonitor) return;
  self.pathMonitor = nw_path_monitor_create();
  // Put the callback on the main thread to ensure serial access.
  nw_path_monitor_set_queue(self.pathMonitor, dispatch_get_main_queue());
  nw_path_monitor_set_update_handler(self.pathMonitor, ^(nw_path_t path) {
    // Only call the setter when there is a change. This will filter out the redundant calls to
    // this callback whenever the network interface states change.
    int reachable = nw_path_get_status(path) == nw_path_status_satisfied;
    if (self.reachable != reachable) {
      self.reachable = reachable;
    }
  });
  nw_path_monitor_set_cancel_handler(self.pathMonitor, ^{
    self.pathMonitor = nil;
  });
  nw_path_monitor_start(self.pathMonitor);
}

// Stop listening for network state changes
- (void)stopReachability {
  if (!self.pathMonitor) return;
  nw_path_monitor_cancel(self.pathMonitor);
}

@end
