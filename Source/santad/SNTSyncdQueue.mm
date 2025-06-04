/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/santad/SNTSyncdQueue.h"

#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/common/SantaCache.h"
#include "Source/common/String.h"

@interface SNTSyncdQueue ()
@property dispatch_queue_t syncdQueue;
@property MOLXPCConnection *syncConnection;
@property dispatch_source_t timer;
@property NSURL *previousSyncBaseURL;
@end

@implementation SNTSyncdQueue {
  // TODO(https://github.com/northpolesec/santa/issues/344): Eventually replace with an LRU.
  std::unique_ptr<SantaCache<std::string, NSDate *>> _uploadBackoff;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _uploadBackoff = std::make_unique<SantaCache<std::string, NSDate *>>(256);
    _syncdQueue = dispatch_queue_create("com.northpolesec.syncd_queue",
                                        DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  }
  return self;
}

/// On each call to reassessSyncServiceConnection, a timer will be created to
/// run ~1s in the future. If a pending timer exists when this method is
/// called, it is first cancelled and a new timer is created. This is done to
/// coalesce bursty calls (e.g. in response to a new configuration that makes
/// changes to multiple values that affect the sync service running state).
/// When the timer event handler fires, it will check the current config
/// state, as well as relevant config deltas, to determine whether the sync
/// service should be started, bounced, or stopped.
- (void)reassessSyncServiceConnection {
  [self reassessSyncServiceConnectionWithDelay:1];
}
- (void)reassessSyncServiceConnectionImmediately {
  [self reassessSyncServiceConnectionWithDelay:0];
}

- (void)reassessSyncServiceConnectionWithDelay:(uint32_t)seconds {
  WEAKIFY(self);
  dispatch_sync(self.syncdQueue, ^{
    if (self.timer) {
      dispatch_source_cancel(self.timer);
    }

    self.timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.syncdQueue);
    dispatch_source_set_timer(self.timer, dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC),
                              DISPATCH_TIME_FOREVER,  // won't repeat
                              100 * NSEC_PER_MSEC);

    // WEAKIFY(self);
    dispatch_source_set_event_handler(self.timer, ^{
      STRONGIFY(self);
      SNTConfigurator *configurator = [SNTConfigurator configurator];

      NSURL *newSyncBaseURL = [configurator syncBaseURL];
      BOOL statsCollectionEnabled = [configurator enableStatsCollection];
      BOOL telemetryExportEnabled = [configurator enableTelemetryExport];

      // If the SyncBaseURL was added or changed, and a connection already
      // exists, it must be bounced.
      if (self.previousSyncBaseURL && ![self.previousSyncBaseURL isEqual:newSyncBaseURL] &&
          self.syncConnection.isConnected) {
        [self tearDownSyncServiceConnectionSerialized];
        // Return early. When the sync service spins down, it will trigger the
        // invalidation handler which will reassess the connection state.
        return;
      }

      self.previousSyncBaseURL = newSyncBaseURL;

      // If newSyncBaseURL or statsCollectionEnabled is set, start the sync service
      if (newSyncBaseURL || statsCollectionEnabled || telemetryExportEnabled) {
        if (!self.syncConnection.isConnected) {
          [self establishSyncServiceConnectionSerialized];
        }

        // Ensure any pending requests to clear sync state are cancelled, but
        // only if there is a sync base URL set
        if (newSyncBaseURL) {
          [NSObject cancelPreviousPerformRequestsWithTarget:[SNTConfigurator configurator]
                                                   selector:@selector(clearSyncState)
                                                     object:nil];
        }
      } else {
        if (self.syncConnection.isConnected) {
          // Note: Only teardown the connection if we're connected. This helps
          // prevent the condition where we would end-up reestablishing the
          // connection when the invalidationHandler fired and a call to
          // spindown would be performed.
          [self tearDownSyncServiceConnectionSerialized];
        }

        // Keep the syncState active for 10 min in case com.apple.ManagedClient is
        // flapping.
        [[SNTConfigurator configurator] performSelector:@selector(clearSyncState)
                                             withObject:nil
                                             afterDelay:600];
      }

      // Only run once
      dispatch_source_cancel(self.timer);
      self.timer = NULL;
    });

    dispatch_resume(self.timer);
  });
}

- (void)establishSyncServiceConnectionSerialized {
  MOLXPCConnection *ss = [SNTXPCSyncServiceInterface configuredConnection];

  WEAKIFY(self);
  ss.invalidationHandler = ^(void) {
    STRONGIFY(self);
    self.syncConnection.invalidationHandler = nil;
    [self reassessSyncServiceConnection];
  };

  [ss resume];
  self.syncConnection = ss;
}

- (void)tearDownSyncServiceConnectionSerialized {
  // Tell the sync service to stop.
  [[self.syncConnection remoteObjectProxy] spindown];
}

- (void)addEvents:(NSArray<SNTStoredEvent *> *)events isFromBundle:(BOOL)isFromBundle {
  if (!events.count) return;
  SNTStoredEvent *first = events.firstObject;
  NSString *hash = isFromBundle ? first.fileBundleHash : first.fileSHA256;
  if ([self backoffForPrimaryHash:hash]) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncConnection.remoteObjectProxy postEventsToSyncServer:events fromBundle:isFromBundle];
  }];
}

- (void)addBundleEvent:(SNTStoredEvent *)event reply:(void (^)(SNTBundleEventAction))reply {
  if ([self backoffForPrimaryHash:event.fileBundleHash]) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncConnection.remoteObjectProxy
        postBundleEventToSyncServer:event
                              reply:^(SNTBundleEventAction action) {
                                // Remove the backoff entry for the initial block event. The same
                                // event will be included in the related events synced using
                                // addEvents:isFromBundle:.
                                if (action == SNTBundleEventActionSendEvents) {
                                  _uploadBackoff->remove(
                                      santa::NSStringToUTF8String(event.fileBundleHash));
                                }
                                reply(action);
                              }];
  }];
}

- (void)dispatchBlockOnSyncdQueue:(void (^)(void))block {
  if (!block) return;
  dispatch_async(self.syncdQueue, ^{
    block();
  });
}

- (void)exportTelemetryFile:(NSFileHandle *)telemetryFile
                     config:(SNTExportConfiguration *)config
          completionHandler:(void (^)(BOOL))completionHandler {
  [self dispatchBlockOnSyncdQueue:^{
    if (self.syncConnection.isConnected) {
      [self.syncConnection.remoteObjectProxy exportTelemetryFile:telemetryFile
                                                          config:config
                                                           reply:completionHandler];
    } else {
      // Unable to send to sync service, but still must call the completion handler
      completionHandler(NO);
    }
  }];
}

// The event upload is skipped if an event has been initiated for it in the last 10 minutes.
// The passed-in hash is fileBundleHash for a bundle event, or fileSHA256 for a normal event.
// Returns YES if backoff is needed, NO otherwise.
- (BOOL)backoffForPrimaryHash:(NSString *)hash {
  NSDate *backoff = _uploadBackoff->get(santa::NSStringToUTF8String(hash));
  NSDate *now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) < 600) return YES;
  _uploadBackoff->set(santa::NSStringToUTF8String(hash), now);
  return NO;
}

@end
