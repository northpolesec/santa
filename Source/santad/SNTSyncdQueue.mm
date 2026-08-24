/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/santad/SNTSyncdQueue.h"

#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#include "Source/common/SantaCache.h"
#include "Source/common/String.h"

// How long a removed SyncBaseURL must stay removed before synced state is dropped. Gives
// com.apple.ManagedClient time to settle if it is flapping.
static constexpr NSTimeInterval kDefaultClearSyncStateGracePeriod = 600;

@interface SNTSyncdQueue ()
@property dispatch_queue_t syncdQueue;
@property MOLXPCConnection* syncConnection;
@property dispatch_source_t timer;
@property NSURL* previousSyncBaseURL;

/// Last non-nil SyncBaseURL seen. Unlike `previousSyncBaseURL` this survives the URL going away,
/// so a server swap is still recognised when SyncBaseURL passes through nil on the way. Seeded
/// from, and written back to, the configurator's persisted record so that a swap spanning a
/// daemon restart is recognised too.
@property NSURL* lastSyncServerURL;

/// Pending clear of synced state, or NULL if none is armed. Only touched on `syncdQueue`.
@property dispatch_source_t clearSyncStateTimer;

/// A property, not the constant directly, so tests don't wait out the real grace period.
@property NSTimeInterval clearSyncStateGracePeriod;
@end

@implementation SNTSyncdQueue {
  // TODO(https://github.com/northpolesec/santa/issues/344): Eventually replace with an LRU.
  std::unique_ptr<SantaCache<std::string, NSDate*>> _uploadBackoff;
}

- (instancetype)initWithCacheSize:(uint64_t)cacheSize {
  self = [super init];
  if (self) {
    _uploadBackoff = std::make_unique<SantaCache<std::string, NSDate*>>(cacheSize);
    _syncdQueue = dispatch_queue_create("com.northpolesec.syncd_queue",
                                        DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    _clearSyncStateGracePeriod = kDefaultClearSyncStateGracePeriod;
    _lastSyncServerURL = [[SNTConfigurator configurator] savedLastSyncServerURL];
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
    // Coalesce: a still-pending reassessment is superseded by this one. The handler retires its
    // own source, so a non-NULL timer here always means one is genuinely still pending.
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
      if (!self) {
        return;
      }

      // One-shot: retire the source before doing any work, so that every exit path below is
      // covered and a non-NULL `timer` always means "armed and not yet fired". Dropping our
      // reference here is safe -- nothing touches the source afterwards, and dispatch keeps it
      // alive for the duration of this handler.
      dispatch_source_cancel(self.timer);
      self.timer = NULL;

      SNTConfigurator* configurator = [SNTConfigurator configurator];

      NSURL* newSyncBaseURL = [configurator syncBaseURL];

      // The server changed identity, rather than appearing or disappearing. Compared against the
      // last non-nil URL, so removing one server and adding another still counts. Computed before
      // the trackers are updated below, and independent of connection state. Only sees changes
      // within this santad's lifetime: an edit made while it was down is missed.
      BOOL syncServerChanged = self.lastSyncServerURL && newSyncBaseURL &&
                               ![self.lastSyncServerURL isEqual:newSyncBaseURL];

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
      if (newSyncBaseURL && ![self.lastSyncServerURL isEqual:newSyncBaseURL]) {
        self.lastSyncServerURL = newSyncBaseURL;
        // Written only on change: persisting rewrites the whole state file. A failure leaves the
        // record stale, so the change is acted on now but missed after a restart.
        if (![configurator persistLastSyncServerURL:newSyncBaseURL]) {
          LOGW(@"Failed to record the current sync server; a change made while santad is not "
               @"running may go unnoticed");
        }
      }

      // A SyncBaseURL is the only thing the sync service exists for.
      if (newSyncBaseURL) {
        // Runs once per change: the bounce above returns early, so this is the pass driven by
        // the old sync service's invalidation, i.e. after it exited and can no longer write.
        if (syncServerChanged) {
          [self dropStateFromPreviousSyncServerSerialized];
        }

        if (!self.syncConnection.isConnected) {
          [self establishSyncServiceConnectionSerialized];
        }

        // A sync server is configured again, so any pending clear is no longer wanted.
        [self cancelPendingClearSyncStateSerialized];
      } else {
        if (self.syncConnection.isConnected) {
          // Note: Only teardown the connection if we're connected. This helps
          // prevent the condition where we would end-up reestablishing the
          // connection when the invalidationHandler fired and a call to
          // spindown would be performed.
          [self tearDownSyncServiceConnectionSerialized];
        }

        // Keep the syncState active for the grace period in case
        // com.apple.ManagedClient is flapping.
        [self scheduleClearSyncStateSerialized];
      }
    });

    dispatch_resume(self.timer);
  });
}

/// Drop the previous sync server's settings and ask the new one for a clean sync. Rules are left
/// alone: the Clean sync replaces them in one transaction, so policy is never momentarily empty.
///
/// Must be called on `syncdQueue`. The hop to main is async because the main thread may itself be
/// blocked in `dispatch_sync(syncdQueue, ...)` via `reassessSyncServiceConnection`.
- (void)dropStateFromPreviousSyncServerSerialized {
  dispatch_async(dispatch_get_main_queue(), ^{
    LOGI(@"SyncBaseURL now points at a different sync server, dropping the previous server's "
         @"synced settings and requesting a clean sync");
    SNTConfigurator* configurator = [SNTConfigurator configurator];
    [configurator performSyncStateBatch:^{
      [configurator clearSyncState];
      [configurator setSyncTypeRequired:SNTSyncTypeClean];
    }];
  });
}

/// Arm a one-shot clear of synced state, `clearSyncStateGracePeriod` from now. An already-armed
/// request is left alone so config churn can't push the deadline out indefinitely.
///
/// Must be called on `syncdQueue`. The hop to main is async because the main thread may itself be
/// blocked in `dispatch_sync(syncdQueue, ...)` via `reassessSyncServiceConnection`.
- (void)scheduleClearSyncStateSerialized {
  if (self.clearSyncStateTimer) {
    return;
  }

  self.clearSyncStateTimer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.syncdQueue);
  dispatch_source_set_timer(
      self.clearSyncStateTimer,
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.clearSyncStateGracePeriod * NSEC_PER_SEC)),
      DISPATCH_TIME_FOREVER,  // won't repeat
      1 * NSEC_PER_SEC);

  WEAKIFY(self);
  dispatch_source_set_event_handler(self.clearSyncStateTimer, ^{
    STRONGIFY(self);
    if (!self) {
      return;
    }

    // Only run once.
    dispatch_source_cancel(self.clearSyncStateTimer);
    self.clearSyncStateTimer = NULL;

    NSTimeInterval gracePeriod = self.clearSyncStateGracePeriod;
    dispatch_async(dispatch_get_main_queue(), ^{
      // Re-check after the hop: cancelPendingClearSyncStateSerialized only stops a clear that is
      // still armed, so a URL landing between the timer firing and this block would be missed.
      SNTConfigurator* configurator = [SNTConfigurator configurator];
      if (configurator.syncBaseURL) {
        LOGD(@"SyncBaseURL reappeared before synced state was cleared, keeping it");
        return;
      }

      LOGI(@"No SyncBaseURL configured for %g seconds, clearing synced state", gracePeriod);
      [configurator clearSyncState];

      // The rules stay, so whichever server comes next must be asked to replace them. Recorded
      // explicitly because `syncTypeRequired`'s empty-state default lapses to Normal the moment
      // postflight writes any other key, and a server that declines the clean sync would then
      // merge its rules onto the departed server's. Not batched with the clear above:
      // `clearSyncState` only removes the plist when it runs outside a batch.
      [configurator setSyncTypeRequired:SNTSyncTypeClean];
    });
  });

  dispatch_resume(self.clearSyncStateTimer);
}

/// Drop any armed request to clear synced state. Must be called on `syncdQueue`.
- (void)cancelPendingClearSyncStateSerialized {
  if (!self.clearSyncStateTimer) {
    return;
  }

  dispatch_source_cancel(self.clearSyncStateTimer);
  self.clearSyncStateTimer = NULL;
}

- (void)establishSyncServiceConnectionSerialized {
  MOLXPCConnection* ss = [SNTXPCSyncServiceInterface configuredConnection];

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

- (void)addStoredEvent:(SNTStoredEvent*)event {
  if (!event) {
    return;
  }
  [self addEvents:@[ event ] withBackoffHashKey:[event uniqueID]];
}

- (void)addBundleEvents:(NSArray<SNTStoredExecutionEvent*>*)events
         withBundleHash:(NSString*)bundleHash {
  if (!events.count) {
    return;
  }
  [self addEvents:events withBackoffHashKey:bundleHash];
}

- (void)addEvents:(NSArray<SNTStoredEvent*>*)events withBackoffHashKey:(NSString*)backoffHashKey {
  if (!events.count || [self backoffForPrimaryHash:backoffHashKey]) {
    return;
  }

  [self dispatchBlockOnSyncdQueue:^{
    [self.syncConnection.remoteObjectProxy
        postEventsToSyncServer:events
                         reply:^(BOOL success) {
                           if (!success) {
                             _uploadBackoff->remove(santa::NSStringToUTF8String(backoffHashKey));
                           }
                         }];
  }];
}

- (void)addBundleEvent:(SNTStoredExecutionEvent*)event reply:(void (^)(SNTBundleEventAction))reply {
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

- (void)uploadSignalReports:(NSArray<SNTStoredSignalReport*>*)reports {
  if (!reports.count) return;
  [self dispatchBlockOnSyncdQueue:^{
    [self.syncConnection.remoteObjectProxy
        uploadSignalReportsToSyncServer:reports
                                  reply:^(BOOL success) {
                                    if (!success) {
                                      LOGD(@"Immediate signal report upload failed; will retry on "
                                           @"next sync");
                                    }
                                  }];
  }];
}

- (void)dispatchBlockOnSyncdQueue:(void (^)(void))block {
  if (!block) return;
  dispatch_async(self.syncdQueue, ^{
    block();
  });
}

// The event upload is skipped if an event has been initiated for it in the last 10 minutes.
// The passed-in hash is fileBundleHash for a bundle event, or fileSHA256 for a normal event.
// Returns YES if backoff is needed, NO otherwise.
- (BOOL)backoffForPrimaryHash:(NSString*)hash {
  NSDate* backoff = _uploadBackoff->get(santa::NSStringToUTF8String(hash));
  NSDate* now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) < 600) return YES;
  _uploadBackoff->set(santa::NSStringToUTF8String(hash), now);
  return NO;
}

- (void)pushNotificationReconnect {
  [self dispatchBlockOnSyncdQueue:^{
    if (!self.syncConnection.isConnected) {
      LOGW(@"Cannot reconnect push notifications: sync service not connected");
      return;
    }

    LOGD(@"SNTSyncdQueue: Forwarding pushNotificationReconnect to sync service");
    [[self.syncConnection remoteObjectProxy] pushNotificationReconnect];
  }];
}

@end
