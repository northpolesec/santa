/// Copyright 2020 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>
#include <os/log.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"

@class SNTExportConfiguration;
@class SNTStoredEvent;

///
///  Protocol implemented by syncservice and utilized by daemon and ctl for communication with a
///  sync server.
///
@protocol SNTSyncServiceXPC
- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events fromBundle:(BOOL)fromBundle;
- (void)postBundleEventToSyncServer:(SNTStoredEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply;
- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply;
- (void)exportTelemetryFile:(NSFileHandle *)fd
                     config:(SNTExportConfiguration *)config
                      reply:(void (^)(BOOL))reply;

// The syncservice regularly syncs with a configured sync server. Use this method to sync out of
// band. The syncservice ensures syncs do not run concurrently.
//
// Pass an NSXPCListenerEndpoint whose associated NSXPCListener exports an object that implements
// the SNTSyncServiceLogReceiverXPC protocol. The caller will receive sync logs over this listener.
// This is required.
//
// Syncs are enqueued in order and executed serially. kMaxEnqueuedSyncs limits the number of syncs
// in the queue. If the queue is full calls to this method will be dropped and
// SNTSyncStatusTypeTooManySyncsInProgress will be passed into the reply block.
//
// Pass true to isClean to perform a clean sync, defaults to false.
//
- (void)syncWithLogListener:(NSXPCListenerEndpoint *)logListener
                   syncType:(SNTSyncType)syncType
                      reply:(void (^)(SNTSyncStatusType))reply;

// Spindown the syncservice. The syncservice will not automatically start back up.
// A new connection to the syncservice will bring it back up. This allows us to avoid running
// the syncservice needlessly when there is no configured sync server.
- (void)spindown;

// The GUI process registers with APNS. The token is then retrieved by the sync service. However,
// tokens are unique per-{device, app, and logged in user}. During fast user switching, a second
// GUI process spins up and registers with APNS. The sync service should then start using that APNS
// token. This method is called when the token has changed, letting the sync service know it needs
// to go and fetch the updated token. Why does the GUI process not send the token to the sync
// service when it changes? A few reasons. First, if the sync service restarts for any reason, it
// will be left without a token. Second, the "active" GUI process is already being negotiated
// between the GUIs and the daemon. Having the sync service fetch the token, via the daemon,
// utilizes the already negotiated active GUI process for token retrieval.
- (void)APNSTokenChanged;

// The GUI process forwards APNS messages to the sync service.
- (void)handleAPNSMessage:(NSDictionary *)message;
@end

@interface SNTXPCSyncServiceInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTSyncServiceXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)syncServiceInterface;

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceID;

///
///  Retrieve a pre-configured MOLXPCConnection for communicating with syncservice.
///  Connections just needs any handlers set and then can be resumed and used.
///
+ (MOLXPCConnection *)configuredConnection;

@end

///
///  Protocol implemented by santactl sync and used to receive log messages from
///  the syncservice during a user initiated sync.
///
@protocol SNTSyncServiceLogReceiverXPC
- (void)didReceiveLog:(NSString *)log withType:(os_log_type_t)logType;
@end
