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
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"

///
///  Protocol implemented by syncservice and utilized by daemon and ctl for communication with a
///  sync server.
///
@protocol SNTSyncServiceXPC
- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events reply:(void (^)(BOOL))reply;
- (void)postBundleEventToSyncServer:(SNTStoredExecutionEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply;
- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply;
- (void)pushNotificationServerAddress:(void (^)(NSString *))reply;

// Array of telemetry files to export. Files will be exported as a single stream to the destination
// provided in the config. The streamed files will be listed under the the provided file name. The
// total size, in bytes, of all files must be provided. The reply block responds YES if all files
// were exported, and NO if any failures occurred.
- (void)exportTelemetryFiles:(NSArray<NSFileHandle *> *)fds
                    fileName:(NSString *)fileName
                   totalSize:(NSUInteger)totalSize
                 contentType:(NSString *)contentType
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
