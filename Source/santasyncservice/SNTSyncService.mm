/// Copyright 2022 Google Inc. All rights reserved.
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

#import "Source/santasyncservice/SNTSyncService.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santasyncservice/SNTPolaris.h"
#import "Source/santasyncservice/SNTStreamingMultipartFormData.h"
#import "Source/santasyncservice/SNTSyncBroadcaster.h"
#import "Source/santasyncservice/SNTSyncManager.h"

@interface SNTSyncService ()
@property(nonatomic, readonly) SNTSyncManager *syncManager;
@property(nonatomic, readonly) MOLXPCConnection *daemonConn;
@property(nonatomic, readonly) NSMutableArray *logListeners;

@property(nonatomic) dispatch_source_t statsSubmissionTimer;
@property NSDate *lastStatsSubmissionAttempt;
@property NSString *lastStatsSubmissionVersion;
@property NSString *currentVersion;
@end

@implementation SNTSyncService

- (instancetype)init {
  self = [super init];
  if (self) {
    _logListeners = [NSMutableArray array];
    MOLXPCConnection *daemonConn = [SNTXPCControlInterface configuredConnection];
    daemonConn.invalidationHandler = ^(void) {
      // Spindown this process if we can't establish a connection
      // or if the daemon is killed or crashes.
      // If we are needed we will be re-launched.
      [self spindown];
    };
    [daemonConn resume];

    // Ensure we have no privileges
    if (!DropRootPrivileges()) {
      LOGE(@"Failed to drop root privileges. Exiting.");
      exit(1);
    }

    // Initialize SNTConfigurator ONLY after privileges have been dropped.
    [SNTConfigurator configurator];
    NSDictionary *infoDict = [[NSBundle mainBundle] infoDictionary];
    _currentVersion = infoDict[@"CFBundleVersion"];
    LOGI(@"Started, version %@", _currentVersion);

    // Dropping root privileges to the 'nobody' user causes the default NSURLCache to throw
    // sandbox errors, which are benign but annoying. This line disables the cache entirely.
    [NSURLCache setSharedURLCache:[[NSURLCache alloc] initWithMemoryCapacity:0
                                                                diskCapacity:0
                                                                    diskPath:nil]];

    _daemonConn = daemonConn;
    _syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:daemonConn];

    // This service should only start up if com.northpolesec.santa.daemon
    // noticed there is sync server configured and established a connection
    // with us. Go ahead and start syncing!
    [_syncManager syncSecondsFromNow:15];

    // Start the stat submission thread, which spins up daily to submit stats to Polaris
    // IF AND ONLY IF the user has enabled stat collection.
    [self statSubmissionThread];
  }
  return self;
}

- (void)postEventsToSyncServer:(NSArray<SNTStoredEvent *> *)events {
  [self.syncManager postEventsToSyncServer:events];
}

- (void)postBundleEventToSyncServer:(SNTStoredExecutionEvent *)event
                              reply:(void (^)(SNTBundleEventAction))reply {
  [self.syncManager postBundleEventToSyncServer:event reply:reply];
}

- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply {
  [self.syncManager pushNotificationStatus:reply];
}

- (void)exportTelemetryFiles:(NSArray<NSFileHandle *> *)fds
                    fileName:(NSString *)fileName
                      config:(SNTExportConfiguration *)config
                       reply:(void (^)(NSArray<NSNumber *> *))reply {
  // TODO: Support multiple telemetry files.
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:config.formValues
                                                          file:fds.firstObject
                                                      fileName:fileName];

  NSURLSessionConfiguration *sessionConfig =
      [NSURLSessionConfiguration ephemeralSessionConfiguration];
  NSURLSession *session = [NSURLSession sessionWithConfiguration:sessionConfig];
  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:config.url];
  request.HTTPBodyStream = stream.stream;
  [request setValue:stream.contentType forHTTPHeaderField:@"Content-Type"];
  [request setValue:[NSString stringWithFormat:@"%lu", stream.contentLength]
      forHTTPHeaderField:@"Content-Length"];
  [request setHTTPMethod:@"POST"];

  NSURLSessionDataTask *task = [session
      dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
          // Capture stream to keep it alive until the upload has completed.
          __unused SNTStreamingMultipartFormData *capturedStream = stream;

          BOOL success = NO;
          NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
          if (httpResponse.statusCode == 200 || httpResponse.statusCode == 204) {
            success = YES;
            LOGD(@"Successfully exported telemetry file: %@", fileName);
          } else {
            LOGE(@"Failed to export file: %@, status: %d: error: %@", fileName,
                 static_cast<uint8_t>(httpResponse.statusCode), error.localizedDescription);
          }
          reply(success ? @[ @(0) ] : nil);
        }];
  [task resume];
}

- (void)syncWithLogListener:(NSXPCListenerEndpoint *)logListener
                   syncType:(SNTSyncType)syncType
                      reply:(void (^)(SNTSyncStatusType))reply {
  MOLXPCConnection *ll = [[MOLXPCConnection alloc] initClientWithListener:logListener];
  ll.remoteInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(SNTSyncServiceLogReceiverXPC)];
  [ll resume];
  [self.syncManager syncType:syncType
                   withReply:^(SNTSyncStatusType status) {
                     if (status == SNTSyncStatusTypeSyncStarted) {
                       [[SNTSyncBroadcaster broadcaster] addLogListener:ll];
                       return;
                     }
                     [[SNTSyncBroadcaster broadcaster] barrier];
                     [[SNTSyncBroadcaster broadcaster] removeLogListener:ll];
                     reply(status);
                   }];
}

- (void)spindown {
  LOGI(@"Spinning down.");
  exit(0);
}

- (void)APNSTokenChanged {
  [self.syncManager APNSTokenChanged];
}

- (void)handleAPNSMessage:(NSDictionary *)message {
  [self.syncManager handleAPNSMessage:message];
}

- (void)statSubmissionThread {
  [[self.daemonConn synchronousRemoteObjectProxy]
      retrieveStatsState:^(NSDate *timestamp, NSString *version) {
        if (!timestamp || [timestamp timeIntervalSinceNow] > 0) {
          // There was no stored date or the stored date was in the future.
          // Change the timestamp to UNIX epoch time as a starting point.
          timestamp = [NSDate dateWithTimeIntervalSince1970:0];
        }
        self.lastStatsSubmissionAttempt = timestamp;
        self.lastStatsSubmissionVersion = version;
      }];

  self.statsSubmissionTimer = dispatch_source_create(
      DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));

  // Trigger a stats collection attempt every hour, however stats will only be
  // submitted once every 24 hours. The OS is given a 5 minute scheduling leeway.
  dispatch_source_set_timer(self.statsSubmissionTimer, DISPATCH_TIME_NOW, 3600 * NSEC_PER_SEC,
                            300 * NSEC_PER_SEC);

  WEAKIFY(self);
  dispatch_source_set_event_handler(self.statsSubmissionTimer, ^{
    STRONGIFY(self);

    // If stats collection is not enabled, skip this submission.
    if (![[SNTConfigurator configurator] enableStatsCollection]) {
      LOGI(@"Stats collection is disabled, skipping submission");
      return;
    }

    // Minimum submission interval is slightly less than one day (23h 30m).
    // This is to account for timing deltas between the dispatch source timer,
    // leeways, etc. Given submission is attempted every hour, this works out
    // to a submission happening about every 24 hours +/- 30 min.
    static const NSTimeInterval minSubmissionInterval = ((23 * 60) + 30) * 60;
    NSTimeInterval timeSinceLastOp =
        [[NSDate date] timeIntervalSinceDate:self.lastStatsSubmissionAttempt];

    // Skip submission if the version didn't change or the last submission was <23.5h ago
    if ([self.lastStatsSubmissionVersion isEqualToString:self.currentVersion] &&
        timeSinceLastOp < minSubmissionInterval) {
      return;
    }

    santa::SubmitStats([[SNTConfigurator configurator] statsOrganizationID]);

    // Inform the daemon to update persistent state
    self.lastStatsSubmissionAttempt = [NSDate now];
    self.lastStatsSubmissionVersion = self.currentVersion;
    [[self.daemonConn synchronousRemoteObjectProxy]
        saveStatsSubmissionAttemptTime:self.lastStatsSubmissionAttempt
                               version:self.lastStatsSubmissionVersion];
  });
  dispatch_resume(self.statsSubmissionTimer);
}

@end
