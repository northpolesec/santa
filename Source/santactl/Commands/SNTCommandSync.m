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

#import <Foundation/Foundation.h>
#include <os/log.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandSync : SNTCommand <SNTCommandProtocol, SNTSyncServiceLogReceiverXPC>
@property BOOL enableDebugLogging;
@end

@implementation SNTCommandSync

REGISTER_COMMAND_NAME(@"sync")

#pragma mark SNTCommand protocol methods

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;  // We talk directly with the syncservice.
}

+ (NSString *)shortHelpText {
  return @"Synchronizes Santa with a configured server.";
}

+ (NSString *)longHelpText {
  return (@"If Santa is configured to synchronize with a server, "
          @"this is the command used for syncing.\n\n"
          @"Options:\n"
          @"  --clean: Perform a clean sync, erasing all existing non-transitive rules and\n"
          @"           requesting a clean sync from the server.\n"
          @"  --clean-all: Perform a clean sync, erasing all existing rules and requesting a\n"
          @"               clean sync from the server.");
}

- (void)runWithArguments:(NSArray *)arguments {
  // Ensure we have no privileges
  if (!DropRootPrivileges()) {
    TEE_LOGE(@"Failed to drop root privileges. Exiting.");
    exit(1);
  }

  if (![[SNTConfigurator configurator] syncBaseURL]) {
    TEE_LOGE(@"Missing SyncBaseURL. Exiting.");
    exit(1);
  }
  MOLXPCConnection *ss = [SNTXPCSyncServiceInterface configuredConnection];
  ss.invalidationHandler = ^(void) {
    TEE_LOGE(@"Failed to connect to the sync service.");
    exit(1);
  };
  [ss resume];

  NSXPCListener *logListener = [NSXPCListener anonymousListener];
  MOLXPCConnection *lr = [[MOLXPCConnection alloc] initServerWithListener:logListener];
  lr.exportedObject = self;
  lr.unprivilegedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(SNTSyncServiceLogReceiverXPC)];
  [lr resume];

  SNTSyncType syncType = SNTSyncTypeNormal;
  if ([NSProcessInfo.processInfo.arguments containsObject:@"--clean-all"]) {
    syncType = SNTSyncTypeCleanAll;
  } else if ([NSProcessInfo.processInfo.arguments containsObject:@"--clean"]) {
    syncType = SNTSyncTypeClean;
  }

  self.enableDebugLogging = [NSProcessInfo.processInfo.arguments containsObject:@"--debug"];

  [[ss remoteObjectProxy]
      syncWithLogListener:logListener.endpoint
                 syncType:syncType
                    reply:^(SNTSyncStatusType status) {
                      if (status == SNTSyncStatusTypeTooManySyncsInProgress) {
                        [self didReceiveLog:@"Too many syncs in progress, try again later."
                                   withType:OS_LOG_TYPE_ERROR];
                      }
                      exit((int)status);
                    }];

  // Do not return from this scope.
  [[NSRunLoop mainRunLoop] run];
}

/// Implement the SNTSyncServiceLogReceiverXPC protocol.
- (void)didReceiveLog:(NSString *)log withType:(os_log_type_t)logType {
  if (logType == OS_LOG_TYPE_DEBUG && !self.enableDebugLogging) {
    return;
  }
  printf("%s\n", log.UTF8String);
  fflush(stdout);
}

@end
