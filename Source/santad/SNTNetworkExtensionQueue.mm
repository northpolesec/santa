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

#import "Source/santad/SNTNetworkExtensionQueue.h"

#import <Foundation/Foundation.h>

#include <utility>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeepCopy.h"
#import "Source/common/SNTError.h"
#include "Source/common/SNTKVOManager.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/ne/SNDXPCNetworkExtensionInterface.h"
#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"
#import "Source/common/ne/SNTXPCNetworkExtensionInterface.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#import "src/santanetd/SNDFlowInfo.h"
#import "src/santanetd/SNDProcessFlows.h"
#import "src/santanetd/SNDProcessInfo.h"

NSString *const kSantaNetworkExtensionProtocolVersion = @"1.0";

@interface SNTNetworkExtensionQueue () {
  std::shared_ptr<santa::Logger> _logger;
}
@property MOLXPCConnection *netExtConnection;
@property(readwrite) NSString *connectedProtocolVersion;
@property NSArray<SNTKVOManager *> *kvoWatchers;
@property(weak) SNTNotificationQueue *notifierQueue;
@property(weak) SNTSyncdQueue *syncdQueue;
@end

@implementation SNTNetworkExtensionQueue

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue *)notifierQueue
                           syncdQueue:(SNTSyncdQueue *)syncdQueue
                               logger:(std::shared_ptr<santa::Logger>)logger {
  self = [super init];
  if (self) {
    _notifierQueue = notifierQueue;
    _syncdQueue = syncdQueue;
    _logger = std::move(logger);

    WEAKIFY(self);

    _kvoWatchers = @[
      [[SNTKVOManager alloc]
          initWithObject:[SNTConfigurator configurator]
                selector:@selector(syncNetworkExtensionSettings)
                    type:[SNTSyncNetworkExtensionSettings class]
                callback:^(SNTSyncNetworkExtensionSettings *oldValue,
                           SNTSyncNetworkExtensionSettings *newValue) {
                  if ((!oldValue && !newValue) || [oldValue isEqual:newValue]) {
                    return;
                  }

                  STRONGIFY(self);

                  LOGI(@"SyncNetworkExtensionSettings changed: enable %d -> %d", oldValue.enable,
                       newValue.enable);

                  [self handleSettingsChanged:newValue];

                  // Force push notification client to reconnect.
                  // This resets the NATS connection state and triggers a sync
                  // to get fresh credentials and reconnect immediately.
                  LOGI(@"SNTNetworkExtensionQueue: Triggering push notification reconnect");
                  [self.syncdQueue pushNotificationReconnect];
                }],
    ];
  }
  return self;
}

- (void)handleSettingsChanged:(SNTSyncNetworkExtensionSettings *)settings {
  MOLXPCConnection *conn = self.notifierQueue.notifierConnection;
  if (!conn) {
    LOGW(@"Notifier connection unavailable; skipping filter enabled update (%d)", settings.enable);
    return;
  }

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // Update the filter enabled state via the GUI process
  [[conn remoteObjectProxy]
      setNetworkExtensionFilterEnabled:settings.enable
                                 reply:^(BOOL success) {
                                   if (success) {
                                     LOGI(@"Successfully updated network extension filter enabled "
                                          @"state");
                                   } else {
                                     LOGW(@"Failed to update network extension filter enabled "
                                          @"state");
                                   }

                                   dispatch_semaphore_signal(sema);
                                 }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
    LOGW(@"Timeout when attempting to set filter enabled state (%d)", settings.enable);
  }
}

- (void)handleNetworkFlows:(NSArray<SNDProcessFlows *> *)processFlows
               windowStart:(NSDate *)windowStart
                 windowEnd:(NSDate *)windowEnd {
  if (!processFlows.count) {
    return;
  }

  NSTimeInterval startSecs = windowStart.timeIntervalSince1970;
  NSTimeInterval endSecs = windowEnd.timeIntervalSince1970;
  struct timespec windowStartTS = {
      .tv_sec = static_cast<time_t>(startSecs),
      .tv_nsec = static_cast<long>((startSecs - static_cast<time_t>(startSecs)) * NSEC_PER_SEC),
  };
  struct timespec windowEndTS = {
      .tv_sec = static_cast<time_t>(endSecs),
      .tv_nsec = static_cast<long>((endSecs - static_cast<time_t>(endSecs)) * NSEC_PER_SEC),
  };

  for (SNDProcessFlows *pf in processFlows) {
    SNDProcessInfo *info = pf.processInfo;
    [pf enumerateFlowsUsingBlock:^(SNDFlowInfo *flow) {
      _logger->LogNetworkFlow(info, flow, windowStartTS, windowEndTS);
    }];
  }
}

- (NSDictionary *)handleRegistrationWithProtocolVersion:(NSString *)protocolVersion
                                                  error:(NSError **)error {
  if (self.netExtConnection) {
    LOGW(@"Network extension attempting to register but already connected, clearing stale "
         @"connection");
    // Clear the existing connection since it may be stale
    [self clearNetworkExtensionConnection];
  }

  if (protocolVersion.length == 0) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeNetworkExtensionProtocolVersionInvalid
                    message:@"Invalid protocol version"
                     detail:@"Protocol version cannot be nil or empty"];
    return nil;
  }

  // Validate protocol version matches "major.minor" format
  NSString *pattern = @"^\\d+\\.\\d+$";
  NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:pattern
                                                                         options:0
                                                                           error:nil];
  NSRange range = NSMakeRange(0, protocolVersion.length);
  NSTextCheckingResult *match = [regex firstMatchInString:protocolVersion options:0 range:range];

  if (!match) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeNetworkExtensionProtocolVersionInvalid
                    message:@"Invalid protocol version format"
                     detail:[NSString stringWithFormat:@"Protocol version must be in 'major.minor' "
                                                       @"format (e.g., '1.0'), received: '%@'",
                                                       protocolVersion]];
    return nil;
  }

  // Extract the major version now that it has been validated.
  // Note: Minor version not currently used
  auto [majorVersion, _] = [self protocolVersionComponents:protocolVersion];

  if (majorVersion < 1) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeNetworkExtensionProtocolVersionBad
                    message:@"Unsupported protocol version"
                     detail:[NSString stringWithFormat:@"Unsupported protocol version '%@'",
                                                       protocolVersion]];
    return nil;
  }

  // At this point we've successfully validated the client. Store important information
  // and go ahead and establish a connection back to the network extension daemon.
  self.connectedProtocolVersion = protocolVersion;
  [self establishNetworkExtensionConnection];

  return [self generateSettingsForProtocolVersion:self.connectedProtocolVersion];
}

- (void)establishNetworkExtensionConnection {
  LOGI(@"Establishing connection to network extension");

  WEAKIFY(self);

  MOLXPCConnection *conn = [SNTXPCNetworkExtensionInterface configuredConnection];
  conn.invalidationHandler = ^{
    STRONGIFY(self);
    LOGI(@"Network extension connection invalidated, clearing state");
    [self clearNetworkExtensionConnection];
  };
  [conn resume];

  self.netExtConnection = conn;
}

- (void)clearNetworkExtensionConnection {
  self.netExtConnection.invalidationHandler = nil;
  [self.netExtConnection invalidate];
  self.netExtConnection = nil;
  self.connectedProtocolVersion = nil;
}

- (std::pair<int, int>)protocolVersionComponents:(NSString *)protocolVersion {
  NSArray<NSString *> *components = [protocolVersion componentsSeparatedByString:@"."];
  return std::make_pair<int, int>([components[0] intValue], [components[1] intValue]);
}

- (NSDictionary *)generateSettingsForProtocolVersion:(NSString *)protocolVersion {
  if (!protocolVersion) {
    return nil;
  }

  NSMutableDictionary *settings = [NSMutableDictionary dictionary];
  auto [majorVersion, _] = [self protocolVersionComponents:self.connectedProtocolVersion];
  SNTSyncNetworkExtensionSettings *netExtSettings =
      [[SNTConfigurator configurator] syncNetworkExtensionSettings];

  if (majorVersion >= 1) {
    settings[@"enable"] = @(netExtSettings.enable);
  }

  return [settings sntDeepCopy];
}

@end
