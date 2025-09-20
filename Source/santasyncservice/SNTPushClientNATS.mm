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

#import "Source/santasyncservice/SNTPushClientNATS.h"

#import <dispatch/dispatch.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"

// Include NATS C client header
extern "C" {
#import "src/nats.h"
}

@interface SNTPushClientNATS ()
@property(weak) id<SNTPushNotificationsSyncDelegate> syncDelegate;
@property(nonatomic) natsConnection *conn;
@property(nonatomic) natsSubscription *deviceSub;
@property(nonatomic) natsSubscription *globalSub;
@property(nonatomic) dispatch_queue_t natsQueue;
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic, readwrite) NSUInteger fullSyncInterval;
@end

@implementation SNTPushClientNATS

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate {
  self = [super init];
  if (self) {
    _syncDelegate = syncDelegate;
    _fullSyncInterval = kDefaultPushNotificationsFullSyncInterval;
    _natsQueue = dispatch_queue_create("com.northpolesec.santa.nats", DISPATCH_QUEUE_SERIAL);
    
    // Only attempt to connect if sync server is configured
    if ([[SNTConfigurator configurator] syncBaseURL]) {
      [self connect];
    } else {
      LOGI(@"NATS push client: No sync server configured, skipping connection");
    }
  }
  return self;
}

- (void)dealloc {
  [self disconnect];
}

- (void)connect {
  dispatch_async(self.natsQueue, ^{
    if (self.conn) {
      LOGD(@"NATS already connected");
      return;
    }
    
    natsStatus status;
    
    // Create connection options
    natsOptions *opts = NULL;
    status = natsOptions_Create(&opts);
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to create options: %s", natsStatus_GetText(status));
      return;
    }
    
    // Set server URL
    status = natsOptions_SetURL(opts, "nats://localhost:4222");
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to set URL: %s", natsStatus_GetText(status));
      natsOptions_Destroy(opts);
      return;
    }
    
    // Set connection callbacks
    natsOptions_SetDisconnectedCB(opts, &connectionDisconnectedCB, (__bridge void *)self);
    natsOptions_SetReconnectedCB(opts, &connectionReconnectedCB, (__bridge void *)self);
    natsOptions_SetClosedCB(opts, &connectionClosedCB, (__bridge void *)self);
    
    // Create connection
    status = natsConnection_Connect(&self->_conn, opts);
    natsOptions_Destroy(opts);
    
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to connect: %s", natsStatus_GetText(status));
      return;
    }
    
    LOGI(@"NATS: Connected to localhost:4222");
    self.isConnected = YES;
    
    // Subscribe to topics
    [self subscribe];
  });
}

- (void)disconnect {
  dispatch_sync(self.natsQueue, ^{
    if (self.deviceSub) {
      natsSubscription_Destroy(self.deviceSub);
      self.deviceSub = NULL;
    }
    
    if (self.globalSub) {
      natsSubscription_Destroy(self.globalSub);
      self.globalSub = NULL;
    }
    
    if (self.conn) {
      natsConnection_Close(self.conn);
      natsConnection_Destroy(self.conn);
      self.conn = NULL;
    }
    
    self.isConnected = NO;
    LOGI(@"NATS: Disconnected");
  });
}

- (void)subscribe {
  natsStatus status;
  
  // Get machine UUID
  NSString *machineID = [[SNTConfigurator configurator] machineID];
  if (!machineID) {
    LOGE(@"NATS: No machine ID available for subscription");
    return;
  }
  
  // Subscribe to device-specific topic
  NSString *deviceTopic = [NSString stringWithFormat:@"cloud.workshop.nps.santa.%@", machineID];
  status = natsConnection_Subscribe(&_deviceSub, self.conn, 
                                    [deviceTopic UTF8String],
                                    &messageHandler, 
                                    (__bridge void *)self);
  
  if (status != NATS_OK) {
    LOGE(@"NATS: Failed to subscribe to device topic %@: %s", 
         deviceTopic, natsStatus_GetText(status));
  } else {
    LOGI(@"NATS: Subscribed to device topic: %@", deviceTopic);
  }
  
  // Subscribe to global topic
  const char *globalTopic = "cloud.workshop.nps.santa.global";
  status = natsConnection_Subscribe(&_globalSub, self.conn, 
                                    globalTopic,
                                    &messageHandler, 
                                    (__bridge void *)self);
  
  if (status != NATS_OK) {
    LOGE(@"NATS: Failed to subscribe to global topic: %s", natsStatus_GetText(status));
  } else {
    LOGI(@"NATS: Subscribed to global topic: %s", globalTopic);
  }
}

// NATS message handler
static void messageHandler(natsConnection *nc, natsSubscription *sub, 
                          natsMsg *msg, void *closure) {
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  
  const char *subject = natsMsg_GetSubject(msg);
  const char *data = natsMsg_GetData(msg);
  int dataLen = natsMsg_GetDataLength(msg);
  
  NSString *msgSubject = subject ? @(subject) : @"<unknown>";
  NSString *msgData = nil;
  if (data && dataLen > 0) {
    msgData = [[NSString alloc] initWithBytes:data length:dataLen encoding:NSUTF8StringEncoding];
  }
  
  LOGD(@"NATS: Received message on subject '%@': %@", msgSubject, msgData ?: @"<no data>");
  
  // Trigger immediate sync
  dispatch_async(dispatch_get_main_queue(), ^{
    LOGI(@"NATS: Triggering immediate sync due to message on %@", msgSubject);
    [self.syncDelegate sync];
  });
  
  natsMsg_Destroy(msg);
}

// Connection callbacks
static void connectionDisconnectedCB(natsConnection *nc, void *closure) {
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  LOGW(@"NATS: Connection disconnected");
  self.isConnected = NO;
}

static void connectionReconnectedCB(natsConnection *nc, void *closure) {
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  LOGI(@"NATS: Connection reconnected");
  self.isConnected = YES;
}

static void connectionClosedCB(natsConnection *nc, void *closure) {
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  LOGI(@"NATS: Connection closed");
  self.isConnected = NO;
}

#pragma mark - SNTPushNotificationsClientDelegate

- (NSString *)token {
  // NATS doesn't use tokens like APNS/FCM
  return [[SNTConfigurator configurator] machineID];
}

- (void)handlePreflightSyncState:(SNTSyncState *)syncState {
  // Check if sync server configuration changed
  if (![[SNTConfigurator configurator] syncBaseURL]) {
    LOGI(@"NATS: Sync server no longer configured, disconnecting");
    [self disconnect];
  } else if (!self.isConnected) {
    LOGI(@"NATS: Sync server configured, attempting to connect");
    [self connect];
  }
}

@end