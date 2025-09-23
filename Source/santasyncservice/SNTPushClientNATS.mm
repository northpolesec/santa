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
@property(nonatomic) dispatch_queue_t connectionQueue; // Single queue for connection management
@property(nonatomic) dispatch_queue_t messageQueue;    // Queue for processing messages
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic, readwrite) NSUInteger fullSyncInterval;
@property(atomic) BOOL isShuttingDown;
@end

@implementation SNTPushClientNATS

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate {
  self = [super init];
  if (self) {
    _syncDelegate = syncDelegate;
    _fullSyncInterval = kDefaultPushNotificationsFullSyncInterval;
    _connectionQueue = dispatch_queue_create("com.northpolesec.santa.nats.connection", DISPATCH_QUEUE_SERIAL);
    _messageQueue = dispatch_queue_create("com.northpolesec.santa.nats.message", DISPATCH_QUEUE_SERIAL);
    _isShuttingDown = NO;
    
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
  // Don't call disconnect here to avoid race conditions
  // Cleanup should be done explicitly before dealloc
  if (self.conn || self.deviceSub || self.globalSub) {
    LOGW(@"NATS: Client deallocated without proper disconnect");
  }
}

- (void)connect {
  dispatch_async(self.connectionQueue, ^{
    if (self.isShuttingDown) return;
    
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
    // Assume we're going to change this ti push.northpole.security
    status = natsOptions_SetURL(opts, "nats://localhost:4222");
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to set URL: %s", natsStatus_GetText(status));
      natsOptions_Destroy(opts);
      return;
    }
    
    // Disable async callbacks to have better control
    natsOptions_SetAllowReconnect(opts, true);
    natsOptions_SetMaxReconnect(opts, -1); // Infinite reconnects
    
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
  [self disconnectWithCompletion:nil];
}

- (void)disconnectAndWait:(BOOL)wait {
  // If nothing to disconnect, return immediately
  if (!self.conn && !self.deviceSub && !self.globalSub) {
    return;
  }
  
  if (wait) {
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    [self disconnectWithCompletion:^{
      dispatch_semaphore_signal(sem);
    }];
    // Add timeout to prevent hanging forever
    dispatch_time_t timeout = dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC);
    long result = dispatch_semaphore_wait(sem, timeout);
    if (result != 0) {
      LOGE(@"NATS: Disconnect timed out after 1 second");
    }
  } else {
    [self disconnectWithCompletion:nil];
  }
}

- (void)disconnectWithCompletion:(void (^)(void))completion {
  self.isShuttingDown = YES;
  
  dispatch_async(self.connectionQueue, ^{
    LOGD(@"NATS: Starting disconnect");
    
    if (self.deviceSub) {
      LOGD(@"NATS: Destroying device subscription");
      natsSubscription_Destroy(self.deviceSub);
      self.deviceSub = NULL;
    }
    
    if (self.globalSub) {
      LOGD(@"NATS: Destroying global subscription");
      natsSubscription_Destroy(self.globalSub);
      self.globalSub = NULL;
    }
    
    if (self.conn) {
      LOGD(@"NATS: Closing connection");
      natsConnection_Close(self.conn);
      LOGD(@"NATS: Destroying connection");
      natsConnection_Destroy(self.conn);
      self.conn = NULL;
    }
    
    self.isConnected = NO;
    LOGI(@"NATS: Disconnected");
    
    if (completion) {
      dispatch_async(dispatch_get_main_queue(), completion);
    }
  });
}

- (void)subscribe {
  if (self.isShuttingDown) return;
  
  natsStatus status;
  
  // Get machine UUID
  NSString *machineID = [[SNTConfigurator configurator] machineID];
  if (!machineID) {
    LOGE(@"NATS: No machine ID available for subscription");
    return;
  }
  
  // Subscribe to device-specific topic
  // TODO make this take a format string from preflight for the the tenant ID
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
  if (!closure || !msg) {
    natsMsg_Destroy(msg);
    return;
  }
  
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  if (!self || self.isShuttingDown) {
    natsMsg_Destroy(msg);
    return;
  }
  
  const char *subject = natsMsg_GetSubject(msg);
  const char *data = natsMsg_GetData(msg);
  int dataLen = natsMsg_GetDataLength(msg);
  
  NSString *msgSubject = subject ? @(subject) : @"<unknown>";
  NSString *msgData = nil;
  if (data && dataLen > 0) {
    msgData = [[NSString alloc] initWithBytes:data length:dataLen encoding:NSUTF8StringEncoding];
  }
  
  LOGD(@"NATS: Received message on subject '%@': %@", msgSubject, msgData ?: @"<no data>");
  
  // Process on message queue to serialize handling
  dispatch_async(self.messageQueue, ^{
    if (!self.isShuttingDown) {
      LOGI(@"NATS: Triggering immediate sync due to message on %@", msgSubject);
      
      // Queue sync to main thread
      dispatch_async(dispatch_get_main_queue(), ^{
        if (!self.isShuttingDown) {
          [self.syncDelegate sync];
        }
      });
    }
  });
  
  natsMsg_Destroy(msg);
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
