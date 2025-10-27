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
#include <string.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/santasyncservice/SNTSyncState.h"

// Include NATS C client header
extern "C" {
#import "src/nats.h"
}

@interface SNTPushClientNATS ()
@property(weak) id<SNTPushNotificationsSyncDelegate> syncDelegate;
@property(nonatomic) natsConnection *conn;
@property(nonatomic) natsSubscription *deviceSub;
@property(nonatomic) natsSubscription *globalSub;
@property(nonatomic)
    NSMutableArray<NSValue *> *tagSubscriptions;        // Array of natsSubscription pointers
@property(nonatomic) dispatch_queue_t connectionQueue;  // Single queue for connection management
@property(nonatomic) dispatch_queue_t messageQueue;     // Queue for processing messages
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic, readwrite) NSUInteger fullSyncInterval;
@property(atomic) BOOL isShuttingDown;
// Push notification configuration from preflight
@property(nonatomic, copy) NSString *pushServer;
@property(nonatomic, copy) NSString *pushToken;  // nkey
@property(nonatomic, copy) NSString *jwt;
@property(nonatomic, copy) NSString *pushDeviceID;
@property(nonatomic, copy) NSArray<NSString *> *tags;
@property(nonatomic) BOOL hasSyncedWithServer;
// Connection retry state
@property(nonatomic) dispatch_source_t connectionRetryTimer;
@property(nonatomic) NSTimeInterval currentRetryDelay;
@property(nonatomic) NSInteger retryAttempt;
@property(nonatomic) BOOL isRetrying;
@end

@implementation SNTPushClientNATS

- (instancetype)initWithSyncDelegate:(id<SNTPushNotificationsSyncDelegate>)syncDelegate {
  self = [super init];
  if (self) {
    _syncDelegate = syncDelegate;
    _fullSyncInterval = kDefaultPushNotificationsFullSyncInterval;
    _connectionQueue =
        dispatch_queue_create("com.northpolesec.santa.nats.connection", DISPATCH_QUEUE_SERIAL);
    _messageQueue =
        dispatch_queue_create("com.northpolesec.santa.nats.message", DISPATCH_QUEUE_SERIAL);
    _isShuttingDown = NO;
    _hasSyncedWithServer = NO;
    _tagSubscriptions = [NSMutableArray array];
    _currentRetryDelay = 1.0;  // Start with 1 second
    _retryAttempt = 0;
    _isRetrying = NO;

    // Don't connect immediately - wait for preflight to provide configuration
    LOGI(@"NATS push client: Initialized, waiting for preflight configuration");
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

- (void)configureWithPushServer:(NSString *)server
                      pushToken:(NSString *)token
                            jwt:(NSString *)jwt
                   pushDeviceID:(NSString *)deviceID
                           tags:(NSArray<NSString *> *)tags {
  dispatch_async(self.connectionQueue, ^{
    if (self.isShuttingDown) return;

    NSString *fullServer;
#ifdef SANTA_FORCE_SYNC_V2
    // In debug builds, allow overriding the domain suffix
    fullServer = server;
    LOGW(@"NATS: Domain suffix disabled for debugging - using server as-is: %@", fullServer);
#else
    // Always append domain suffix in release builds 
    fullServer = [NSString stringWithFormat:@"%@.push.northpole.security", server];
#endif

    // Check if device ID has changed
    BOOL deviceIDChanged = NO;
    if (self.pushDeviceID == nil && deviceID != nil) {
      deviceIDChanged = YES;
    } else if (self.pushDeviceID != nil && deviceID == nil) {
      deviceIDChanged = YES;
    } else if (self.pushDeviceID != nil && deviceID != nil) {
      deviceIDChanged = ![self.pushDeviceID isEqualToString:deviceID];
    }

    if (deviceIDChanged) {
      LOGI(@"NATS: Push device ID changed from '%@' to '%@'", self.pushDeviceID ?: @"(none)",
           deviceID ?: @"(none)");
    }

    // Check if tags have changed
    BOOL tagsChanged = NO;
    if (self.tags == nil && tags != nil) {
      tagsChanged = YES;
    } else if (self.tags != nil && tags == nil) {
      tagsChanged = YES;
    } else if (self.tags != nil && tags != nil) {
      NSSet *oldTagSet = [NSSet setWithArray:self.tags];
      NSSet *newTagSet = [NSSet setWithArray:tags];
      tagsChanged = ![oldTagSet isEqualToSet:newTagSet];
    }

    // If device ID or tags changed, resubscribe to all topics
    if ((deviceIDChanged || tagsChanged) && self.conn) {
      if (deviceIDChanged) {
        LOGI(@"NATS: Device ID changed, resubscribing to all topics");
      } else {
        LOGI(@"NATS: Tags changed, resubscribing to all topics");
      }
      [self unsubscribeAll];
    }

    // Store configuration
    self.pushServer = fullServer;
    self.pushToken = token;
    self.jwt = jwt;
    self.pushDeviceID = deviceID;
    self.tags = tags;
    self.hasSyncedWithServer = YES;

    LOGI(@"NATS: Configured with server: %@, deviceID: %@, tags: %@", fullServer, deviceID, tags);

    // If device ID or tags changed and we're connected, resubscribe with new configuration
    if ((deviceIDChanged || tagsChanged) && self.conn) {
      [self subscribe];
    }
  });
}

- (BOOL)hasRequiredConfiguration {
  return self.hasSyncedWithServer && self.pushServer && self.pushToken && self.jwt &&
         self.pushDeviceID;
}

- (void)connectIfConfigured {
  dispatch_async(self.connectionQueue, ^{
    if (self.isShuttingDown) return;

    // Only connect if we have configuration
    if ([self hasRequiredConfiguration]) {
      [self connect];
    } else {
      LOGD(@"NATS: Not connecting - missing configuration");
    }
  });
}

- (void)connect {
  dispatch_async(self.connectionQueue, ^{
    if (self.isShuttingDown) return;

    if (self.conn) {
      LOGD(@"NATS already connected");
      return;
    }

    // Check if we have teh necessary configuration to connect to the push service.
    if (![self hasRequiredConfiguration]) {
      LOGD(@"NATS: Not connecting - waiting for preflight configuration");
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

    // Set server URL with TLS unless debug mode is enabled
    NSString *serverURL;

#if defined(SANTA_FORCE_SYNC_V2) && defined(SANTA_NATS_DISABLE_TLS)
    serverURL = [NSString stringWithFormat:@"nats://%@", self.pushServer];
    LOGW(@"NATS: TLS disabled for debugging - using insecure connection on %@", serverURL);
#else 
      serverURL = [NSString stringWithFormat:@"tls://%@", self.pushServer];
#endif

    LOGI(@"NATS: Using connection to %@", serverURL);

    status = natsOptions_SetURL(opts, [serverURL UTF8String]);
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to set URL %@: %s", serverURL, natsStatus_GetText(status));
      natsOptions_Destroy(opts);
      return;
    }

    // Set nkey and JWT for authentication
    // Create a combined string with JWT and seed (nkey) separated by newlines
    NSString *jwtAndSeed = [NSString
        stringWithFormat:
            @"-----BEGIN NATS USER JWT-----\n%@\n------END NATS USER JWT------\n\n-----BEGIN USER "
            @"NKEY SEED-----\n%@\n------END USER NKEY SEED------",
            self.jwt, self.pushToken];

    status = natsOptions_SetUserCredentialsFromMemory(opts, [jwtAndSeed UTF8String]);
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to set credentials: %s", natsStatus_GetText(status));
      natsOptions_Destroy(opts);
      return;
    }

    // Connection options
    natsOptions_SetAllowReconnect(opts, true);
    natsOptions_SetMaxReconnect(opts, -1);  // Infinite reconnects

    // Set error callback to catch subscription violations and other errors
    natsOptions_SetErrorHandler(opts, &errorHandler, (__bridge void *)self);

    // Set connection callbacks for better monitoring
    natsOptions_SetDisconnectedCB(opts, &disconnectedCallback, (__bridge void *)self);
    natsOptions_SetReconnectedCB(opts, &reconnectedCallback, (__bridge void *)self);
    natsOptions_SetClosedCB(opts, &closedCallback, (__bridge void *)self);

    // Create connection
    status = natsConnection_Connect(&self->_conn, opts);
    natsOptions_Destroy(opts);

    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to connect: %s", natsStatus_GetText(status));
      [self scheduleConnectionRetry];
      return;
    }

    LOGI(@"NATS: Connected to %@", serverURL);
    self.isConnected = YES;

    // Reset retry state on successful connection
    self.retryAttempt = 0;
    self.currentRetryDelay = 1.0;
    self.isRetrying = NO;
    if (self.connectionRetryTimer) {
      dispatch_source_cancel(self.connectionRetryTimer);
      self.connectionRetryTimer = nil;
    }

    // Subscribe to topics
    [self subscribe];
  });
}

- (void)disconnectWithCompletion:(void (^)(void))completion {
  // Early return if nothing to disconnect
  if (!self.conn && !self.deviceSub && !self.globalSub && self.tagSubscriptions.count == 0) {
    if (completion) {
      dispatch_async(dispatch_get_main_queue(), completion);
    }
    return;
  }

  self.isShuttingDown = YES;

  dispatch_async(self.connectionQueue, ^{
    LOGD(@"NATS: Starting disconnect");

    // Cancel any pending retry timer
    if (self.connectionRetryTimer) {
      dispatch_source_cancel(self.connectionRetryTimer);
      self.connectionRetryTimer = nil;
    }
    self.isRetrying = NO;

    // Use unsubscribeAll to avoid code duplication
    [self unsubscribeAll];

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

- (void)cleanupSubscription:(natsSubscription **)subscription {
  if (subscription && *subscription) {
    natsSubscription_Unsubscribe(*subscription);
    natsSubscription_Destroy(*subscription);
    *subscription = NULL;
  }
}

- (void)unsubscribeAll {
  // This should only be called from within connectionQueue
  LOGD(@"NATS: Unsubscribing from all topics");

  // Unsubscribe device subscription
  [self cleanupSubscription:&_deviceSub];

  // Unsubscribe global subscription
  [self cleanupSubscription:&_globalSub];

  // Unsubscribe all tag subscriptions
  for (NSValue *subValue in self.tagSubscriptions) {
    natsSubscription *sub = (natsSubscription *)[subValue pointerValue];
    if (sub) {
      natsSubscription_Unsubscribe(sub);
      natsSubscription_Destroy(sub);
    }
  }
  [self.tagSubscriptions removeAllObjects];

  LOGD(@"NATS: All topics unsubscribed");
}

- (NSString *)buildTopicFromTag:(NSString *)tag {
  NSString *processedTag = tag;

  // IMPORTANT: santa.host.* topics should never be processed as tags
  if ([tag hasPrefix:@"santa.host."]) {
    LOGE(@"NATS: Attempted to process host topic '%@' as tag - this should not happen", tag);
    // Return the original tag to let validation fail it
    return tag;
  }

  // If tag already has santa.tag. prefix, extract just the tag part
  if ([tag hasPrefix:@"santa.tag."]) {
    processedTag = [tag substringFromIndex:10];  // Length of "santa.tag."
    LOGD(@"NATS: Tag already has prefix, extracted: '%@'", processedTag);
  }

  // Strip hyphens and periods from tag for NATS compatibility
  NSString *sanitizedTag = [processedTag stringByReplacingOccurrencesOfString:@"-" withString:@""];
  sanitizedTag = [sanitizedTag stringByReplacingOccurrencesOfString:@"." withString:@""];
  LOGD(@"NATS: Sanitized tag: '%@'", sanitizedTag);

  // Build as santa.tag.<sanitized>
  NSString *tagTopic = [NSString stringWithFormat:@"santa.tag.%@", sanitizedTag];
  LOGD(@"NATS: Built tag topic: '%@'", tagTopic);
  return tagTopic;
}

- (BOOL)isValidNATSTopic:(NSString *)topic {
  if (!topic || topic.length == 0) {
    return NO;
  }

  NSString *suffix = nil;

  // Check if topic starts with santa.host. or santa.tag.
  if ([topic hasPrefix:@"santa.host."]) {
    suffix = [topic substringFromIndex:11];
  } else if ([topic hasPrefix:@"santa.tag."]) {
    suffix = [topic substringFromIndex:10];
  } else {
    return NO;  // Topic doesn't start with allowed prefixes
  }

  // Validate suffix: must exist and cannot contain periods or hyphens
  return suffix.length > 0 && [suffix rangeOfString:@"."].location == NSNotFound &&
         [suffix rangeOfString:@"-"].location == NSNotFound;
}

- (void)subscribe {
  if (self.isShuttingDown) return;

  natsStatus status;
  NSString *deviceTopic = nil;

  // Check if we should skip device subscription (for debugging)
  BOOL skipDeviceSubscription = NO;
#ifdef DEBUG
  if (getenv("SANTA_NATS_SKIP_DEVICE_SUB")) {
    skipDeviceSubscription = YES;
    LOGW(@"NATS: Skipping device subscription due to SANTA_NATS_SKIP_DEVICE_SUB");
  }
#endif

  if (!skipDeviceSubscription) {
    // Use push device ID from preflight
    if (!self.pushDeviceID) {
      LOGE(@"NATS: No push device ID available for subscription");
      // Don't return - continue with other subscriptions
    } else {
      // Log the raw push device ID to debug
      LOGI(@"NATS: Push device ID from preflight: '%@'", self.pushDeviceID);

      // Sanitize device ID - remove periods and hyphens for NATS compatibility
      NSString *sanitizedDeviceID = [self.pushDeviceID stringByReplacingOccurrencesOfString:@"-"
                                                                                 withString:@""];
      sanitizedDeviceID = [sanitizedDeviceID stringByReplacingOccurrencesOfString:@"."
                                                                       withString:@""];

      if (![sanitizedDeviceID isEqualToString:self.pushDeviceID]) {
        LOGW(@"NATS: Sanitized device ID from '%@' to '%@' (removed periods/hyphens)",
             self.pushDeviceID, sanitizedDeviceID);
      }

      if (sanitizedDeviceID.length == 0) {
        LOGE(@"NATS: Device ID became empty after sanitization");
        return;
      } else {
        // Subscribe to device-specific topic: santa.host.<device_id>
        deviceTopic = [NSString stringWithFormat:@"santa.host.%@", sanitizedDeviceID];
      }

      // Final validation of the complete topic
      if (![self isValidNATSTopic:deviceTopic]) {
        LOGE(@"NATS: Invalid device topic: %@", deviceTopic);
      } else {
        LOGI(@"NATS: Attempting to subscribe to device topic: %@", deviceTopic);

        status = natsConnection_Subscribe(&_deviceSub, self.conn, [deviceTopic UTF8String],
                                          &messageHandler, (__bridge void *)self);

        if (status != NATS_OK) {
          LOGE(@"NATS: Failed to subscribe to device topic %@: %s (status: %d)", deviceTopic,
               natsStatus_GetText(status), status);
          // Log connection info for debugging
          char urlBuffer[256];
          natsStatus urlStatus =
              natsConnection_GetConnectedUrl(self.conn, urlBuffer, sizeof(urlBuffer));
          if (urlStatus == NATS_OK) {
            LOGE(@"NATS: Connection URL: %s", urlBuffer);
          } else {
            LOGE(@"NATS: Could not get connection URL");
          }
          LOGW(@"NATS: Continuing without device-specific subscription - will use tag-based topics "
               @"only");
        } else {
          LOGI(@"NATS: Successfully subscribed to device topic: %@", deviceTopic);
        }
      }
    }
  }
}

// Subscribe to global tag: santa.tag.global
NSString *globalTagTopic = @"santa.tag.global";

// Validate global tag topic
if (![self isValidNATSTopic:globalTagTopic]) {
  LOGE(@"NATS: Invalid global tag topic: %@", globalTagTopic);
} else {
  status = natsConnection_Subscribe(&_globalSub, self.conn, [globalTagTopic UTF8String],
                                    &messageHandler, (__bridge void *)self);

  if (status != NATS_OK) {
    LOGE(@"NATS: Failed to subscribe to global tag topic: %s", natsStatus_GetText(status));
  } else {
    LOGI(@"NATS: Subscribed to global tag topic: %@", globalTagTopic);
  }
}

// Subscribe to all tags from preflight: santa.tag.<tag>
if (self.tags && self.tags.count > 0) {
  LOGD(@"NATS: Processing %lu tags from preflight", (unsigned long)self.tags.count);

  // Keep track of already subscribed topics to avoid duplicates
  NSMutableSet *subscribedTopics = [NSMutableSet set];
  if (deviceTopic) {
    [subscribedTopics addObject:deviceTopic];
  }
  [subscribedTopics addObject:globalTagTopic];

  for (NSString *tag in self.tags) {
    LOGD(@"NATS: Processing tag: '%@'", tag);

    // Skip santa.host.* topics in tags - these should not be in the tags array
    if ([tag hasPrefix:@"santa.host."]) {
      LOGW(@"NATS: Skipping host topic in tags array: %@ (host topics should not be in tags)", tag);
      continue;
    }

    // Build the topic from the tag
    NSString *tagTopic = [self buildTopicFromTag:tag];

    // Double-check the built topic doesn't start with santa.host.
    if ([tagTopic hasPrefix:@"santa.host."]) {
      LOGE(@"NATS: Built topic still has host prefix: %@ from tag: %@", tagTopic, tag);
      continue;
    }

    // Skip if we've already subscribed to this topic
    if ([subscribedTopics containsObject:tagTopic]) {
      LOGD(@"NATS: Skipping duplicate subscription to: %@", tagTopic);
      continue;
    }

    // Validate tag topic
    if (![self isValidNATSTopic:tagTopic]) {
      LOGE(@"NATS: Invalid tag topic: %@", tagTopic);
      continue;
    }

    [subscribedTopics addObject:tagTopic];

    natsSubscription *tagSub = NULL;
    status = natsConnection_Subscribe(&tagSub, self.conn, [tagTopic UTF8String], &messageHandler,
                                      (__bridge void *)self);

    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to subscribe to tag topic %@: %s", tagTopic, natsStatus_GetText(status));
    } else {
      LOGI(@"NATS: Subscribed to tag topic: %@", tagTopic);
      // Store the subscription for later cleanup
      [self.tagSubscriptions addObject:[NSValue valueWithPointer:tagSub]];
    }
  }
}
}

// NATS message handler
static void messageHandler(natsConnection *nc, natsSubscription *sub, natsMsg *msg, void *closure) {
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

// NATS error handler callback
static void errorHandler(natsConnection *nc, natsSubscription *sub, natsStatus err, void *closure) {
  if (!closure) return;

  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  const char *lastError = natsStatus_GetText(err);
  const char *subSubject = sub ? natsSubscription_GetSubject(sub) : "unknown";

  LOGE(@"NATS Error: %s (status: %d) on subscription: %s", lastError ? lastError : "unknown error",
       err, subSubject);

  // Check for specific error types
  // NATS doesn't expose specific permission violation status, but we can check the error text
  if (err == NATS_ERR || (lastError && strstr(lastError, "violation")) ||
      (lastError && strstr(lastError, "Permitted"))) {
    LOGE(@"NATS: Permission/Subscription violation on subject: %s", subSubject);

    // Check if this is a device subscription error
    if (subSubject && strstr(subSubject, "santa.host")) {
      LOGE(@"NATS: Device-specific subscription not permitted by server JWT");
      // Don't mark connection as failed - other subscriptions might work
    } else {
      // Mark connection as failed if we get permission violations on other subjects
      dispatch_async(self.connectionQueue, ^{
        self.isConnected = NO;
      });
    }
  }
}

// NATS disconnected callback
static void disconnectedCallback(natsConnection *nc, void *closure) {
  if (!closure) return;
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  LOGW(@"NATS: Disconnected from server");
  dispatch_async(self.connectionQueue, ^{
    self.isConnected = NO;
  });
}

// NATS reconnected callback
static void reconnectedCallback(natsConnection *nc, void *closure) {
  if (!closure) return;
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  LOGI(@"NATS: Reconnected to server");
  dispatch_async(self.connectionQueue, ^{
    self.isConnected = YES;

    // Trigger sync with jitter to avoid thundering herd
    // We might have missed push notifications while disconnected
    if (!self.isShuttingDown) {
      // Calculate jitter: random delay between 0 and 30 seconds
      uint32_t jitterSeconds = arc4random_uniform(30);

      LOGI(@"NATS: Scheduling sync after reconnect with %u second jitter delay", jitterSeconds);

      dispatch_after(dispatch_time(DISPATCH_TIME_NOW, jitterSeconds * NSEC_PER_SEC),
                     dispatch_get_main_queue(), ^{
                       if (!self.isShuttingDown && self.isConnected) {
                         LOGI(@"NATS: Triggering sync after reconnection (jitter delay completed)");
                         [self.syncDelegate sync];
                       }
                     });
    }
  });
}

// NATS closed callback
static void closedCallback(natsConnection *nc, void *closure) {
  if (!closure) return;
  SNTPushClientNATS *self = (__bridge SNTPushClientNATS *)closure;
  LOGI(@"NATS: Connection closed");
  dispatch_async(self.connectionQueue, ^{
    self.isConnected = NO;
  });
}

// Schedule a connection retry with exponential backoff and jitter
- (void)scheduleConnectionRetry {
  if (self.isShuttingDown || self.isRetrying) return;

  self.isRetrying = YES;
  self.retryAttempt++;

  // Calculate exponential backoff with jitter
  // Base delay doubles each attempt: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s
  NSTimeInterval baseDelay = pow(2.0, MIN(self.retryAttempt - 1, 8));  // Cap at 2^8 = 256 seconds

  // Add jitter: ±25% randomization to prevent thundering herd
  double jitterFactor = 0.75 + (0.5 * ((double)arc4random_uniform(UINT32_MAX) / UINT32_MAX));
  self.currentRetryDelay = baseDelay * jitterFactor;

  // Cap at 5-10 minutes (randomly between 300-600 seconds) after initial backoff
  if (self.retryAttempt > 9) {
    self.currentRetryDelay = 300.0 + arc4random_uniform(301);  // 5-10 minutes
  }

  LOGW(@"NATS: Connection failed, will retry in %.1f seconds (attempt %ld)", self.currentRetryDelay,
       (long)self.retryAttempt);

  // Cancel any existing retry timer
  if (self.connectionRetryTimer) {
    dispatch_source_cancel(self.connectionRetryTimer);
    self.connectionRetryTimer = nil;
  }

  // Create retry timer
  self.connectionRetryTimer =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.connectionQueue);
  if (!self.connectionRetryTimer) {
    LOGE(@"NATS: Failed to create retry timer");
    self.isRetrying = NO;
    return;
  }

  dispatch_source_set_timer(
      self.connectionRetryTimer,
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.currentRetryDelay * NSEC_PER_SEC)),
      DISPATCH_TIME_FOREVER,
      (int64_t)(0.1 * NSEC_PER_SEC));  // 100ms leeway

  __weak SNTPushClientNATS *weakSelf = self;
  dispatch_source_set_event_handler(self.connectionRetryTimer, ^{
    __strong SNTPushClientNATS *strongSelf = weakSelf;
    if (!strongSelf || strongSelf.isShuttingDown) return;

    strongSelf.isRetrying = NO;
    if (strongSelf.connectionRetryTimer) {
      dispatch_source_cancel(strongSelf.connectionRetryTimer);
      strongSelf.connectionRetryTimer = nil;
    }

    LOGI(@"NATS: Retrying connection (attempt %ld)", (long)strongSelf.retryAttempt);
    [strongSelf connect];
  });

  dispatch_resume(self.connectionRetryTimer);
}

#pragma mark - SNTPushNotificationsClientDelegate
- (NSString *)token {
  // NATS doesn't use tokens like APNS/FCM
  return [[SNTConfigurator configurator] machineID];
}

- (void)handlePreflightSyncState:(SNTSyncState *)syncState {
  LOGD(@"NATS: handlePreflightSyncState - server: %@, deviceID: %@", syncState.pushServer,
       syncState.pushDeviceID);

  // Check if we have push configuration from preflight
  if (syncState.pushServer && syncState.pushNKey && syncState.pushJWT && syncState.pushDeviceID) {
    // Configure with preflight data
    [self configureWithPushServer:syncState.pushServer
                        pushToken:syncState.pushNKey
                              jwt:syncState.pushJWT
                     pushDeviceID:syncState.pushDeviceID
                             tags:syncState.pushTags];

    // Now attempt to connect
    [self connectIfConfigured];
  } else {
    NSMutableArray *missing = [NSMutableArray array];
    if (!syncState.pushServer) [missing addObject:@"server"];
    if (!syncState.pushNKey) [missing addObject:@"nkey"];
    if (!syncState.pushJWT) [missing addObject:@"JWT"];
    if (!syncState.pushDeviceID) [missing addObject:@"device ID"];
    LOGW(@"NATS: Missing required push configuration from preflight: %@",
         [missing componentsJoinedByString:@", "]);
  }

  // Update sync interval to avoid polling Workshop.
  if (syncState.pushNotificationsFullSyncInterval > 0) {
    self.fullSyncInterval = syncState.pushNotificationsFullSyncInterval;
  }
}

@end
