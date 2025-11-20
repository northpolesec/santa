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
#import "Source/santasyncservice/SNTPushClientNATSCommands.h"

#import <dispatch/dispatch.h>
#include <string.h>
#include <sys/cdefs.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include "commands/v1.pb.h"

__BEGIN_DECLS

// Include NATS C client header
#import "src/nats.h"

__END_DECLS

@interface SNTPushClientNATS ()
@property(weak) id<SNTPushNotificationsSyncDelegate> syncDelegate;
@property(nonatomic) natsConnection *conn;
// Array of natsSubscription pointers wrapped in NSValue
@property(nonatomic) NSMutableArray<NSValue *> *tagSubscriptions;
// Commands subscription
@property(nonatomic) natsSubscription *commandsSubscription;
// Single queue for connection management
@property(nonatomic) dispatch_queue_t connectionQueue;
// Queue for processing messages
@property(nonatomic) dispatch_queue_t messageQueue;
@property(atomic, readwrite) BOOL isConnected;
@property(nonatomic, readwrite) NSUInteger fullSyncInterval;
@property(atomic) BOOL isShuttingDown;
// Push notification configuration from preflight
@property(nonatomic, copy) NSString *pushServer;
// nkey
@property(nonatomic, copy) NSString *pushToken;
@property(nonatomic, copy) NSString *jwt;
@property(nonatomic, copy) NSString *pushDeviceID;
@property(nonatomic, copy) NSArray<NSString *> *tags;
// Connection retry state
@property(nonatomic) dispatch_source_t connectionRetryTimer;
@property(atomic) NSInteger retryAttempt;
@property(atomic) BOOL isRetrying;
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
    _tagSubscriptions = [NSMutableArray array];

    // Don't connect immediately - wait for preflight to provide configuration
    LOGI(@"NATS push client: Initialized, waiting for preflight configuration");
  }
  return self;
}

- (void)dealloc {
  // Don't call disconnect here to avoid race conditions
  // Cleanup should be done explicitly before dealloc
  if (self.conn && self.isConnected) {
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

    if (!server) {
      LOGE(@"NATS: Invalid push server domain. No server provided");
      return;
    }

    NSString *fullServer;
#ifdef DEBUG
    // In debug builds, allow overriding the domain suffix and avoid TLS checks.
    LOGW(@"NATS: Domain check disabled - using server as-is: %@", server);
#else
    // In release builds, validate the domain suffix.
    if (![server hasSuffix:@".push.northpole.security:443"]) {
        LOGE(@"NATS: Invalid push server domain. Must end with '.push.northpole.security', got: %@", server);
        return;
    }
    // Make sure we're using TLS for production builds.
    if (![server hasPrefix:@"tls://"]) {
        LOGE(@"NATS: Invalid push server domain. Must start with 'tls://', got: %@", server);
        return;
    }
#endif
    fullServer = server;

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

    // Check if credentials (JWT or NKey) have changed Credential changes
    // require a full reconnection since they're embedded in the connection
    BOOL credentialsChanged = NO;
    if (self.jwt == nil && jwt != nil) {
      credentialsChanged = YES;
    } else if (self.jwt != nil && jwt == nil) {
      credentialsChanged = YES;
    } else if (self.jwt != nil && jwt != nil) {
      credentialsChanged = ![self.jwt isEqualToString:jwt];
    }

    if (!credentialsChanged) {
      if (self.pushToken == nil && token != nil) {
        credentialsChanged = YES;
      } else if (self.pushToken != nil && token == nil) {
        credentialsChanged = YES;
      } else if (self.pushToken != nil && token != nil) {
        credentialsChanged = ![self.pushToken isEqualToString:token];
      }
    }

    if (credentialsChanged) {
      LOGI(@"NATS: Credentials changed - will reconnect with new JWT/NKey");
    }

    // Handle configuration changes
    BOOL isConnected = [self isConnectionAlive];

    if ((deviceIDChanged || tagsChanged || credentialsChanged) && isConnected) {
      if (credentialsChanged) {
        LOGI(@"NATS: Credentials changed, forcing disconnect and reconnect");
        // Must fully disconnect and reconnect since credentials are embedded in the connection
        [self unsubscribeAll];
        natsConnection_Close(self.conn);
        natsConnection_Destroy(self.conn);
        self.conn = NULL;
        self.isConnected = NO;
      } else if (deviceIDChanged) {
        LOGI(@"NATS: Device ID changed, resubscribing to all topics");
        [self unsubscribeAll];
      } else {
        LOGI(@"NATS: Tags changed, resubscribing to all topics");
        [self unsubscribeAll];
      }
    }

    // Store configuration
    self.pushServer = fullServer;
    self.pushToken = token;
    self.jwt = jwt;
    self.pushDeviceID = deviceID;
    self.tags = tags;

    LOGI(@"NATS: Configured with server: %@, deviceID: %@, tags: %@", fullServer, deviceID, tags);

    // Reconnect or resubscribe based on what changed
    if (credentialsChanged) {
      // Reconnect with new credentials
      [self connect];
    } else if ((deviceIDChanged || tagsChanged) && isConnected) {
      // Just resubscribe with new device ID or tags
      [self subscribe];
    }
  });
}

// Check if we have the necessary configuration to connect to the push service.
- (BOOL)hasRequiredConfiguration {
  return self.pushServer && self.pushToken && self.jwt && self.pushDeviceID;
}

// Check if the connection is actually alive by consulting both our flag and the NATS library.
// This should be called from within connectionQueue for thread safety.
- (BOOL)isConnectionAlive {
  if (!self.conn) {
    return NO;
  }

  // Check NATS library's view of the connection state
  if (natsConnection_IsClosed(self.conn)) {
    // Connection is closed according to NATS but our flag might be stale
    if (self.isConnected) {
      LOGW(@"NATS: Connection state mismatch - NATS reports closed but isConnected=YES");
      self.isConnected = NO;
    }
    return NO;
  }

  return self.isConnected;
}

- (void)connect {
  dispatch_async(self.connectionQueue, ^{
    if (self.isShuttingDown) return;

    // Check if we already have a live connection
    if ([self isConnectionAlive]) {
      LOGD(@"NATS already connected");
      return;
    }

    // Clean up any stale connection
    if (self.conn) {
      LOGW(@"NATS: Cleaning up stale connection before reconnecting");
      natsConnection_Destroy(self.conn);
      self.conn = NULL;
      self.isConnected = NO;
    }

    // Check if we have the necessary configuration to connect to the push service.
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

#ifndef DEBUG
    // Make sure it's running on push.northpole.security and on port 443
    if (![self.pushServer hasSuffix:@".push.northpole.security:443"]) {
      LOGE(@"NATS: Invalid push server domain. Must end with '.push.northpole.security:443', got: "
           @"%@",
           self.pushServer);
      natsOptions_Destroy(opts);
      return;
    }

    // Production builds must use TLS
    if (![self.pushServer hasPrefix:@"tls://"]) {
      LOGE(@"NATS: Invalid push server domain. Must start with 'tls://', got: %@", self.pushServer);
      natsOptions_Destroy(opts);
      return;
    }
#endif
    serverURL = self.pushServer;

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
    natsConnection *conn = NULL;
    status = natsConnection_Connect(&conn, opts);
    natsOptions_Destroy(opts);

    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to connect: %s", natsStatus_GetText(status));
      [self scheduleConnectionRetry];
      return;
    }

    LOGI(@"NATS: Connected to %@", serverURL);
    self.conn = conn;
    self.isConnected = YES;

    // Reset retry state on successful connection
    self.retryAttempt = 0;
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
  // Note: We check self.conn directly here rather than isConnectionAlive since we want to
  // clean up even if the connection is closed but resources still exist
  if (!self.conn && !self.isConnected && self.tagSubscriptions.count == 0 &&
      !self.commandsSubscription) {
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
  // Failure to unsubscribe is non-fatal - client continues operating
  LOGD(@"NATS: Unsubscribing from all topics");

  // Unsubscribe all tag subscriptions
  for (NSValue *subValue in self.tagSubscriptions) {
    natsSubscription *sub = (natsSubscription *)[subValue pointerValue];
    if (sub) {
      natsSubscription_Unsubscribe(sub);
      natsSubscription_Destroy(sub);
    }
  }
  [self.tagSubscriptions removeAllObjects];

  // Unsubscribe commands subscription
  // Failure to unsubscribe to the commands topic is non-fatal - client
  // continues operating
  if (self.commandsSubscription) {
    natsSubscription_Unsubscribe(self.commandsSubscription);
    natsSubscription_Destroy(self.commandsSubscription);
    self.commandsSubscription = NULL;
  }

  LOGD(@"NATS: All topics unsubscribed");
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

  // Verify connection is alive before subscribing
  if (![self isConnectionAlive]) {
    LOGW(@"NATS: Cannot subscribe - not connected");
    return;
  }

  natsStatus status;

  // Use push device ID from preflight
  // Subscribe to all tags from preflight: santa.tag.<tag>
  if (self.tags && self.tags.count > 0) {
    LOGD(@"NATS: Processing %lu tags from preflight", (unsigned long)self.tags.count);

    // Keep track of already subscribed topics to avoid duplicates
    NSMutableSet *subscribedTopics = [NSMutableSet set];

    for (NSString *tag in self.tags) {
      LOGD(@"NATS: Processing tag: '%@'", tag);

      // Skip if we've already subscribed to this topic
      if ([subscribedTopics containsObject:tag]) {
        LOGD(@"NATS: Skipping duplicate subscription to: %@", tag);
        continue;
      }

      if (![self isValidNATSTopic:tag]) {
        LOGE(@"NATS: Invalid tag: %@ - skipping", tag);
        continue;
      }

      natsSubscription *tagSub = NULL;
      status = natsConnection_Subscribe(&tagSub, self.conn, [tag UTF8String], &messageHandler,
                                        (__bridge void *)self);

      if (status != NATS_OK) {
        LOGE(@"NATS: Failed to subscribe to tag topic %@: %s", tag, natsStatus_GetText(status));
      } else {
        LOGI(@"NATS: Subscribed to tag topic: %@", tag);
        // Store the subscription for later cleanup
        [self.tagSubscriptions addObject:[NSValue valueWithPointer:tagSub]];
        [subscribedTopics addObject:tag];
      }
    }
  }

  // Subscribe to commands topic: santa.host.<device-id>.commands
  // Note: Failure to subscribe to commands topic is non-fatal - client continues operating
  if (self.pushDeviceID.length > 0) {
    NSString *commandsTopic =
        [NSString stringWithFormat:@"santa.host.%@.commands", self.pushDeviceID];
    LOGD(@"NATS: Subscribing to commands topic: %@", commandsTopic);

    natsSubscription *commandsSub = NULL;
    status = natsConnection_Subscribe(&commandsSub, self.conn, [commandsTopic UTF8String],
                                      &commandMessageHandler, (__bridge void *)self);

    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to subscribe to commands topic %@: %s (non-fatal, continuing)",
           commandsTopic, natsStatus_GetText(status));
      // Client continues operating even if commands subscription fails
      // Commands will simply not be received, but other subscriptions continue
    } else {
      LOGI(@"NATS: Subscribed to commands topic: %@", commandsTopic);
      self.commandsSubscription = commandsSub;
    }
  } else {
    LOGW(@"NATS: Cannot subscribe to commands topic - no device ID available (non-fatal)");
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
  NSString *msgData;
  if (data && dataLen > 0) {
    // Decode the payload as a UTF-8 string.
    // TODO in the future handle binary data e.g. protobuf if / when needed.
    msgData = [[NSString alloc] initWithBytes:data length:dataLen encoding:NSUTF8StringEncoding];
  } else {
    msgData = @"";
  }

  LOGD(@"NATS: Received message on subject '%@': %@", msgSubject, msgData ?: @"<no data>");

  // Process on message queue to serialize handling of messages and gurantee we
  // avoid blocking the NATS managed thread. Then call back to the main thread
  // to trigger the sync. Also force serialization of the sync call to avoid
  // thundering herd.
  //
  // IMPORTANT: Do not touch the nats objects in this block they are owned by
  // the nats library and will be destroyed after this block.
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


// Publish a command response to the reply topic
- (void)publishResponse:(const santa::commands::v1::SantaCommandResponse &)response
           toReplyTopic:(NSString *)replyTopic {
  // Failures are logged but don't crash the client
  if (!replyTopic || replyTopic.length == 0) {
    LOGW(@"NATS: Cannot publish command response - no reply topic provided (non-fatal)");
    return;
  }

  // Serialize the response
  std::string responseData;
  if (!response.SerializeToString(&responseData)) {
    LOGE(@"NATS: Failed to serialize command response (non-fatal)");
    return;
  }

  // Publish asynchronously - failures are logged but don't crash
  dispatch_async(self.connectionQueue, ^{
    if (![self isConnectionAlive]) {
      LOGW(@"NATS: Cannot send command response - not connected (non-fatal)");
      return;
    }

    natsStatus status =
        natsConnection_Publish(self.conn, [replyTopic UTF8String], responseData.data(),
                               static_cast<int>(responseData.length()));
    if (status != NATS_OK) {
      LOGE(@"NATS: Failed to publish command response to %@: %s (non-fatal)", replyTopic,
           natsStatus_GetText(status));
    } else {
      LOGD(@"NATS: Sent command response to %@ (code: %d)", replyTopic, response.code());
    }
  });
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

    // Permission errors on subscriptions don't necessarily mean the connection is dead.
    // The connection may still be alive and other subscriptions may work.
    // We just log the failure and continue - the subscription that failed won't receive messages.
    // If the server actually closes the connection due to policy violations,
    // the disconnected or closed callbacks will handle that separately.

    // Verify if the connection is actually closed despite the permission error
    dispatch_async(self.connectionQueue, ^{
      if (self.conn && natsConnection_IsClosed(self.conn)) {
        LOGE(@"NATS: Connection was closed by server due to permissions error, cleaning up and "
             @"scheduling reconnect");
        self.isConnected = NO;
        natsConnection_Destroy(self.conn);
        self.conn = NULL;
        [self scheduleConnectionRetry];
      } else {
        LOGD(@"NATS: Connection still alive despite subscription error on %s, continuing",
             subSubject);
      }
    });
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
      // Calculate jitter: random delay between 0 and 600 seconds (10 minutes)
      uint32_t jitterSeconds = arc4random_uniform(601);

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

    // If we're not shutting down, schedule a reconnection attempt
    // The closed callback is called when the connection is permanently closed
    // and NATS won't automatically reconnect, so we need to do it ourselves
    if (!self.isShuttingDown && self.conn) {
      LOGI(@"NATS: Connection closed unexpectedly, cleaning up and scheduling reconnect");

      // Clean up the closed connection
      natsConnection_Destroy(self.conn);
      self.conn = NULL;

      // Schedule reconnection with exponential backoff
      [self scheduleConnectionRetry];
    }
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
  NSTimeInterval currentRetryDelay = baseDelay * jitterFactor;

  // Cap at 5-10 minutes (randomly between 300-600 seconds) after initial backoff
  if (self.retryAttempt > 9) {
    currentRetryDelay = 300.0 + arc4random_uniform(301);  // 5-10 minutes
  }

  LOGW(@"NATS: Connection failed, will retry in %.1f seconds (attempt %ld)", currentRetryDelay,
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

  // Set a one shot timer to retry the connection with the calculated delay.
  dispatch_source_set_timer(
      self.connectionRetryTimer,
      dispatch_time(DISPATCH_TIME_NOW, (int64_t)(currentRetryDelay * NSEC_PER_SEC)),
      DISPATCH_TIME_FOREVER,
      (int64_t)(100 * NSEC_PER_MSEC));  // 100ms leeway

  WEAKIFY(self);

  // Set the event handler to retry the connection when the timer fires.
  dispatch_source_set_event_handler(self.connectionRetryTimer, ^{
    STRONGIFY(self);
    if (!self || self.isShuttingDown) return;

    self.isRetrying = NO;
    if (self.connectionRetryTimer) {
      dispatch_source_cancel(self.connectionRetryTimer);
      self.connectionRetryTimer = nil;
    }

    LOGI(@"NATS: Retrying connection (attempt %ld)", (long)self.retryAttempt);
    [self connect];
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
    [self connect];
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
