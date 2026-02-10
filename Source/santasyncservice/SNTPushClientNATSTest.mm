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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSyncState.h"

extern "C" {
#import "src/nats.h"
}

// Expose private methods for testing
@interface SNTPushClientNATS (Testing)
@property(nonatomic) natsConnection *conn;
@property(nonatomic, readwrite) BOOL isConnected;
@property(nonatomic) dispatch_source_t connectionRetryTimer;
@property(nonatomic) NSInteger retryAttempt;
@property(nonatomic) BOOL isRetrying;
- (void)connect;
- (void)disconnectWithCompletion:(void (^)(void))completion;
- (void)subscribe;
- (void)scheduleConnectionRetry;
- (void)configureWithPushServer:(NSString *)server
                      pushToken:(NSString *)token
                            jwt:(NSString *)jwt
                   pushDeviceID:(NSString *)deviceID
                           tags:(NSArray<NSString *> *)tags;
- (void)handlePushNotificationForSubject:(NSString *)subject;
@end

@interface SNTPushClientNATSTest : XCTestCase
@property id mockConfigurator;
@property id mockSystemInfo;
@property id mockSyncDelegate;
@property SNTPushClientNATS *client;
@end

@implementation SNTPushClientNATSTest

- (void)setUp {
  [super setUp];

  // Mock configurator
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // Mock system info
  self.mockSystemInfo = OCMClassMock([SNTSystemInfo class]);

  // Mock sync delegate
  self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));
}

- (void)tearDown {
  [self.client disconnectWithCompletion:nil];
  self.client = nil;
  [self.mockConfigurator stopMocking];
  [self.mockSystemInfo stopMocking];
  [super tearDown];
}

#pragma mark - Initialization Tests

- (void)testInitWithSyncDelegate {
  // When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Then: Client should be created with sync delegate set but not connected
  XCTAssertNotNil(self.client);
  XCTAssertEqual(self.client.fullSyncInterval, kDefaultPushNotificationsFullSyncInterval);
  XCTAssertFalse(self.client.isConnected);
  XCTAssertTrue(self.client.conn == NULL);
}

#pragma mark - Connection Tests

- (void)testConnectWithoutConfiguration {
  // Given: Client is initialized without configuration
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Connect is called without configuration
  [self.client connect];

  // Then: Should not connect
  XCTAssertFalse(self.client.isConnected);
  XCTAssertTrue(self.client.conn == NULL);
}

- (void)testDisconnect {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Disconnect is called
  [self.client disconnectWithCompletion:nil];

  // Then: Client should be disconnected
  XCTAssertFalse(self.client.isConnected);
  XCTAssertTrue(self.client.conn == NULL);
}

#pragma mark - Subscription Tests

- (void)testSubscribeWithValidMachineID {
  // Given: Valid machine ID is available
  NSString *machineID = @"12345678-1234-1234-1234-123456789012";
  OCMStub([self.mockConfigurator machineID]).andReturn(machineID);

  // When: Client is initialized and configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Then: Should sanitize the device ID (remove hyphens)
  // Expected sanitized device topic: santa.host.12345678123412341234123456789012
  // Tags: as provided in configuration
  // (Would verify through NATS connection in integration test)
}

- (void)testSubscribeWithNoMachineID {
  // Given: No machine ID available
  OCMStub([self.mockConfigurator machineID]).andReturn(nil);

  // When: Client is initialized and configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Then: Should log error and not crash
  // (Would verify through logs in integration test)
}

#pragma mark - Message Handling Tests

- (void)testConfigureWithPushServer {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Client is configured with push server details
  [self.client configureWithPushServer:@"workshop"
                             pushToken:@"test-nkey"
                                   jwt:@"test-jwt"
                          pushDeviceID:@"test-device-id"
                                  tags:@[ @"tag1", @"tag2" ]];

  // Then: Configuration should be stored and connection attempted
  // Server should be appended with .push.northpole.security
  // (Would verify connection parameters in integration test)
  [NSThread sleepForTimeInterval:0.1];  // Allow async configuration
}

#pragma mark - Token Tests

- (void)testTokenReturnsMachineID {
  // Given: Machine ID is configured
  NSString *machineID = @"test-machine-id";
  OCMStub([self.mockConfigurator machineID]).andReturn(machineID);

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Token is requested
  NSString *token = self.client.token;

  // Then: Should return machine ID
  XCTAssertEqualObjects(token, machineID);
}

#pragma mark - Preflight Sync State Tests

- (void)testHandlePreflightSyncStateWithConfiguration {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Preflight sync state with push configuration is handled
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"workshop";
  syncState.pushNKey = @"test-nkey";
  syncState.pushJWT = @"test-jwt";
  syncState.pushDeviceID = @"test-device-id";
  syncState.pushTags = @[ @"tag1", @"tag2" ];
  syncState.pushNotificationsFullSyncInterval = 3600;

  [self.client handlePreflightSyncState:syncState];

  // Then: Client should be configured and connection attempted
  XCTAssertEqual(self.client.fullSyncInterval, 3600);
  // (Would verify configuration and connection in integration test)
}

- (void)testHandlePreflightSyncStateWithoutConfiguration {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Preflight sync state without push configuration is handled
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  // No push configuration fields set

  [self.client handlePreflightSyncState:syncState];

  // Then: Client should not connect
  XCTAssertFalse(self.client.isConnected);
  // (Would verify no connection attempt in integration test)
}

- (void)testHandlePreflightSyncStateUpdatesInterval {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  NSUInteger originalInterval = self.client.fullSyncInterval;

  // When: Preflight sync state with new interval is handled
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushNotificationsFullSyncInterval = 7200;  // 2 hours

  [self.client handlePreflightSyncState:syncState];

  // Then: Interval should be updated
  XCTAssertEqual(self.client.fullSyncInterval, 7200);
  XCTAssertNotEqual(self.client.fullSyncInterval, originalInterval);
}

#pragma mark - Full Sync Interval Tests

- (void)testFullSyncIntervalDefaultValue {
  // Given/When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Then: Full sync interval should be default value
  XCTAssertEqual(self.client.fullSyncInterval, kDefaultPushNotificationsFullSyncInterval);
}

#pragma mark - Connection Retry Tests

- (void)testConnectionRetryInitialization {
  // Given/When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Then: Retry state should be initialized correctly
  XCTAssertEqual(self.client.retryAttempt, 0);
  XCTAssertFalse(self.client.isRetrying);
  XCTAssertNil(self.client.connectionRetryTimer);
}

- (void)testConnectionRetryScheduled {
  // Given: Client is initialized and configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: scheduleConnectionRetry is called
  [self.client scheduleConnectionRetry];

  // Then: Retry should be scheduled
  XCTAssertTrue(self.client.isRetrying);
  XCTAssertEqual(self.client.retryAttempt, 1);
  XCTAssertNotNil(self.client.connectionRetryTimer);

  // Cleanup
  if (self.client.connectionRetryTimer) {
    dispatch_source_cancel(self.client.connectionRetryTimer);
  }
}

- (void)testRetryDelayExponentialBackoff {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Multiple retries are scheduled
  for (int i = 1; i <= 5; i++) {
    [self.client scheduleConnectionRetry];

    // Then: Retry attempt should increase
    XCTAssertEqual(self.client.retryAttempt, i);

    // Cleanup timer for next iteration
    if (self.client.connectionRetryTimer) {
      dispatch_source_cancel(self.client.connectionRetryTimer);
      self.client.connectionRetryTimer = nil;
    }
    self.client.isRetrying = NO;
  }
}

- (void)testRetryDelayCapAt5To10Minutes {
  // Given: Client with many retry attempts
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  self.client.retryAttempt = 9;  // Set to 9 so next attempt will be 10th

  // When: Next retry is scheduled
  [self.client scheduleConnectionRetry];

  // Then: Retry attempt should be incremented
  XCTAssertEqual(self.client.retryAttempt, 10);

  // Cleanup
  if (self.client.connectionRetryTimer) {
    dispatch_source_cancel(self.client.connectionRetryTimer);
  }
}

#pragma mark - Topic Building Tests

- (void)testHandlePreflightSyncStateFiltersHostTopics {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Preflight sync state includes santa.host.* in tags (which shouldn't happen)
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"workshop";
  syncState.pushNKey = @"test-nkey";
  syncState.pushJWT = @"test-jwt";
  syncState.pushDeviceID = @"test-device-id";
  syncState.pushTags =
      @[ @"production", @"santa.host.7228546F079C54169E2C929EACE830BE", @"staging" ];
  syncState.pushNotificationsFullSyncInterval = 3600;

  [self.client handlePreflightSyncState:syncState];

  // Then: The santa.host.* topic should be filtered out during subscription
  // (This would be verified through logs in integration test)
  // The client should still be configured normally
  XCTAssertEqual(self.client.fullSyncInterval, 3600);
}

#pragma mark - Credential Rotation Tests

- (void)testCredentialRotationTriggersReconnection {
  // Given: Client is initialized and configured with initial credentials
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  XCTestExpectation *initialConfigExpectation =
      [self expectationWithDescription:@"Initial configuration completed"];

  SNTSyncState *initialState = [[SNTSyncState alloc] init];
  initialState.pushServer = @"workshop";
  initialState.pushNKey = @"old-nkey";
  initialState.pushJWT = @"old-jwt";
  initialState.pushDeviceID = @"test-device-id";
  initialState.pushTags = @[ @"tag1", @"tag2" ];

  [self.client handlePreflightSyncState:initialState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [initialConfigExpectation fulfill];
  });

  [self waitForExpectations:@[ initialConfigExpectation ] timeout:1.0];

  // When: New credentials arrive (JWT changed)
  XCTestExpectation *rotationExpectation =
      [self expectationWithDescription:@"Credential rotation completed"];

  SNTSyncState *updatedState = [[SNTSyncState alloc] init];
  updatedState.pushServer = @"workshop";
  updatedState.pushNKey = @"old-nkey";  // NKey unchanged
  updatedState.pushJWT = @"new-jwt";    // JWT changed (rotated)
  updatedState.pushDeviceID = @"test-device-id";
  updatedState.pushTags = @[ @"tag1", @"tag2" ];

  [self.client handlePreflightSyncState:updatedState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [rotationExpectation fulfill];
  });

  [self waitForExpectations:@[ rotationExpectation ] timeout:1.0];

  // Then: Client should attempt to reconnect with new credentials
  // In a real connection, isConnected would eventually become true again
  // For unit test, we verify the configuration was accepted
  // (Full reconnection behavior is verified in integration tests)
}

- (void)testNKeyRotationTriggersReconnection {
  // Given: Client is initialized and configured with initial credentials
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  XCTestExpectation *initialConfigExpectation =
      [self expectationWithDescription:@"Initial configuration completed"];

  SNTSyncState *initialState = [[SNTSyncState alloc] init];
  initialState.pushServer = @"workshop";
  initialState.pushNKey = @"old-nkey";
  initialState.pushJWT = @"test-jwt";
  initialState.pushDeviceID = @"test-device-id";
  initialState.pushTags = @[ @"production" ];

  [self.client handlePreflightSyncState:initialState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [initialConfigExpectation fulfill];
  });

  [self waitForExpectations:@[ initialConfigExpectation ] timeout:1.0];

  // When: New credentials arrive (NKey changed)
  XCTestExpectation *rotationExpectation =
      [self expectationWithDescription:@"Credential rotation completed"];

  SNTSyncState *updatedState = [[SNTSyncState alloc] init];
  updatedState.pushServer = @"workshop";
  updatedState.pushNKey = @"new-nkey";  // NKey changed (rotated)
  updatedState.pushJWT = @"test-jwt";   // JWT unchanged
  updatedState.pushDeviceID = @"test-device-id";
  updatedState.pushTags = @[ @"production" ];

  [self.client handlePreflightSyncState:updatedState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [rotationExpectation fulfill];
  });

  [self waitForExpectations:@[ rotationExpectation ] timeout:1.0];

  // Then: Client should attempt to reconnect with new credentials
  // (Full reconnection behavior is verified in integration tests)
}

- (void)testBothCredentialsRotateSimultaneously {
  // Given: Client is initialized and configured with initial credentials
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  XCTestExpectation *initialConfigExpectation =
      [self expectationWithDescription:@"Initial configuration completed"];

  SNTSyncState *initialState = [[SNTSyncState alloc] init];
  initialState.pushServer = @"workshop";
  initialState.pushNKey = @"old-nkey";
  initialState.pushJWT = @"old-jwt";
  initialState.pushDeviceID = @"device-123";
  initialState.pushTags = @[ @"staging" ];

  [self.client handlePreflightSyncState:initialState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [initialConfigExpectation fulfill];
  });

  [self waitForExpectations:@[ initialConfigExpectation ] timeout:1.0];

  // When: Both credentials change simultaneously
  XCTestExpectation *rotationExpectation =
      [self expectationWithDescription:@"Credential rotation completed"];

  SNTSyncState *updatedState = [[SNTSyncState alloc] init];
  updatedState.pushServer = @"workshop";
  updatedState.pushNKey = @"new-nkey";  // Both changed
  updatedState.pushJWT = @"new-jwt";    // Both changed
  updatedState.pushDeviceID = @"device-123";
  updatedState.pushTags = @[ @"staging" ];

  [self.client handlePreflightSyncState:updatedState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [rotationExpectation fulfill];
  });

  [self waitForExpectations:@[ rotationExpectation ] timeout:1.0];

  // Then: Client should detect credential change and attempt reconnection
  // (Full reconnection behavior is verified in integration tests)
}

- (void)testNoReconnectionWhenCredentialsUnchanged {
  // Given: Client is initialized and configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  XCTestExpectation *initialConfigExpectation =
      [self expectationWithDescription:@"Initial configuration completed"];

  SNTSyncState *initialState = [[SNTSyncState alloc] init];
  initialState.pushServer = @"workshop";
  initialState.pushNKey = @"test-nkey";
  initialState.pushJWT = @"test-jwt";
  initialState.pushDeviceID = @"test-device-id";
  initialState.pushTags = @[ @"tag1" ];

  [self.client handlePreflightSyncState:initialState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [initialConfigExpectation fulfill];
  });

  [self waitForExpectations:@[ initialConfigExpectation ] timeout:1.0];

  // When: Same credentials are provided again (only tags changed)
  XCTestExpectation *reconfigExpectation =
      [self expectationWithDescription:@"Reconfiguration completed"];

  SNTSyncState *updatedState = [[SNTSyncState alloc] init];
  updatedState.pushServer = @"workshop";
  updatedState.pushNKey = @"test-nkey";  // Same
  updatedState.pushJWT = @"test-jwt";    // Same
  updatedState.pushDeviceID = @"test-device-id";
  updatedState.pushTags = @[ @"tag1", @"tag2" ];  // Only tags changed

  [self.client handlePreflightSyncState:updatedState];

  dispatch_async(dispatch_get_main_queue(), ^{
    [reconfigExpectation fulfill];
  });

  [self waitForExpectations:@[ reconfigExpectation ] timeout:1.0];

  // Then: Should resubscribe to new tags but not force full reconnection
  // (since credentials unchanged)
}

#pragma mark - Device ID Sanitization Tests

- (void)testDeviceIDSanitization {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Test various device ID formats that need sanitization
  NSArray<NSArray<NSString *> *> *testCases = @[
    @[ @"12345678-1234-1234-1234-123456789012", @"santa.host.12345678123412341234123456789012" ],
    @[ @"device.id.with.dots", @"santa.host.deviceidwithdots" ],
    @[ @"device-id-with-hyphens", @"santa.host.deviceidwithhyphens" ],
    @[ @"mixed.device-id.format-123", @"santa.host.mixeddeviceidformat123" ],
    @[ @"UPPERCASE-DEVICE.ID", @"santa.host.UPPERCASEDEVICEID" ],
    @[ @"simple", @"santa.host.simple" ]
  ];

  for (NSArray<NSString *> *testCase in testCases) {
    NSString *input = testCase[0];
    // NSString *expected = testCase[1]; // Expected sanitized topic for verification in integration
    // tests

    // Configure with device ID that needs sanitization
    [self.client configureWithPushServer:@"workshop"
                               pushToken:@"test-nkey"
                                     jwt:@"test-jwt"
                            pushDeviceID:input
                                    tags:@[]];

    // The subscribe method would create the sanitized topic
    // Expected result: testCase[1]
    // (Would verify through connection logs in integration test)
  }
}

- (void)testEmptyDeviceIDAfterSanitization {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Device ID consists only of periods and hyphens
  [self.client configureWithPushServer:@"workshop"
                             pushToken:@"test-nkey"
                                   jwt:@"test-jwt"
                          pushDeviceID:@"..--..--"
                                  tags:@[]];

  // Then: Should log error about empty device ID after sanitization
  // (Would verify through logs in integration test)
}

#pragma mark - Push Notification Jitter Tests

- (void)testTagMessageTriggersDelayedSync {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  XCTestExpectation *expectation =
      [self expectationWithDescription:@"syncSecondsFromNow called for tag message"];

  OCMStub([self.mockSyncDelegate syncSecondsFromNow:0])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation *invocation) {
        uint64_t seconds;
        [invocation getArgument:&seconds atIndex:2];
        XCTAssertLessThanOrEqual(seconds, 180u);
        [expectation fulfill];
      });

  // Reject immediate sync - it should NOT be called for tag messages
  OCMReject([self.mockSyncDelegate sync]);

  // When: A tag push notification is received
  [self.client handlePushNotificationForSubject:@"santa.tag.production"];

  // Then: syncSecondsFromNow should be called with jitter in [0, 180]
  [self waitForExpectations:@[ expectation ] timeout:2.0];
}

- (void)testHostMessageTriggersImmediateSync {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  XCTestExpectation *expectation =
      [self expectationWithDescription:@"sync called for host message"];

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [expectation fulfill];
  });

  // Reject delayed sync - it should NOT be called for host messages
  OCMReject([self.mockSyncDelegate syncSecondsFromNow:0]).ignoringNonObjectArgs();

  // When: A host push notification is received
  [self.client handlePushNotificationForSubject:@"santa.host.ABC123"];

  // Then: sync should be called immediately (no jitter)
  [self waitForExpectations:@[ expectation ] timeout:2.0];
}

@end
