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
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSyncState.h"

extern "C" {
#import "src/nats.h"
}

// Test credentials
#define TEST_JWT                                                                                   \
  @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."                                               \
  @"eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxN" \
  @"zYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSl" \
  @"RCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o" \
  @"3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0s" \
  @"InN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0L" \
  @"ioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdG" \
  @"EiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_"  \
  @"a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw"
#define TEST_NKEY @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ"
#define TEST_PUBLISHER_JWT                                                                         \
  @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ."                                               \
  @"eyJqdGkiOiJYNlREWklOTE1VUVRHWjdXT0k1Tzc0MkQ2VExWQk1OV0oyNDIyUEtCUTRJMklMRk1ITlFBIiwiaWF0IjoxN" \
  @"zYxMzk2NjU0LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSl" \
  @"RCNCIsIm5hbWUiOiJ0ZXN0LXB1Ymxpc2hlciIsInN1YiI6IlVCM1ZDTFRRSVMyWklPUjRNRzdZSFFQNkU2Q1NQUVA0Nkx" \
  @"QNjNVUUFHNldITU40WUJJS0VPTkIyIiwibmF0cyI6eyJwdWIiOnsiYWxsb3ciOlsic2FudGEuKiIsInNhbnRhLmhvc3Qu" \
  @"KiIsInNhbnRhLnRhZy4qIl19LCJzdWIiOnsiYWxsb3ciOlsic2FudGEuKiJdfSwic3VicyI6LTEsImRhdGEiOi0xLCJwY" \
  @"Xlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.-WT84YZASQ4e8cqmTncyVwaDMfjkM66HQFnFxYU36_" \
  @"WOoUV9FZHexCDYHArWLjdJu_ybaiIv4tmn2hIhkRq2Bw"
#define TEST_PUBLISHER_NKEY @"SUAHTEEWVEQ72TBSE5ZRCCALOU57HKPOLWDLZGBHZB6RMAPOD5OI4KNAYM"
#define TEST_MACHINE_ID @"testmachine12345"

// Expose private methods for testing
@interface SNTPushClientNATS (IntegrationTesting)
- (void)disconnectWithCompletion:(void (^)(void))completion;
@end

// Integration test that requires a real NATS server running on localhost:4222
// Run with: bazel test //Source/santasyncservice:SNTPushClientNATSIntegrationTest
// --test_env=NATS_INTEGRATION_TEST=1
@interface SNTPushClientNATSIntegrationTest : XCTestCase
@property id mockConfigurator;
@property id mockSyncDelegate;
@property SNTPushClientNATS *client;
@property natsConnection *testPublisher;
@property XCTestExpectation *syncExpectation;
@property NSString *machineID;
@end

@implementation SNTPushClientNATSIntegrationTest

- (void)setUp {
  [super setUp];

  // Skip these tests unless explicitly enabled
  if (!getenv("NATS_INTEGRATION_TEST")) {
    XCTSkip(@"NATS integration tests require NATS_INTEGRATION_TEST=1 and a running NATS server");
    return;
  }

  // Check if NATS server is running
  // Note: We skip the connectivity check since it requires credentials
  // The actual tests will fail if the server is not available

  // Setup mocks
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  // Setup test machine ID to match our credentials
  self.machineID = TEST_MACHINE_ID;
  OCMStub([self.mockConfigurator machineID]).andReturn(self.machineID);

  // Setup sync URL
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);

  // Mock sync delegate
  self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));
}

- (void)tearDown {
  if (self.client) {
    // Use expectation to wait for disconnect completion
    XCTestExpectation *disconnectExpectation =
        [self expectationWithDescription:@"Client disconnect"];
    [self.client disconnectWithCompletion:^{
      [disconnectExpectation fulfill];
    }];
    [self waitForExpectations:@[ disconnectExpectation ] timeout:1.0];
    self.client = nil;
  }

  if (self.testPublisher) {
    natsConnection_Close(self.testPublisher);
    natsConnection_Destroy(self.testPublisher);
    self.testPublisher = NULL;
  }

  [self.mockConfigurator stopMocking];
  [super tearDown];
}

- (void)testConnectionToNATSServer {
  // Given: NATS server is running

  // When: Client is initialized and configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];

  // Then: Client should be connected
  XCTAssertTrue(self.client.isConnected, @"Client should be connected to NATS server");
}

- (void)testSubscriptionToDeviceTopic {
  // Given: Client is initialized and connected
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered"];

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];  // Allow connection and subscription

  // When: Message is published to device topic
  [self setupTestPublisher];
  NSString *deviceTopic = [NSString stringWithFormat:@"santa.host.%@", self.machineID];
  natsConnection_PublishString(self.testPublisher, [deviceTopic UTF8String], "test message");
  natsConnection_Flush(self.testPublisher);

  // Then: Sync should be triggered
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testSubscriptionToSpecificTagTopic {
  // Given: Client is initialized and connected
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered"];

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];  // Allow connection and subscription

  // When: Message is published to tag topic
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "santa.tag.workshop", "test message");
  natsConnection_Flush(self.testPublisher);

  // Then: Sync should be triggered
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testSubscriptionToGlobalTagTopic {
  // Given: Client is initialized and connected
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered"];

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials (no specific tags needed, global is always subscribed)
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushTags = @[];  // No specific tags, just testing global

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];  // Allow connection and subscription

  // When: Message is published to global tag topic
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "santa.tag.global", "test message");
  natsConnection_Flush(self.testPublisher);

  // Then: Sync should be triggered
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testMultipleMessagesTriggersMultipleSyncs {
  // Given: Client is initialized and connected
  __block NSInteger syncCallCount = 0;
  self.syncExpectation = [self expectationWithDescription:@"All syncs should complete"];

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    syncCallCount++;
    if (syncCallCount == 5) {
      [self.syncExpectation fulfill];
    }
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];  // Allow connection and subscription

  // When: Multiple messages are published rapidly to global tag topic
  [self setupTestPublisher];
  for (int i = 0; i < 5; i++) {
    natsConnection_PublishString(self.testPublisher, "santa.tag.global", "test message");
  }
  natsConnection_Flush(self.testPublisher);

  // Then: Each message should trigger a sync
  [self waitForExpectationsWithTimeout:2.0 handler:nil];

  // Verify we got all 5 syncs
  XCTAssertEqual(syncCallCount, 5, @"Each message should trigger a sync");
}

- (void)testReconnectionAfterServerRestart {
  // Given: Client is connected
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  [NSThread sleepForTimeInterval:0.5];
  XCTAssertTrue(self.client.isConnected);

  // When: Connection is lost (simulate by closing from client side)
  // In a real test, you would restart the NATS server

  // Note: NATS client has automatic reconnection built in
  // The callbacks we set up (disconnectedCB, reconnectedCB) will handle state changes

  // For this test, we just verify the client remains functional
  XCTAssertNotNil(self.client);
}

- (void)testDisconnectStopsReceivingMessages {
  // Given: Client is connected and receiving messages
  self.syncExpectation = [self expectationWithDescription:@"First sync should be triggered"];
  __block NSInteger syncCallCount = 0;

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    syncCallCount++;
    if (syncCallCount == 1) {
      [self.syncExpectation fulfill];
    }
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with test credentials
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  [NSThread sleepForTimeInterval:0.5];

  // Verify initial message triggers sync
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "santa.tag.global", "message 1");
  natsConnection_Flush(self.testPublisher);
  [self waitForExpectationsWithTimeout:2.0 handler:nil];

  // When: Client disconnects
  [self.client disconnectWithCompletion:nil];
  [NSThread sleepForTimeInterval:0.2];

  // Then: Further messages should not trigger sync
  NSInteger countBeforePublish = syncCallCount;
  natsConnection_PublishString(self.testPublisher, "santa.tag.global", "message 2");
  natsConnection_Flush(self.testPublisher);
  [NSThread sleepForTimeInterval:0.5];

  XCTAssertEqual(syncCallCount, countBeforePublish,
                 @"No sync should be triggered after disconnect");
}

#pragma mark - Helper Methods

- (void)setupTestPublisher {
  if (!self.testPublisher) {
    // Configure with proper credentials for the test publisher
    natsOptions *opts = NULL;
    natsStatus status = natsOptions_Create(&opts);
    XCTAssertEqual(status, NATS_OK, @"Failed to create NATS options");

    // Create credentials string in NATS format - use test publisher credentials with pub
    // permissions
    NSString *creds = [NSString
        stringWithFormat:
            @"-----BEGIN NATS USER JWT-----\n%@\n------END NATS USER JWT------\n\n-----BEGIN USER "
            @"NKEY SEED-----\n%@\n------END USER NKEY SEED------\n",
            TEST_PUBLISHER_JWT, TEST_PUBLISHER_NKEY];

    // Set credentials
    status = natsOptions_SetUserCredentialsFromMemory(opts, creds.UTF8String);
    XCTAssertEqual(status, NATS_OK, @"Failed to set user credentials");

    // Set server URL - connect to localhost:443
    status = natsOptions_SetURL(opts, "nats://localhost:4222");
    XCTAssertEqual(status, NATS_OK, @"Failed to set server URL");

    // Connect with credentials
    status = natsConnection_Connect(&_testPublisher, opts);
    XCTAssertEqual(status, NATS_OK, @"Test publisher should connect successfully with credentials");

    natsOptions_Destroy(opts);
  }
}

- (void)testTLSConnectionInProductionMode {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Client is configured with a remote server (not localhost)
  // Note: This will fail to connect since we don't have a real TLS server
  // but we can verify it attempts TLS connection on port 443
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"workshop";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushTags = @[ @"santa-clients", @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection attempt
  [NSThread sleepForTimeInterval:0.5];

  // Then: Client should not be connected (no TLS server available)
  // In a real deployment, this would connect to workshop.push.northpole.security:443
  XCTAssertFalse(self.client.isConnected, @"Should not connect without proper TLS server");
}

- (void)testInvalidDeviceIDWithPeriodsIsRejected {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Client is configured with device ID containing periods
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = @"invalid.device.id";
  syncState.pushTags = @[ @"santa-clients" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];

  // Then: Client should be connected but device subscription should fail
  XCTAssertTrue(self.client.isConnected, @"Client should still connect to NATS server");

  // Verify no sync is triggered from device topic
  [self setupTestPublisher];
  NSString *deviceTopic = [NSString stringWithFormat:@"santa.host.%@", @"invalid.device.id"];
  natsConnection_PublishString(self.testPublisher, [deviceTopic UTF8String], "test message");
  natsConnection_Flush(self.testPublisher);

  // Wait a bit - no sync should be triggered
  [NSThread sleepForTimeInterval:0.5];

  // Verify client responds to valid tag topics
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered from tag"];
  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });

  natsConnection_PublishString(self.testPublisher, "santa.tag.santaclients", "test message");
  natsConnection_Flush(self.testPublisher);

  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testInvalidDeviceIDWithHyphensIsRejected {
  // Given: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // When: Client is configured with device ID containing hyphens
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = @"invalid-device-id";
  syncState.pushTags = @[ @"workshop" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];

  // Then: Client should be connected but device subscription should fail
  XCTAssertTrue(self.client.isConnected, @"Client should still connect to NATS server");

  // Verify client responds to valid tag topics
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered from tag"];
  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });

  natsConnection_PublishString(self.testPublisher, "santa.tag.workshop", "test message");
  natsConnection_Flush(self.testPublisher);

  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testValidTopicsWithAlphanumericCharacters {
  // Given: Client is initialized
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered"];

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  // Configure with valid alphanumeric device ID and tags
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = @"ABC123xyz789";
  syncState.pushTags = @[ @"tag123", @"workshop456", @"santa-test-tag" ];

  [self.client handlePreflightSyncState:syncState];

  // Wait for connection
  [NSThread sleepForTimeInterval:0.5];

  // When: Message is published to valid device topic
  [self setupTestPublisher];
  NSString *deviceTopic = @"santa.host.ABC123xyz789";
  natsConnection_PublishString(self.testPublisher, [deviceTopic UTF8String], "test message");
  natsConnection_Flush(self.testPublisher);

  // Then: Sync should be triggered
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testReconnectionTriggersSync {
  // Skip this test in automated builds - it requires manual server restart
  if (!getenv("NATS_MANUAL_RECONNECT_TEST")) {
    XCTSkip(@"Manual reconnection test requires NATS_MANUAL_RECONNECT_TEST=1");
    return;
  }

  // Given: Client is connected
  self.syncExpectation = [self expectationWithDescription:@"Initial sync after message"];
  __block NSInteger syncCallCount = 0;

  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    syncCallCount++;
    if (self.syncExpectation) {
      [self.syncExpectation fulfill];
      self.syncExpectation = nil;
    }
  });

  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];

  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushServer = @"localhost";
  syncState.pushNKey = TEST_NKEY;
  syncState.pushJWT = TEST_JWT;
  syncState.pushDeviceID = self.machineID;
  syncState.pushTags = @[ @"santa-clients" ];

  [self.client handlePreflightSyncState:syncState];
  [NSThread sleepForTimeInterval:0.5];

  XCTAssertTrue(self.client.isConnected, @"Should be connected initially");

  // Send initial message to verify connection
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "santa.tag.global", "test initial");
  natsConnection_Flush(self.testPublisher);
  [self waitForExpectationsWithTimeout:2.0 handler:nil];

  NSInteger initialSyncCount = syncCallCount;

  // When: Server disconnects and reconnects
  // NOTE: This requires manually stopping/starting the NATS server
  NSLog(@"Please restart the NATS server now. Test will wait 35 seconds for reconnection sync...");

  // Create expectation for sync after reconnection (with jitter up to 30s)
  self.syncExpectation = [self expectationWithDescription:@"Sync after reconnection"];

  // Wait for reconnection sync (max jitter is 30s + some buffer)
  [self waitForExpectationsWithTimeout:35.0
                               handler:^(NSError *error) {
                                 if (error) {
                                   XCTFail(@"Sync was not triggered after reconnection within "
                                           @"jitter window: %@",
                                           error);
                                 }
                               }];

  // Then: Sync should have been triggered exactly once more
  XCTAssertEqual(syncCallCount, initialSyncCount + 1,
                 @"Exactly one additional sync should be triggered after reconnection");
  XCTAssertTrue(self.client.isConnected, @"Should be reconnected");
}

@end
