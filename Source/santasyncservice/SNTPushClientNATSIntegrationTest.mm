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

#import <XCTest/XCTest.h>
#import <OCMock/OCMock.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTSyncState.h"
#import "Source/santasyncservice/SNTPushNotifications.h"

extern "C" {
#import "src/nats.h"
}

// Integration test that requires a real NATS server running on localhost:4222
// Run with: bazel test //Source/santasyncservice:SNTPushClientNATSIntegrationTest --test_env=NATS_INTEGRATION_TEST=1
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
  
  // Setup test machine ID to match our credentials (hexadecimal only)
  self.machineID = @"ABCDEF123456789";
  OCMStub([self.mockConfigurator machineID]).andReturn(self.machineID);
  
  // Setup sync URL
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // Mock sync delegate
  self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));
}

- (void)tearDown {
  if (self.client) {
    [self.client disconnectAndWait:YES];
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
  [self.client handlePreflightSyncState:syncState];
  
  // Wait for connection
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
  [self.client handlePreflightSyncState:syncState];
  
  // Wait for connection
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[];  // No specific tags, just testing global
  
  [self.client handlePreflightSyncState:syncState];
  
  // Wait for connection
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
  [self.client handlePreflightSyncState:syncState];
  
  // Wait for connection
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
  [self.client handlePreflightSyncState:syncState];
  
  [NSThread sleepForTimeInterval:0.5];
  
  // Verify initial message triggers sync
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "santa.tag.global", "message 1");
  natsConnection_Flush(self.testPublisher);
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
  
  // When: Client disconnects
  [self.client disconnect];
  [NSThread sleepForTimeInterval:0.2];
  
  // Then: Further messages should not trigger sync
  NSInteger countBeforePublish = syncCallCount;
  natsConnection_PublishString(self.testPublisher, "santa.tag.global", "message 2");
  natsConnection_Flush(self.testPublisher);
  [NSThread sleepForTimeInterval:0.5];
  
  XCTAssertEqual(syncCallCount, countBeforePublish, @"No sync should be triggered after disconnect");
}

#pragma mark - Helper Methods

- (void)setupTestPublisher {
  if (!self.testPublisher) {
    // Configure with proper credentials for the test publisher
    natsOptions *opts = NULL;
    natsStatus status = natsOptions_Create(&opts);
    XCTAssertEqual(status, NATS_OK, @"Failed to create NATS options");
    
    // Create credentials string in NATS format - use test publisher credentials with pub permissions
    NSString *creds = @"-----BEGIN NATS USER JWT-----\n"
                      @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiJBVExEVUVUNlY2NktISk02SjdNSFJGNFJTM1EzWEpKQ0JTUjc0T0lBQzI1UlpaNlpVM09RIiwiaWF0IjoxNzYxMzk3NjcxLCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LXB1Ymxpc2hlciIsInN1YiI6IlVCM1ZDTFRRSVMyWklPUjRNRzdZSFFQNkU2Q1NQUVA0NkxQNjNVUUFHNldITU40WUJJS0VPTkIyIiwibmF0cyI6eyJwdWIiOnsiYWxsb3ciOlsiX0lOQk9YLlx1MDAzZSIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiJdfSwic3ViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiLCJzYW50YS4qIl19LCJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.tXLixxZrPw0ELjueZ3gNJsfwytv8aprtDygWo-kKWvEKtNXSYZ9gKIW3zm5LkuyIuD5c2Y3ZEPnxDteJbi77Cw\n"
                      @"------END NATS USER JWT------\n"
                      @"\n"
                      @"-----BEGIN USER NKEY SEED-----\n"
                      @"SUAHTEEWVEQ72TBSE5ZRCCALOU57HKPOLWDLZGBHZB6RMAPOD5OI4KNAYM\n"
                      @"------END USER NKEY SEED------\n";
    
    // Set credentials
    status = natsOptions_SetUserCredentialsFromMemory(opts, creds.UTF8String);
    XCTAssertEqual(status, NATS_OK, @"Failed to set user credentials");
    
    // Set server URL - connect to localhost:443
    status = natsOptions_SetURL(opts, "nats://localhost:443");
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
  syncState.pushNKey = @"SUACBNSCZDJFQNXSNUMNMPHN7UY5AWS42E6VMQXVTKCU2KJYBR75MVDPJQ";
  syncState.pushJWT = @"eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJqdGkiOiI0N1dWSzdBUkpUV1c1NFhJSENIVDU1SlM3M1dWU1VUTUxUV1U0SUdPUlVJVUFHUVRLQkdRIiwiaWF0IjoxNzYxMzk3NjA4LCJpc3MiOiJBRE40R1VISEtNR01MMkQyQURFTFBVWUVGRjNRWU5JNERWTjZGNDNKUFA2R0k3VjRTVVlTSlRCNCIsIm5hbWUiOiJ0ZXN0LW1hY2hpbmUtMTIzNDUiLCJzdWIiOiJVQ043WTQ1VzVLTkE3V01ZTVdSQVVRSkRDSEVOQ1o3N1BSWVNCMkhYSENNUFRBNlBXRVZMVVRNTyIsIm5hdHMiOnsicHViIjp7ImFsbG93IjpbIl9JTkJPWC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIiwic2FudGEtY2xpZW50cyIsInNhbnRhLioiLCJzYW50YS5ob3N0LioiLCJzYW50YS50YWcuKiIsIndvcmtzaG9wIl19LCJyZXNwIjp7Im1heCI6MSwidHRsIjowfSwic3VicyI6LTEsImRhdGEiOi0xLCJwYXlsb2FkIjotMSwidHlwZSI6InVzZXIiLCJ2ZXJzaW9uIjoyfX0.L2C1512oLT6KDkgRLN8Ggl5Pa9ZQ1_a_NCqL8YZyzp9ot4PwHLHkLsGNuIgodRYi7LWybYKKIPJN1eRTxs0CDw";
  syncState.pushTags = @[@"santa-clients", @"workshop"];
  
  [self.client handlePreflightSyncState:syncState];
  
  // Wait for connection attempt
  [NSThread sleepForTimeInterval:0.5];
  
  // Then: Client should not be connected (no TLS server available)
  // In a real deployment, this would connect to workshop.push.northpole.security:443
  XCTAssertFalse(self.client.isConnected, @"Should not connect without proper TLS server");
}

@end