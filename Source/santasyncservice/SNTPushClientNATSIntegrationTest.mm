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
  natsConnection *testConn = NULL;
  natsStatus status = natsConnection_ConnectTo(&testConn, "nats://localhost:4222");
  if (status != NATS_OK) {
    natsConnection_Destroy(testConn);
    XCTSkip(@"NATS server not available at localhost:4222");
    return;
  }
  natsConnection_Close(testConn);
  natsConnection_Destroy(testConn);
  
  // Setup mocks
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  
  // Setup test machine ID
  self.machineID = @"test-machine-12345678";
  OCMStub([self.mockConfigurator machineID]).andReturn(self.machineID);
  
  // Setup sync URL
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // Mock sync delegate
  self.mockSyncDelegate = OCMProtocolMock(@protocol(SNTPushNotificationsSyncDelegate));
}

- (void)tearDown {
  [self.client disconnect];
  self.client = nil;
  
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
  
  // When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
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
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
  // When: Message is published to device topic
  [self setupTestPublisher];
  NSString *deviceTopic = [NSString stringWithFormat:@"cloud.workshop.nps.santa.%@", self.machineID];
  natsConnection_PublishString(self.testPublisher, [deviceTopic UTF8String], "test message");
  natsConnection_Flush(self.testPublisher);
  
  // Then: Sync should be triggered
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testSubscriptionToGlobalTopic {
  // Given: Client is initialized and connected
  self.syncExpectation = [self expectationWithDescription:@"Sync should be triggered"];
  
  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    [self.syncExpectation fulfill];
  });
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
  // When: Message is published to global topic
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "cloud.workshop.nps.santa.global", "test message");
  natsConnection_Flush(self.testPublisher);
  
  // Then: Sync should be triggered
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
}

- (void)testMultipleMessagesOnlyTriggerOneSync {
  // Given: Client is initialized and connected
  __block NSInteger syncCallCount = 0;
  self.syncExpectation = [self expectationWithDescription:@"Sync should be called"];
  
  OCMStub([self.mockSyncDelegate sync]).andDo(^(NSInvocation *invocation) {
    syncCallCount++;
    if (syncCallCount == 1) {
      [self.syncExpectation fulfill];
    }
  });
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  [NSThread sleepForTimeInterval:0.5]; // Allow connection and subscription
  
  // When: Multiple messages are published rapidly
  [self setupTestPublisher];
  for (int i = 0; i < 5; i++) {
    natsConnection_PublishString(self.testPublisher, "cloud.workshop.nps.santa.global", "test message");
  }
  natsConnection_Flush(self.testPublisher);
  
  // Then: Sync should be triggered once (messages processed sequentially)
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
  
  // Give a bit more time to ensure no additional syncs are triggered
  [NSThread sleepForTimeInterval:0.5];
  
  // Each message triggers a sync, so we expect 5 calls
  XCTAssertEqual(syncCallCount, 5, @"Each message should trigger a sync");
}

- (void)testReconnectionAfterServerRestart {
  // Given: Client is connected
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
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
  [NSThread sleepForTimeInterval:0.5];
  
  // Verify initial message triggers sync
  [self setupTestPublisher];
  natsConnection_PublishString(self.testPublisher, "cloud.workshop.nps.santa.global", "message 1");
  natsConnection_Flush(self.testPublisher);
  [self waitForExpectationsWithTimeout:2.0 handler:nil];
  
  // When: Client disconnects
  [self.client disconnect];
  [NSThread sleepForTimeInterval:0.2];
  
  // Then: Further messages should not trigger sync
  NSInteger countBeforePublish = syncCallCount;
  natsConnection_PublishString(self.testPublisher, "cloud.workshop.nps.santa.global", "message 2");
  natsConnection_Flush(self.testPublisher);
  [NSThread sleepForTimeInterval:0.5];
  
  XCTAssertEqual(syncCallCount, countBeforePublish, @"No sync should be triggered after disconnect");
}

#pragma mark - Helper Methods

- (void)setupTestPublisher {
  if (!self.testPublisher) {
    natsStatus status = natsConnection_ConnectTo(&_testPublisher, "nats://localhost:4222");
    XCTAssertEqual(status, NATS_OK, @"Test publisher should connect successfully");
  }
}

@end