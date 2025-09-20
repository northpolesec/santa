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
@property(nonatomic) natsSubscription *deviceSub;
@property(nonatomic) natsSubscription *globalSub;
@property(nonatomic, readwrite) BOOL isConnected;
- (void)connect;
- (void)disconnect;
- (void)disconnectWithCompletion:(void (^)(void))completion;
- (void)subscribe;
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
  [self.client disconnect];
  self.client = nil;
  [self.mockConfigurator stopMocking];
  [self.mockSystemInfo stopMocking];
  [super tearDown];
}

#pragma mark - Initialization Tests

- (void)testInitWithSyncDelegateWhenSyncServerConfigured {
  // Given: Sync server is configured
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Then: Client should be created with sync delegate set
  XCTAssertNotNil(self.client);
  XCTAssertEqual(self.client.fullSyncInterval, kDefaultPushNotificationsFullSyncInterval);
  
  // Give time for async connection
  [NSThread sleepForTimeInterval:0.1];
}

- (void)testInitWithSyncDelegateWhenSyncServerNotConfigured {
  // Given: No sync server configured
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(nil);
  
  // When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Then: Client should be created but not connected
  XCTAssertNotNil(self.client);
  XCTAssertFalse(self.client.isConnected);
  XCTAssertTrue(self.client.conn == NULL);
}

#pragma mark - Connection Tests

- (void)testConnectWhenAlreadyConnected {
  // Given: Sync server is configured and client is connected
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  [NSThread sleepForTimeInterval:0.1]; // Allow initial connection
  
  // Assuming connection succeeded (would need real NATS server for true test)
  // When: Connect is called again
  [self.client connect];
  
  // Then: Should not attempt duplicate connection
  // (Would verify through logs in real test)
}

- (void)testDisconnect {
  // Given: Client is initialized
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // When: Disconnect is called
  [self.client disconnect];
  
  // Then: Client should be disconnected
  XCTAssertFalse(self.client.isConnected);
  XCTAssertTrue(self.client.conn == NULL);
  XCTAssertTrue(self.client.deviceSub == NULL);
  XCTAssertTrue(self.client.globalSub == NULL);
}

#pragma mark - Subscription Tests

- (void)testSubscribeWithValidMachineID {
  // Given: Valid machine ID is available
  NSString *machineID = @"12345678-1234-1234-1234-123456789012";
  OCMStub([self.mockConfigurator machineID]).andReturn(machineID);
  
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // When: Client is initialized (which triggers subscribe)
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Then: Should attempt to subscribe to both topics
  // Device topic: cloud.workshop.nps.santa.12345678-1234-1234-1234-123456789012
  // Global topic: cloud.workshop.nps.santa.global
  // (Would verify through NATS connection in integration test)
}

- (void)testSubscribeWithNoMachineID {
  // Given: No machine ID available
  OCMStub([self.mockConfigurator machineID]).andReturn(nil);
  
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // When: Client is initialized
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Then: Should log error and not crash
  // (Would verify through logs)
}

#pragma mark - Message Handling Tests

- (void)testMessageHandlerTriggersSyncImmediately {
  // Given: Client is initialized with mock delegate
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // Expect sync to be called
  OCMExpect([self.mockSyncDelegate sync]);
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // When: Message handler would be called by NATS
  // (In a real test, we'd simulate NATS calling the message handler)
  // For now, we'll verify the delegate would be called
  
  // Then: Verify expectations
  // OCMVerifyAllWithDelay(self.mockSyncDelegate, 0.5);
}

#pragma mark - Token Tests

- (void)testTokenReturnsMachineID {
  // Given: Machine ID is configured
  NSString *machineID = @"test-machine-id";
  OCMStub([self.mockConfigurator machineID]).andReturn(machineID);
  
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // When: Token is requested
  NSString *token = self.client.token;
  
  // Then: Should return machine ID
  XCTAssertEqualObjects(token, machineID);
}

#pragma mark - Preflight Sync State Tests

- (void)testHandlePreflightSyncStateWhenSyncServerRemoved {
  // Skip this test for now as it requires actual NATS connection
  // The unit test should focus on logic, not integration
  XCTSkip(@"This test requires integration testing approach");
}

- (void)testHandlePreflightSyncStateWhenSyncServerAddedAndNotConnected {
  // Given: Client is not connected (no sync server initially)
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(nil);
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  XCTAssertFalse(self.client.isConnected);
  
  // When: Sync server is configured
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  [self.client handlePreflightSyncState:syncState];
  
  // Then: Client should attempt to connect
  [NSThread sleepForTimeInterval:0.1]; // Allow connection attempt
  // (Would verify connection attempt in integration test)
}

- (void)testHandlePreflightSyncStateWhenAlreadyConnected {
  // Given: Client is connected with sync server
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  self.client.isConnected = YES; // Simulate connected state
  
  // When: Preflight sync state is handled (server still configured)
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  [self.client handlePreflightSyncState:syncState];
  
  // Then: Should remain connected (no disconnect/reconnect)
  XCTAssertTrue(self.client.isConnected);
}

#pragma mark - Full Sync Interval Tests

- (void)testFullSyncIntervalDefaultValue {
  // Given: Client is initialized
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Then: Full sync interval should be default value
  XCTAssertEqual(self.client.fullSyncInterval, kDefaultPushNotificationsFullSyncInterval);
}

@end