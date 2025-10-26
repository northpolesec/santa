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
  
  // When: Client is initialized and configured
  self.client = [[SNTPushClientNATS alloc] initWithSyncDelegate:self.mockSyncDelegate];
  
  // Then: Should attempt to subscribe when connected
  // Device topic: santa.12345678-1234-1234-1234-123456789012
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
                                 tags:@[@"tag1", @"tag2"]];
  
  // Then: Configuration should be stored and connection attempted
  // Server should be appended with .push.northpole.security
  // (Would verify connection parameters in integration test)
  [NSThread sleepForTimeInterval:0.1]; // Allow async configuration
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
  syncState.pushTags = @[@"tag1", @"tag2"];
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
  syncState.pushNotificationsFullSyncInterval = 7200; // 2 hours
  
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

@end