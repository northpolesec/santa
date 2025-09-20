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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/santasyncservice/SNTPushClientAPNS.h"
#import "Source/santasyncservice/SNTPushClientFCM.h"
#import "Source/santasyncservice/SNTPushClientNATS.h"
#import "Source/santasyncservice/SNTSyncManager.h"

// Expose private property for testing
@interface SNTSyncManager (Testing)
@property(readonly) id<SNTPushNotificationsClientDelegate> pushNotifications;
@end

@interface SNTSyncManagerNATSTest : XCTestCase
@property id mockConfigurator;
@property id mockDaemonConn;
@property SNTSyncManager *syncManager;
@end

@implementation SNTSyncManagerNATSTest

- (void)setUp {
  [super setUp];
  
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  
  self.mockDaemonConn = OCMClassMock([MOLXPCConnection class]);
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
  self.syncManager = nil;
  [super tearDown];
}

- (void)testSyncManagerInitializesNATSClientWhenEnabled {
  // Given: NATS is enabled and sync URL is configured
  OCMStub([self.mockConfigurator enableNATS]).andReturn(YES);
  OCMStub([self.mockConfigurator enableAPNS]).andReturn(NO);
  OCMStub([self.mockConfigurator fcmEnabled]).andReturn(NO);
  
  NSURL *syncURL = [NSURL URLWithString:@"https://sync.example.com"];
  OCMStub([self.mockConfigurator syncBaseURL]).andReturn(syncURL);
  
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];
  
  // Then: Push notifications should be NATS client
  XCTAssertNotNil(self.syncManager.pushNotifications);
  XCTAssertTrue([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientNATS class]]);
}

- (void)testSyncManagerPrefersNATSOverAPNS {
  // Given: Both NATS and APNS are enabled
  OCMStub([self.mockConfigurator enableNATS]).andReturn(YES);
  OCMStub([self.mockConfigurator enableAPNS]).andReturn(YES);
  OCMStub([self.mockConfigurator fcmEnabled]).andReturn(NO);
  
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];
  
  // Then: NATS should be chosen over APNS
  XCTAssertTrue([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientNATS class]]);
  XCTAssertFalse([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientAPNS class]]);
}

- (void)testSyncManagerPrefersNATSOverFCM {
  // Given: Both NATS and FCM are enabled
  OCMStub([self.mockConfigurator enableNATS]).andReturn(YES);
  OCMStub([self.mockConfigurator enableAPNS]).andReturn(NO);
  OCMStub([self.mockConfigurator fcmEnabled]).andReturn(YES);
  
  // Mock FCM requirements
  OCMStub([self.mockConfigurator fcmProject]).andReturn(@"test-project");
  OCMStub([self.mockConfigurator fcmEntity]).andReturn(@"test-entity");
  OCMStub([self.mockConfigurator fcmAPIKey]).andReturn(@"test-api-key");
  
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];
  
  // Then: NATS should be chosen over FCM
  XCTAssertTrue([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientNATS class]]);
  XCTAssertFalse([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientFCM class]]);
}

- (void)testSyncManagerFallsBackToAPNSWhenNATSDisabled {
  // Given: NATS is disabled, APNS is enabled
  OCMStub([self.mockConfigurator enableNATS]).andReturn(NO);
  OCMStub([self.mockConfigurator enableAPNS]).andReturn(YES);
  OCMStub([self.mockConfigurator fcmEnabled]).andReturn(NO);
  
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];
  
  // Then: APNS should be used
  XCTAssertTrue([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientAPNS class]]);
}

- (void)testSyncManagerFallsBackToFCMWhenNATSAndAPNSDisabled {
  // Given: NATS and APNS are disabled, FCM is enabled
  OCMStub([self.mockConfigurator enableNATS]).andReturn(NO);
  OCMStub([self.mockConfigurator enableAPNS]).andReturn(NO);
  OCMStub([self.mockConfigurator fcmEnabled]).andReturn(YES);
  
  // Mock FCM requirements
  OCMStub([self.mockConfigurator fcmProject]).andReturn(@"test-project");
  OCMStub([self.mockConfigurator fcmEntity]).andReturn(@"test-entity");
  OCMStub([self.mockConfigurator fcmAPIKey]).andReturn(@"test-api-key");
  
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];
  
  // Then: FCM should be used
  XCTAssertTrue([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientFCM class]]);
}

- (void)testSyncManagerHasNoPushClientWhenAllDisabled {
  // Given: All push notification methods are disabled
  OCMStub([self.mockConfigurator enableNATS]).andReturn(NO);
  OCMStub([self.mockConfigurator enableAPNS]).andReturn(NO);
  OCMStub([self.mockConfigurator fcmEnabled]).andReturn(NO);
  
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];
  
  // Then: No push client should be initialized
  XCTAssertNil(self.syncManager.pushNotifications);
}

@end