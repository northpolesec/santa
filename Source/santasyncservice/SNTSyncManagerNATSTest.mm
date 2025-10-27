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

- (void)testSyncManagerAlwaysInitializesNATSClient {
  // Given: Daemon connection is available
  // When: Sync manager is initialized
  self.syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:self.mockDaemonConn];

  // Then: Push notifications should always be NATS client
  XCTAssertNotNil(self.syncManager.pushNotifications);
  XCTAssertTrue([self.syncManager.pushNotifications isKindOfClass:[SNTPushClientNATS class]]);
}

@end
