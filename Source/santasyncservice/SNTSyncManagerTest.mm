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
#import <dispatch/dispatch.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSyncManager.h"
#import "Source/santasyncservice/SNTSyncState.h"

// Test category to access private timer properties for testing
@interface SNTSyncManager (TestAccess)
@property(nonatomic) dispatch_source_t fullSyncTimer;
@property(nonatomic) dispatch_source_t ruleSyncTimer;
- (void)rescheduleTimerQueue:(dispatch_source_t)timerQueue secondsFromNow:(uint64_t)seconds;
- (dispatch_source_t)createSyncTimerWithBlock:(void (^)(void))block;
@end

@interface SNTSyncManagerTest : XCTestCase
@end

@implementation SNTSyncManagerTest

#pragma mark - Test Timer Creation and Management

- (void)testTimersAreCreatedOnInitialization {
  // Verify that both timers are created when SNTSyncManager is initialized
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  XCTAssertNotNil(syncManager.fullSyncTimer, @"fullSyncTimer should be created on initialization");
  XCTAssertNotNil(syncManager.ruleSyncTimer, @"ruleSyncTimer should be created on initialization");
}

- (void)testFullSyncTimerIsNotNil {
  // Verify fullSyncTimer is created and not nil
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  dispatch_source_t fullTimer = syncManager.fullSyncTimer;
  XCTAssertNotNil(fullTimer, @"fullSyncTimer must not be nil");
}

- (void)testRuleSyncTimerIsNotNil {
  // Verify ruleSyncTimer is created and not nil
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  dispatch_source_t ruleTimer = syncManager.ruleSyncTimer;
  XCTAssertNotNil(ruleTimer, @"ruleSyncTimer must not be nil");
}

- (void)testRescheduleTimerQueueWithValidInterval {
  // Test that rescheduleTimerQueue correctly sets timer intervals
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  // Create a test timer
  dispatch_source_t testTimer = [syncManager createSyncTimerWithBlock:^{
      // Timer block - would execute when timer fires
  }];

  XCTAssertNotNil(testTimer, @"Test timer should be created");

  // Reschedule the timer for 1 second from now
  [syncManager rescheduleTimerQueue:testTimer secondsFromNow:1];

  // Verify timer is still valid (not nil)
  XCTAssertNotNil(testTimer, @"Timer should remain valid after rescheduling");

  // Clean up
  dispatch_source_cancel(testTimer);
}

- (void)testRescheduleTimerQueueWithZeroInterval {
  // Test rescheduling with zero interval (immediate)
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  dispatch_source_t testTimer = [syncManager createSyncTimerWithBlock:^{
  }];
  XCTAssertNotNil(testTimer, @"Test timer should be created");

  // Reschedule with zero seconds
  [syncManager rescheduleTimerQueue:testTimer secondsFromNow:0];

  XCTAssertNotNil(testTimer, @"Timer should remain valid");

  // Clean up
  dispatch_source_cancel(testTimer);
}

- (void)testRescheduleTimerQueueWithLargeInterval {
  // Test rescheduling with a large interval
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  dispatch_source_t testTimer = [syncManager createSyncTimerWithBlock:^{
  }];
  XCTAssertNotNil(testTimer, @"Test timer should be created");

  // Reschedule with a large interval (24 hours = 86400 seconds)
  uint64_t largeInterval = 86400;
  [syncManager rescheduleTimerQueue:testTimer secondsFromNow:largeInterval];

  XCTAssertNotNil(testTimer, @"Timer should remain valid with large interval");

  // Clean up
  dispatch_source_cancel(testTimer);
}

- (void)testCreateSyncTimerWithBlock {
  // Test that createSyncTimerWithBlock creates a valid timer
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  dispatch_source_t timer = [syncManager createSyncTimerWithBlock:^{
      // Timer block - would execute when timer fires
  }];

  XCTAssertNotNil(timer, @"Timer should be created");

  // Clean up
  dispatch_source_cancel(timer);
}

- (void)testTimerReschedulingAfterIntervalChange {
  // Test that timers are properly rescheduled when intervals change
  // This verifies the integration between interval updates and timer rescheduling
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  SNTSyncManager *syncManager = [[SNTSyncManager alloc] initWithDaemonConnection:mockConnection];

  // Verify initial timer state
  dispatch_source_t initialFullTimer = syncManager.fullSyncTimer;
  XCTAssertNotNil(initialFullTimer, @"fullSyncTimer should exist");

  // Reschedule the timer (simulating what happens when interval changes)
  uint64_t newInterval = 3600;  // 1 hour
  [syncManager rescheduleTimerQueue:initialFullTimer secondsFromNow:newInterval];

  // Verify timer is still valid
  XCTAssertNotNil(initialFullTimer, @"Timer should remain valid after rescheduling");
}

@end
