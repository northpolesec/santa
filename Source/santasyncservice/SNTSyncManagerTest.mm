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

#import "Source/common/SNTSyncConstants.h"
#import "Source/santasyncservice/SNTPushClientAPNS.h"
#import "Source/santasyncservice/SNTPushNotifications.h"
#import "Source/santasyncservice/SNTSyncState.h"

@interface SNTSyncManagerTest : XCTestCase
@end

@implementation SNTSyncManagerTest

#pragma mark - Test Push Client Interval Updates

// These tests verify that SNTPushClientAPNS correctly updates its interval
// when handlePreflightSyncState: is called. This is the core functionality
// that SNTSyncManager relies on to detect interval changes.

- (void)testPushClientAPNSDefaultInterval {
  // Verify default initialization
  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  XCTAssertEqual(pushClient.fullSyncInterval, kDefaultPushNotificationsFullSyncInterval,
                 @"Push client should initialize with default interval");
}

- (void)testPushClientAPNSIntervalUpdate {
  // Test that the interval gets updated when handlePreflightSyncState is called
  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  NSUInteger newInterval = 7200;  // 2 hours
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushNotificationsFullSyncInterval = newInterval;

  // This is what SNTSyncManager calls after capturing the old interval
  [pushClient handlePreflightSyncState:syncState];

  // Verify interval was updated - this is what SNTSyncManager compares against
  XCTAssertEqual(pushClient.fullSyncInterval, newInterval,
                 @"Push client should update its interval from sync state");
}

- (void)testIntervalChangeIsDetectable {
  // Test that we can detect an interval change by comparing before/after values
  // This verifies the logic: if (oldInterval != pushNotifications.fullSyncInterval)

  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  // Capture the "old" interval before the update (what SNTSyncManager does)
  NSUInteger oldInterval = pushClient.fullSyncInterval;

  // Update with new interval
  NSUInteger newInterval = 7200;
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushNotificationsFullSyncInterval = newInterval;
  [pushClient handlePreflightSyncState:syncState];

  // The comparison that SNTSyncManager uses to detect changes
  BOOL intervalChanged = (oldInterval != pushClient.fullSyncInterval);

  XCTAssertTrue(intervalChanged, @"Should detect that interval changed");
  XCTAssertEqual(pushClient.fullSyncInterval, newInterval, @"Should have new interval value");
}

- (void)testIntervalUnchangedIsDetectable {
  // Test that when interval doesn't change, the comparison works correctly

  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  NSUInteger unchangedInterval = kDefaultPushNotificationsFullSyncInterval;
  NSUInteger oldInterval = pushClient.fullSyncInterval;

  // "Update" with same interval
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushNotificationsFullSyncInterval = unchangedInterval;
  [pushClient handlePreflightSyncState:syncState];

  // The comparison
  BOOL intervalChanged = (oldInterval != pushClient.fullSyncInterval);

  XCTAssertFalse(intervalChanged, @"Should detect that interval did NOT change");
  XCTAssertEqual(pushClient.fullSyncInterval, unchangedInterval);
}

- (void)testIntervalIncrease {
  // Test interval increasing (less frequent syncs)
  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  // Start with a small interval
  SNTSyncState *syncState1 = [[SNTSyncState alloc] init];
  syncState1.pushNotificationsFullSyncInterval = 1800;  // 30 minutes
  [pushClient handlePreflightSyncState:syncState1];

  NSUInteger oldInterval = pushClient.fullSyncInterval;

  // Increase to larger interval
  SNTSyncState *syncState2 = [[SNTSyncState alloc] init];
  syncState2.pushNotificationsFullSyncInterval = 14400;  // 4 hours
  [pushClient handlePreflightSyncState:syncState2];

  NSUInteger newInterval = pushClient.fullSyncInterval;

  XCTAssertGreaterThan(newInterval, oldInterval, @"Interval should have increased");
  XCTAssertNotEqual(oldInterval, newInterval, @"Should detect change");
}

- (void)testIntervalDecrease {
  // Test interval decreasing (more frequent syncs)
  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  // Start with a large interval
  SNTSyncState *syncState1 = [[SNTSyncState alloc] init];
  syncState1.pushNotificationsFullSyncInterval = 14400;  // 4 hours
  [pushClient handlePreflightSyncState:syncState1];

  NSUInteger oldInterval = pushClient.fullSyncInterval;

  // Decrease to smaller interval
  SNTSyncState *syncState2 = [[SNTSyncState alloc] init];
  syncState2.pushNotificationsFullSyncInterval = 1800;  // 30 minutes
  [pushClient handlePreflightSyncState:syncState2];

  NSUInteger newInterval = pushClient.fullSyncInterval;

  XCTAssertLessThan(newInterval, oldInterval, @"Interval should have decreased");
  XCTAssertNotEqual(oldInterval, newInterval, @"Should detect change");
}

- (void)testMultipleIntervalUpdates {
  // Test multiple sequential updates - ensures the mechanism works repeatedly
  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  NSArray *intervals = @[ @3600, @7200, @1800, @14400, @600 ];

  for (NSNumber *intervalNum in intervals) {
    NSUInteger expectedInterval = [intervalNum unsignedIntegerValue];
    SNTSyncState *syncState = [[SNTSyncState alloc] init];
    syncState.pushNotificationsFullSyncInterval = expectedInterval;

    [pushClient handlePreflightSyncState:syncState];

    XCTAssertEqual(pushClient.fullSyncInterval, expectedInterval,
                   @"Interval should match after each update");
  }
}

- (void)testIntervalChangeLogicFlow {
  // Simulate the exact logic flow from SNTSyncManager.mm lines 306-316
  SNTPushClientAPNS *pushClient = [[SNTPushClientAPNS alloc] initWithSyncDelegate:nil];

  NSUInteger newInterval = 9000;
  SNTSyncState *syncState = [[SNTSyncState alloc] init];
  syncState.pushNotificationsFullSyncInterval = newInterval;

  // This simulates the code in SNTSyncManager:
  // NSUInteger oldInterval = self.pushNotifications.fullSyncInterval;
  NSUInteger oldInterval = pushClient.fullSyncInterval;

  // [self.pushNotifications handlePreflightSyncState:syncState];
  [pushClient handlePreflightSyncState:syncState];

  // if (oldInterval != self.pushNotifications.fullSyncInterval)
  if (oldInterval != pushClient.fullSyncInterval) {
    // This branch should execute when interval changed
    NSLog(@"Interval changed from %lu to %lu", oldInterval, pushClient.fullSyncInterval);
  }

  // Verify the logic detected the change
  XCTAssertNotEqual(oldInterval, pushClient.fullSyncInterval,
                    @"Logic should detect interval change");

  // [self rescheduleTimerQueue:self.fullSyncTimer
  //            secondsFromNow:self.pushNotifications.fullSyncInterval];
  // (We verify the final interval value that would be used for rescheduling)
  XCTAssertEqual(pushClient.fullSyncInterval, newInterval, @"Would reschedule with new interval");
}

@end
