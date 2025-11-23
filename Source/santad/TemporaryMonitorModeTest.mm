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

#include "Source/santad/TemporaryMonitorMode.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <mach/mach_time.h>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTModeTransition.h"
#include "Source/common/SystemResources.h"
#import "Source/santad/SNTNotificationQueue.h"

static NSString *const kBootSessionUUIDKey = @"UUID";
static NSString *const kDeadlineKey = @"Deadline";
static NSString *const kSyncURLKey = @"SyncURL";

namespace santa {
class TemporaryMonitorModePeer : public TemporaryMonitorMode {
 public:
  TemporaryMonitorModePeer(SNTConfigurator *configurator, SNTNotificationQueue *notQueue)
      : santa::TemporaryMonitorMode(MakeKey(), configurator, notQueue) {}

  using TemporaryMonitorMode::GetSecondsRemainingFromInitialState;
};
}  // namespace santa

using santa::TemporaryMonitorModePeer;

// Return a mach continuous time that is at least the given seconds in the future.
// Checks should use `XCTAssertGreaterThan(..., want)` to account for timing delays.
uint64_t MakeDeadline(uint64_t want) {
  return MachTimeToNanos(
      AddNanosecondsToMachTime((want + 5) * NSEC_PER_SEC, mach_continuous_time()));
}

@interface TemporaryMonitorModeTest : XCTestCase
@property id mockConfigurator;
@property id mockNotQueue;
@end

@implementation TemporaryMonitorModeTest

- (void)setUp {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.mockNotQueue = OCMClassMock([SNTNotificationQueue class]);
  OCMStub([self.mockNotQueue alloc]).andReturn(self.mockNotQueue);

  OCMStub([self.mockNotQueue initWithRingBuffer:nullptr]).andReturn(self.mockNotQueue);
  self.mockNotQueue = [[SNTNotificationQueue alloc] initWithRingBuffer:nil];
}

- (void)testGetSecondsRemainingFromInitialState {
  NSURL *unpinnedURL = [NSURL URLWithString:@"https://my.sync.server"];
  NSURL *pinnedURL = [NSURL URLWithString:@"https://foo.workshop.cloud"];
  NSURL *pinnedURL2 = [NSURL URLWithString:@"https://bar.workshop.cloud"];
  NSString *testBootUUID = @"my.boot.uuid";
  uint64_t wantAtLeastSeconds = 100;

  TemporaryMonitorModePeer tmm([SNTConfigurator configurator], self.mockNotQueue);

  NSDictionary *goodTestState = @{
    kBootSessionUUIDKey : testBootUUID,
    kDeadlineKey : @(MakeDeadline(wantAtLeastSeconds)),
    kSyncURLKey : pinnedURL.host
  };

  NSMutableDictionary *testState = [goodTestState copy];
  XCTAssertGreaterThan(tmm.GetSecondsRemainingFromInitialState(testState, testBootUUID, pinnedURL),
                       wantAtLeastSeconds);

  // Bad Boot Session UUID type
  testState = [goodTestState mutableCopy];
  testState[kBootSessionUUIDKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialState(testState, testBootUUID, pinnedURL), 0);

  // Bad Deadline type
  testState = [goodTestState mutableCopy];
  testState[kDeadlineKey] = @"123";
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialState(testState, testBootUUID, pinnedURL), 0);

  // Bad Sync URL type type
  testState = [goodTestState mutableCopy];
  testState[kSyncURLKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialState(testState, testBootUUID, pinnedURL), 0);

  // Mismatched boot session UUID
  testState = [goodTestState mutableCopy];
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialState(testState, @"xyz", pinnedURL), 0);

  // Unpinned sync URL
  testState = [goodTestState mutableCopy];
  testState[kSyncURLKey] = unpinnedURL.host;
  OCMExpect([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition *mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialState(testState, testBootUUID, unpinnedURL), 0);

  // Mismatched sync URL
  testState = [goodTestState mutableCopy];
  testState[kSyncURLKey] = pinnedURL2.host;
  OCMExpect([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition *mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialState(testState, testBootUUID, pinnedURL), 0);

  XCTAssertTrue(OCMVerifyAll(self.mockConfigurator));
}

@end
