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

namespace santa {
class TemporaryMonitorModePeer : public TemporaryMonitorMode {
 public:
  TemporaryMonitorModePeer(SNTConfigurator *configurator, SNTNotificationQueue *notQueue,
                           HandleAuditEventBlock block)
      : santa::TemporaryMonitorMode(MakeKey(), configurator, notQueue, block) {}

  using TemporaryMonitorMode::GetSecondsRemainingFromInitialStateLocked;
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
  NSString *testSessionUUID = [[NSUUID UUID] UUIDString];
  uint64_t wantAtLeastSeconds = 100;

  TemporaryMonitorModePeer tmm([SNTConfigurator configurator], self.mockNotQueue,
                               ^(id){
                                   // This space intentionally left blank.
                               });

  NSDictionary *goodTestState = @{
    kStateTempMonitorModeBootUUIDKey : testBootUUID,
    kStateTempMonitorModeDeadlineKey : @(MakeDeadline(wantAtLeastSeconds)),
    kStateTempMonitorModeSavedSyncURLKey : pinnedURL.host,
    kStateTempMonitorModeSessionUUIDKey : testSessionUUID,
  };

  NSMutableDictionary *testState = [goodTestState copy];
  XCTAssertGreaterThan(
      tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
      wantAtLeastSeconds);

  // Bad Boot Session UUID type
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeBootUUIDKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
                 0);

  // Bad Deadline type
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeDeadlineKey] = @"123";
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
                 0);

  // Bad Session UUID type
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeSessionUUIDKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
                 0);

  // Invalid Session UUID
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeSessionUUIDKey] = @"ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ";
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
                 0);

  // Bad Sync URL type type
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeSavedSyncURLKey] = @(123);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
                 0);

  // Mismatched boot session UUID
  testState = [goodTestState mutableCopy];
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, @"xyz", pinnedURL), 0);

  // Unpinned sync URL
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeSavedSyncURLKey] = unpinnedURL.host;
  OCMExpect([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition *mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  XCTAssertEqual(
      tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, unpinnedURL), 0);

  // Mismatched sync URL
  testState = [goodTestState mutableCopy];
  testState[kStateTempMonitorModeSavedSyncURLKey] = pinnedURL2.host;
  OCMExpect([self.mockConfigurator
      setSyncServerModeTransition:[OCMArg checkWithBlock:^BOOL(SNTModeTransition *mt) {
        return mt.type == SNTModeTransitionTypeRevoke;
      }]]);
  XCTAssertEqual(tmm.GetSecondsRemainingFromInitialStateLocked(testState, testBootUUID, pinnedURL),
                 0);

  XCTAssertTrue(OCMVerifyAll(self.mockConfigurator));
}

@end
