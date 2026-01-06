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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "src/common/SNTTimer.h"
#import "src/common/TestUtils.h"

@interface SNTTimerTest : XCTestCase
@end

@implementation SNTTimerTest

- (void)testInitWithNoName {
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:nil
                                              fireOnStart:YES
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_UTILITY
                                                 callback:^BOOL(void) {
                                                   return YES;
                                                 }];

  XCTAssertNil(timer);

  timer = [[SNTTimer alloc] initWithMinInterval:1
                                    maxInterval:60
                                           name:@""
                                    fireOnStart:YES
                                 rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                       qosClass:QOS_CLASS_UTILITY
                                       callback:^BOOL(void) {
                                         return YES;
                                       }];

  XCTAssertNil(timer);

  timer = [[SNTTimer alloc] initWithMinInterval:1
                                    maxInterval:60
                                           name:@"TestTimer"
                                    fireOnStart:YES
                                 rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                       qosClass:QOS_CLASS_UTILITY
                                       callback:^BOOL(void) {
                                         return YES;
                                       }];

  XCTAssertNotNil(timer);
}

- (void)testStartStopIsStarted {
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   return YES;
                                                 }];

  XCTAssertFalse([timer isStarted]);

  [timer startWithInterval:1];
  XCTAssertTrue([timer isStarted]);

  [timer stop];
  XCTAssertFalse([timer isStarted]);
}

- (void)testStopWhenNotStarted {
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   return YES;
                                                 }];

  XCTAssertFalse([timer isStarted]);
  [timer stop];
  XCTAssertFalse([timer isStarted]);
}

- (void)testMultipleStarts {
  // Don't fire on start.
  // Start with a higher interval, and ensure it fires after one cycle.
  // Start again with s shorter interval, and ensure it fires as expected.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return YES;
                                                 }];

  [timer startWithInterval:4];
  XCTAssertSemaFalseTimeout(sema, 1, "Semaphore should not have been signaled yet");
  XCTAssertSemaTrue(sema, 4, "Semaphore did not get signaled after expected time");

  // The timer should still be going
  XCTAssertTrue([timer isStarted]);

  [timer startWithInterval:2];
  XCTAssertSemaFalseTimeout(sema, 1, "Semaphore should not have been signaled yet");
  XCTAssertSemaTrue(sema, 2, "Semaphore did not get signaled after expected time");
}

- (void)testLeadingEdgeScheduling {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  // The sleep time should be slightly longer than the timer interval
  long sleepTime = 4000;

  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   SleepMS(sleepTime);
                                                   return YES;
                                                 }];

  // Start the timer and wait for the first fire
  [timer startWithInterval:3];
  XCTAssertSemaFalseTimeout(sema, 1, "Semaphore should not have been signaled yet");
  XCTAssertSemaTrue(sema, 3, "Semaphore did not get signaled after expected time");

  // Match the sleep interval in the callback
  SleepMS(sleepTime);

  // The interval should fire almost immediately since the reschedule should've
  // occurred prior to the sleep
  XCTAssertSemaTrue(sema, 1, "Semaphore did not get signaled after expected time");
}

- (void)testLeadingEdgeStopReschedule {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return NO;
                                                 }];

  // Start the timer and wait for the first fire
  [timer startWithInterval:2];
  XCTAssertTrue([timer isStarted]);

  // Ensure timer fires once
  XCTAssertSemaTrue(sema, 3, "Semaphore did not get signaled after expected time");

  // The timer should no longer be running
  XCTAssertFalse([timer isStarted]);

  // Ensure the timer doesn't fire again
  XCTAssertSemaFalseTimeout(sema, 3, "Semaphore should not be signaled again");
}

- (void)testTrailingEdgeScheduling {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  // The sleep time should be long enough to detect the trailling edge reschedule.
  long sleepTime = 3000;

  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeTrailingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   SleepMS(sleepTime);
                                                   return YES;
                                                 }];

  // Start the timer and wait for the first fire
  [timer startWithInterval:3];
  XCTAssertSemaFalseTimeout(sema, 1, "Semaphore should not have been signaled yet");
  XCTAssertSemaTrue(sema, 3, "Semaphore did not get signaled after expected time");

  // Match the sleep interval in the callback
  SleepMS(sleepTime);

  // The timer shouldn't fire immediately, instead waiting another full cycle
  XCTAssertSemaFalseTimeout(sema, 1, "Semaphore should not have been signaled yet");

  // Now wait for the timer to actually fire
  XCTAssertSemaTrue(sema, 3, "Semaphore did not get signaled after expected time");
}

- (void)testTrailingEdgeStopReschedule {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeTrailingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return NO;
                                                 }];

  // Start the timer and wait for the first fire
  [timer startWithInterval:2];
  XCTAssertTrue([timer isStarted]);

  // Ensure timer fires once
  XCTAssertSemaTrue(sema, 3, "Semaphore did not get signaled after expected time");

  // The timer should no longer be running
  XCTAssertFalse([timer isStarted]);

  // Ensure the timer doesn't fire again
  XCTAssertSemaFalseTimeout(sema, 3, "Semaphore should not be signaled again");
}

- (void)testClampMinimum {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:3
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return NO;
                                                 }];

  // Start the timer below the min interval
  [timer startWithInterval:1];

  // Ensure the timer doesn't fire before the min interval
  XCTAssertSemaFalseTimeout(sema, 2, "Semaphore should not be signaled yet");

  // Ensure timer fires at the min interval time
  XCTAssertSemaTrue(sema, 2, "Semaphore did not get signaled after expected time");
}

- (void)testClampMaximum {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:2
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return NO;
                                                 }];

  // Start the timer above the max interval
  [timer startWithInterval:100];

  // Ensure the timer fires at the max interval time (some added wiggle room here)
  XCTAssertSemaTrue(sema, 3, "Semaphore should not be signaled yet");
}

- (void)testFireOnStart {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:YES
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return YES;
                                                 }];

  XCTAssertNotNil(timer);
  XCTAssertFalse([timer isStarted]);

  [timer startWithInterval:10];
  XCTAssertSemaTrue(sema, 2, "Semaphore should have been signaled immediately");
  XCTAssertTrue([timer isStarted]);
}

- (void)testWaitOneCycle {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return YES;
                                                 }];

  XCTAssertNotNil(timer);
  XCTAssertFalse([timer isStarted]);

  [timer startWithInterval:3];
  XCTAssertSemaFalseTimeout(sema, 1, "Semaphore should not have been signaled yet");
  XCTAssertTrue([timer isStarted]);

  // Now wait for the callback to fire
  XCTAssertSemaTrue(sema, 5, "Semaphore was not signaled after expected time");
}

- (void)testDoubleStartReturn {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  SNTTimer *timer = [[SNTTimer alloc] initWithMinInterval:1
                                              maxInterval:60
                                                     name:@"TestTimer"
                                              fireOnStart:NO
                                           rescheduleMode:SNTTimerRescheduleModeLeadingEdge
                                                 qosClass:QOS_CLASS_USER_INTERACTIVE
                                                 callback:^BOOL(void) {
                                                   dispatch_semaphore_signal(sema);
                                                   return YES;
                                                 }];

  XCTAssertNotNil(timer);
  XCTAssertFalse([timer isStarted]);

  XCTAssertTrue([timer startWithInterval:2]);
  XCTAssertTrue([timer isStarted]);

  // Starting an already started timer returns false,
  XCTAssertFalse([timer startWithInterval:4]);
  XCTAssertSemaFalseTimeout(sema, 2, "Semaphore should not have been signaled yet");
  XCTAssertSemaTrue(sema, 4, "Semaphore was not signaled after expected time");
  XCTAssertTrue([timer isStarted]);
}

@end
