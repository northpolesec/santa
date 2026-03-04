/// Copyright 2026 North Pole Security, Inc.
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

#include <memory>

#include "Source/common/PowerMonitor.h"

using santa::PowerEvent;
using santa::PowerMonitor;

@interface PowerMonitorTest : XCTestCase
@end

@implementation PowerMonitorTest

- (void)testCreateReturnsNonNull {
  auto monitor = PowerMonitor::Create(^(PowerEvent event){
  });
  XCTAssertTrue(monitor != nullptr);
}

- (void)testCreateWithNilCallbackReturnsNull {
  auto monitor = PowerMonitor::Create(nil);
  XCTAssertTrue(monitor == nullptr);
}

- (void)testConstructAndDestruct {
  // Verify that creating and immediately destroying a monitor doesn't crash.
  auto monitor = PowerMonitor::Create(^(PowerEvent event){
  });
  XCTAssertTrue(monitor != nullptr);
  monitor.reset();
}

- (void)testMultipleMonitorsCoexist {
  auto monitor1 = PowerMonitor::Create(^(PowerEvent event){
  });
  auto monitor2 = PowerMonitor::Create(^(PowerEvent event){
  });
  XCTAssertTrue(monitor1 != nullptr);
  XCTAssertTrue(monitor2 != nullptr);
}

@end
