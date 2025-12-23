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

#include "Source/santad/DaemonConfigBundle.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

@interface DaemonConfigBundleTest : XCTestCase
@end

@implementation DaemonConfigBundleTest

- (void)testNetworkMountConfigBundle {
  __block XCTestExpectation *exp = [self expectationWithDescription:@"Result Blocks"];
  exp.expectedFulfillmentCount = 2;
  SNTConfigBundle *bundle;

  SNTConfigurator *configurator = [SNTConfigurator configurator];
  id mockConfigurator = OCMPartialMock(configurator);

  OCMExpect([mockConfigurator enableNotificationSilences]).andReturn(YES);
  OCMExpect([mockConfigurator bannedNetworkMountBlockMessage]).andReturn(@"this has been banned");

  bundle = santa::NetworkMountConfigBundle(mockConfigurator);

  [bundle bannedNetworkMountBlockMessage:^(NSString *val) {
    XCTAssertEqualObjects(val, @"this has been banned");
    [exp fulfill];
  }];

  [bundle enableNotificationSilences:^(BOOL val) {
    XCTAssertTrue(val);
    [exp fulfill];
  }];

  // Low timeout because code above is synchronous
  [self waitForExpectationsWithTimeout:0.1 handler:NULL];
}

@end
