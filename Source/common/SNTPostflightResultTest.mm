/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/common/SNTPostflightResult.h"

#include <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/santasyncservice/SNTSyncState.h"

@interface SNTPostflightResult (Testing)
@property NSNumber *clientMode;
@property NSNumber *syncType;
@property NSString *allowlistRegex;
@property NSString *blocklistRegex;
@property NSNumber *blockUSBMount;
@property NSArray *remountUSBMode;
@property NSNumber *enableBundles;
@property NSNumber *enableTransitiveRules;
@property NSNumber *enableAllEventUpload;
@property NSNumber *disableUnknownEventUpload;
@property NSString *overrideFileAccessAction;
@end

@interface SNTPostflightResultTest : XCTestCase
@end

@implementation SNTPostflightResultTest

- (void)testInit {
  SNTPostflightResult *postflightResult;
  SNTSyncState *state = [[SNTSyncState alloc] init];

  state.clientMode = SNTClientModeUnknown;
  postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];
  XCTAssertNil(postflightResult.clientMode);

  state.clientMode = SNTClientModeMonitor;
  postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];
  XCTAssertEqualObjects(postflightResult.clientMode, @(SNTClientModeMonitor));

  state.syncType = SNTSyncTypeNormal;
  postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];
  XCTAssertNil(postflightResult.syncType);

  state.syncType = SNTSyncTypeClean;
  postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];
  XCTAssertEqualObjects(postflightResult.syncType, @(SNTSyncTypeNormal));

  state.syncType = SNTSyncTypeCleanAll;
  postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];
  XCTAssertEqualObjects(postflightResult.syncType, @(SNTSyncTypeNormal));
}

- (void)testGettersWithValues {
  SNTSyncState *state = [[SNTSyncState alloc] init];
  state.clientMode = SNTClientModeLockdown;
  state.syncType = SNTSyncTypeClean;
  state.allowlistRegex = @"allow";
  state.blocklistRegex = @"block";
  state.blockUSBMount = @(YES);
  state.remountUSBMode = @[ @"foo" ];
  state.enableBundles = @(YES);
  state.enableTransitiveRules = @(YES);
  state.enableAllEventUpload = @(YES);
  state.disableUnknownEventUpload = @(YES);
  state.overrideFileAccessAction = @"disable";

  __block XCTestExpectation *exp = [self expectationWithDescription:@"Result Blocks"];

  exp.expectedFulfillmentCount = 11;

  SNTPostflightResult *postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];

  [postflightResult clientMode:^(SNTClientMode val){
    XCTAssertEqual(val, SNTClientModeLockdown);
    [exp fulfill];
  }];

  [postflightResult syncType:^(SNTSyncType val){
    XCTAssertEqual(val, SNTSyncTypeNormal);
    [exp fulfill];
  }];

  [postflightResult allowlistRegex:^(NSString *val){
    XCTAssertEqualObjects(val, @"allow");
    [exp fulfill];
  }];

  [postflightResult blocklistRegex:^(NSString *val){
    XCTAssertEqualObjects(val, @"block");
    [exp fulfill];
  }];

  [postflightResult blockUSBMount:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult remountUSBMode:^(NSArray *val){
    XCTAssertEqualObjects(val, @[ @"foo" ]);
    [exp fulfill];
  }];

  [postflightResult enableBundles:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult enableTransitiveRules:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult enableAllEventUpload:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult disableUnknownEventUpload:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult overrideFileAccessAction:^(NSString *val){
    XCTAssertEqualObjects(val, @"disable");
    [exp fulfill];
  }];

  [self waitForExpectationsWithTimeout:3.0 handler:NULL];
}

- (void)testGettersWithoutValues {
  SNTSyncState *state = [[SNTSyncState alloc] init];
  state.syncType = SNTSyncTypeNormal;

  __block XCTestExpectation *exp = [self expectationWithDescription:@"Result Blocks"];
  exp.inverted = YES;

  SNTPostflightResult *postflightResult = [[SNTPostflightResult alloc] initWithSyncState:state];

  [postflightResult clientMode:^(SNTClientMode val){
    XCTAssertEqual(val, SNTClientModeLockdown);
    [exp fulfill];
  }];

  [postflightResult syncType:^(SNTSyncType val){
    XCTAssertEqual(val, SNTSyncTypeNormal);
    [exp fulfill];
  }];

  [postflightResult allowlistRegex:^(NSString *val){
    XCTAssertEqualObjects(val, @"allow");
    [exp fulfill];
  }];

  [postflightResult blocklistRegex:^(NSString *val){
    XCTAssertEqualObjects(val, @"block");
    [exp fulfill];
  }];

  [postflightResult blockUSBMount:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult remountUSBMode:^(NSArray *val){
    XCTAssertEqualObjects(val, @[ @"foo" ]);
    [exp fulfill];
  }];

  [postflightResult enableBundles:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult enableTransitiveRules:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult enableAllEventUpload:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult disableUnknownEventUpload:^(BOOL val){
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [postflightResult overrideFileAccessAction:^(NSString *val){
    XCTAssertEqualObjects(val, @"disable");
    [exp fulfill];
  }];

  // Low timeout because code above is synchronous
  [self waitForExpectationsWithTimeout:0.1 handler:NULL];
}

@end
