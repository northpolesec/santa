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

#import "Source/common/SNTConfigBundle.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTExportConfiguration.h"

@interface SNTConfigBundle (Testing)
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
@property SNTExportConfiguration *exportConfiguration;
@property NSDate *fullSyncLastSuccess;
@property NSDate *ruleSyncLastSuccess;
@end

@interface SNTConfigBundleTest : XCTestCase
@end

@implementation SNTConfigBundleTest

- (void)testGettersWithValues {
  __block XCTestExpectation *exp = [self expectationWithDescription:@"Result Blocks"];
  exp.expectedFulfillmentCount = 14;
  NSDate *nowDate = [NSDate now];

  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];
  bundle.clientMode = @(SNTClientModeLockdown);
  bundle.syncType = @(SNTSyncTypeNormal);
  bundle.allowlistRegex = @"allow";
  bundle.blocklistRegex = @"block";
  bundle.blockUSBMount = @(YES);
  bundle.remountUSBMode = @[ @"foo" ];
  bundle.enableBundles = @(YES);
  bundle.enableTransitiveRules = @(YES);
  bundle.enableAllEventUpload = @(NO);
  bundle.disableUnknownEventUpload = @(YES);
  bundle.overrideFileAccessAction = @"disable";
  bundle.fullSyncLastSuccess = nowDate;
  bundle.ruleSyncLastSuccess = nowDate;
  bundle.exportConfiguration = [[SNTExportConfiguration alloc]
      initWithAWSToken:[@"foo" dataUsingEncoding:NSUTF8StringEncoding]];

  [bundle clientMode:^(SNTClientMode val) {
    XCTAssertEqual(val, SNTClientModeLockdown);
    [exp fulfill];
  }];

  [bundle syncType:^(SNTSyncType val) {
    XCTAssertEqual(val, SNTSyncTypeNormal);
    [exp fulfill];
  }];

  [bundle allowlistRegex:^(NSString *val) {
    XCTAssertEqualObjects(val, @"allow");
    [exp fulfill];
  }];

  [bundle blocklistRegex:^(NSString *val) {
    XCTAssertEqualObjects(val, @"block");
    [exp fulfill];
  }];

  [bundle blockUSBMount:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle remountUSBMode:^(NSArray *val) {
    XCTAssertEqualObjects(val, @[ @"foo" ]);
    [exp fulfill];
  }];

  [bundle enableBundles:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle enableTransitiveRules:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle enableAllEventUpload:^(BOOL val) {
    XCTAssertEqual(val, NO);
    [exp fulfill];
  }];

  [bundle disableUnknownEventUpload:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle overrideFileAccessAction:^(NSString *val) {
    XCTAssertEqualObjects(val, @"disable");
    [exp fulfill];
  }];

  [bundle exportConfiguration:^(SNTExportConfiguration *val) {
    XCTAssertEqual(val.configType, SNTExportConfigurationTypeAWS);
    [exp fulfill];
  }];

  [bundle fullSyncLastSuccess:^(NSDate *val) {
    XCTAssertEqualObjects(val, nowDate);
    [exp fulfill];
  }];

  [bundle ruleSyncLastSuccess:^(NSDate *val) {
    XCTAssertEqualObjects(val, nowDate);
    [exp fulfill];
  }];

  // Low timeout because code above is synchronous
  [self waitForExpectationsWithTimeout:0.1 handler:NULL];
}

- (void)testGettersWithoutValues {
  __block XCTestExpectation *exp = [self expectationWithDescription:@"Result Blocks"];
  exp.inverted = YES;

  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];

  [bundle clientMode:^(SNTClientMode val) {
    XCTAssertEqual(val, SNTClientModeLockdown);
    [exp fulfill];
  }];

  [bundle syncType:^(SNTSyncType val) {
    XCTAssertEqual(val, SNTSyncTypeNormal);
    [exp fulfill];
  }];

  [bundle allowlistRegex:^(NSString *val) {
    XCTAssertEqualObjects(val, @"allow");
    [exp fulfill];
  }];

  [bundle blocklistRegex:^(NSString *val) {
    XCTAssertEqualObjects(val, @"block");
    [exp fulfill];
  }];

  [bundle blockUSBMount:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle remountUSBMode:^(NSArray *val) {
    XCTAssertEqualObjects(val, @[ @"foo" ]);
    [exp fulfill];
  }];

  [bundle enableBundles:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle enableTransitiveRules:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle enableAllEventUpload:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle disableUnknownEventUpload:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle overrideFileAccessAction:^(NSString *val) {
    XCTAssertEqualObjects(val, @"disable");
    [exp fulfill];
  }];

  [bundle exportConfiguration:^(SNTExportConfiguration *val) {
    XCTAssertEqual(val.configType, SNTExportConfigurationTypeAWS);
    [exp fulfill];
  }];

  [bundle fullSyncLastSuccess:^(NSDate *val) {
    XCTAssertEqualObjects(val, [NSDate now]);
    [exp fulfill];
  }];

  [bundle ruleSyncLastSuccess:^(NSDate *val) {
    XCTAssertEqualObjects(val, [NSDate now]);
    [exp fulfill];
  }];

  // Low timeout because code above is synchronous
  [self waitForExpectationsWithTimeout:0.1 handler:NULL];
}

@end
