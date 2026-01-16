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
#import "Source/common/SNTModeTransition.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"

@interface SNTConfigBundle (Testing)
@property NSNumber *clientMode;
@property NSNumber *syncType;
@property NSString *allowlistRegex;
@property NSString *blocklistRegex;
@property NSNumber *blockUSBMount;
@property NSArray *remountUSBMode;
@property NSNumber *blockNetworkMount;
@property NSString *bannedNetworkMountBlockMessage;
@property NSArray<NSString *> *allowedNetworkMountHosts;
@property NSNumber *enableBundles;
@property NSNumber *enableTransitiveRules;
@property NSNumber *enableAllEventUpload;
@property NSNumber *disableUnknownEventUpload;
@property NSString *overrideFileAccessAction;
@property SNTExportConfiguration *exportConfiguration;
@property NSDate *fullSyncLastSuccess;
@property NSDate *ruleSyncLastSuccess;
@property SNTModeTransition *modeTransition;
@property NSString *eventDetailURL;
@property NSString *eventDetailText;
@property NSNumber *enableNotificationSilences;
@property SNTNetworkExtensionSettings *networkExtensionSettings;
@end

@interface SNTConfigBundleTest : XCTestCase
@end

@implementation SNTConfigBundleTest

- (void)testGettersWithValues {
  __block XCTestExpectation *exp = [self expectationWithDescription:@"Result Blocks"];
  exp.expectedFulfillmentCount = 22;
  NSDate *nowDate = [NSDate now];

  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];
  bundle.clientMode = @(SNTClientModeLockdown);
  bundle.syncType = @(SNTSyncTypeNormal);
  bundle.allowlistRegex = @"allow";
  bundle.blocklistRegex = @"block";
  bundle.blockUSBMount = @(YES);
  bundle.remountUSBMode = @[ @"foo" ];
  bundle.blockNetworkMount = @(YES);
  bundle.bannedNetworkMountBlockMessage = @"Network mount blocked";
  bundle.allowedNetworkMountHosts = @[ @"example.com", @"localhost" ];
  bundle.enableBundles = @(YES);
  bundle.enableTransitiveRules = @(YES);
  bundle.enableAllEventUpload = @(NO);
  bundle.disableUnknownEventUpload = @(YES);
  bundle.overrideFileAccessAction = @"disable";
  bundle.fullSyncLastSuccess = nowDate;
  bundle.ruleSyncLastSuccess = nowDate;
  bundle.exportConfiguration = [[SNTExportConfiguration alloc]
      initWithURL:[NSURL URLWithString:@"https://example.com/upload"]
       formValues:@{@"key1" : @"value1", @"key2" : @"value2"}];
  bundle.modeTransition = [[SNTModeTransition alloc] initOnDemandMinutes:4 defaultDuration:2];
  bundle.eventDetailURL = @"https://example.com/details";
  bundle.eventDetailText = @"View Details";
  bundle.enableNotificationSilences = @(YES);
  bundle.networkExtensionSettings = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES];

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

  [bundle blockNetworkMount:^(BOOL val) {
    XCTAssertNotEqual(val, NO);
    [exp fulfill];
  }];

  [bundle bannedNetworkMountBlockMessage:^(NSString *val) {
    XCTAssertEqualObjects(val, @"Network mount blocked");
    [exp fulfill];
  }];

  [bundle allowedNetworkMountHosts:^(NSArray<NSString *> *val) {
    XCTAssertEqualObjects(val, (@[ @"example.com", @"localhost" ]));
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
    XCTAssertEqualObjects(val.url, [NSURL URLWithString:@"https://example.com/upload"]);
    XCTAssertEqualObjects(val.formValues[@"key1"], @"value1");
    XCTAssertEqualObjects(val.formValues[@"key2"], @"value2");
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

  [bundle modeTransition:^(SNTModeTransition *val) {
    XCTAssertEqual(val.type, SNTModeTransitionTypeOnDemand);
    XCTAssertEqualObjects(val.maxMinutes, @(4));
    XCTAssertEqualObjects(val.defaultDurationMinutes, @(2));
    [exp fulfill];
  }];

  [bundle eventDetailURL:^(NSString *val) {
    XCTAssertEqualObjects(val, @"https://example.com/details");
    [exp fulfill];
  }];

  [bundle eventDetailText:^(NSString *val) {
    XCTAssertEqualObjects(val, @"View Details");
    [exp fulfill];
  }];

  [bundle enableNotificationSilences:^(BOOL val) {
    XCTAssertTrue(val);
    [exp fulfill];
  }];

  [bundle networkExtensionSettings:^(SNTNetworkExtensionSettings *val) {
    XCTAssertNotNil(val);
    XCTAssertTrue(val.enable);
    [exp fulfill];
  }];

  // Low timeout because code above is synchronous
  [self waitForExpectationsWithTimeout:0.1 handler:NULL];
}

- (void)testGettersWithoutValues {
  SNTConfigBundle *bundle = [[SNTConfigBundle alloc] init];

  [bundle clientMode:^(SNTClientMode val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle syncType:^(SNTSyncType val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle allowlistRegex:^(NSString *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle blocklistRegex:^(NSString *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle blockUSBMount:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle remountUSBMode:^(NSArray *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle blockNetworkMount:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle bannedNetworkMountBlockMessage:^(NSString *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle allowedNetworkMountHosts:^(NSArray<NSString *> *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle enableBundles:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle enableTransitiveRules:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle enableAllEventUpload:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle disableUnknownEventUpload:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle overrideFileAccessAction:^(NSString *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle exportConfiguration:^(SNTExportConfiguration *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle fullSyncLastSuccess:^(NSDate *val) {
    XCTAssertEqualObjects(val, [NSDate now]);
  }];

  [bundle ruleSyncLastSuccess:^(NSDate *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle modeTransition:^(SNTModeTransition *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle eventDetailURL:^(NSString *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle eventDetailText:^(NSString *val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle enableNotificationSilences:^(BOOL val) {
    XCTFail(@"This shouldn't be called");
  }];

  [bundle networkExtensionSettings:^(SNTNetworkExtensionSettings *val) {
    XCTFail(@"This shouldn't be called");
  }];
}

@end
