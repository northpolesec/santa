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

#import "Source/santasyncservice/SNTSyncConfigBundle.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigBundle.h"
#import "Source/santasyncservice/SNTSyncState.h"

@interface SNTConfigBundle (ConfigBundleCreator)
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
@property NSDate *fullSyncLastSuccess;
@property NSDate *ruleSyncLastSuccess;
@end

@interface SNTSyncConfigBundleTest : XCTestCase
@end

@implementation SNTSyncConfigBundleTest

- (void)testPostflightConfigBundle {
  SNTConfigBundle *bundle;
  SNTSyncState *syncState = [[SNTSyncState alloc] init];

  syncState.clientMode = SNTClientModeUnknown;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertNil(bundle.clientMode);

  syncState.clientMode = SNTClientModeMonitor;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.clientMode, @(SNTClientModeMonitor));

  syncState.syncType = SNTSyncTypeNormal;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertNil(bundle.syncType);

  syncState.syncType = SNTSyncTypeClean;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeNormal));

  syncState.syncType = SNTSyncTypeCleanAll;
  bundle = PostflightConfigBundle(syncState);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeNormal));
}

- (void)testRuleSyncConfigBundle {
  NSDate *curTime = [NSDate now];
  SNTConfigBundle *bundle = RuleSyncConfigBundle();
  XCTAssertGreaterThanOrEqual([bundle.ruleSyncLastSuccess timeIntervalSince1970],
                              [curTime timeIntervalSince1970]);

  XCTAssertNil(bundle.clientMode);
  XCTAssertNil(bundle.syncType);
  XCTAssertNil(bundle.allowlistRegex);
  XCTAssertNil(bundle.blocklistRegex);
  XCTAssertNil(bundle.blockUSBMount);
  XCTAssertNil(bundle.remountUSBMode);
  XCTAssertNil(bundle.enableBundles);
  XCTAssertNil(bundle.enableTransitiveRules);
  XCTAssertNil(bundle.enableAllEventUpload);
  XCTAssertNil(bundle.disableUnknownEventUpload);
  XCTAssertNil(bundle.overrideFileAccessAction);
  XCTAssertNil(bundle.fullSyncLastSuccess);
}

- (void)testSyncTypeConfigBundle {
  SNTConfigBundle *bundle;

  bundle = SyncTypeConfigBundle(SNTSyncTypeNormal);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeNormal));

  bundle = SyncTypeConfigBundle(SNTSyncTypeCleanAll);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeCleanAll));

  bundle = SyncTypeConfigBundle(SNTSyncTypeClean);
  XCTAssertEqualObjects(bundle.syncType, @(SNTSyncTypeClean));

  XCTAssertNil(bundle.clientMode);
  XCTAssertNil(bundle.allowlistRegex);
  XCTAssertNil(bundle.blocklistRegex);
  XCTAssertNil(bundle.blockUSBMount);
  XCTAssertNil(bundle.remountUSBMode);
  XCTAssertNil(bundle.enableBundles);
  XCTAssertNil(bundle.enableTransitiveRules);
  XCTAssertNil(bundle.enableAllEventUpload);
  XCTAssertNil(bundle.disableUnknownEventUpload);
  XCTAssertNil(bundle.overrideFileAccessAction);
  XCTAssertNil(bundle.fullSyncLastSuccess);
  XCTAssertNil(bundle.ruleSyncLastSuccess);
}

@end
