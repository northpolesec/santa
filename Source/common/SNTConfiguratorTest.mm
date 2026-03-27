/// Copyright 2024 Google LLC
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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"

typedef BOOL (^StateFileAccessAuthorizer)(void);

@interface SNTConfigurator (Testing)
- (instancetype)initWithSyncStateFile:(NSString*)syncStateFilePath
                            stateFile:(NSString*)stateFilePath
                         oldStateFile:(NSString*)oldStateFilePath
            syncStateAccessAuthorizer:(StateFileAccessAuthorizer)syncStateAccessAuthorizer
                stateAccessAuthorizer:(StateFileAccessAuthorizer)stateAccessAuthorizer;

@property NSMutableDictionary* configState;
@property NSMutableDictionary* syncState;
@end

@interface SNTConfiguratorTest : XCTestCase
@property NSFileManager* fileMgr;
@property NSString* testDir;
@end

@implementation SNTConfiguratorTest

- (void)setUp {
  self.fileMgr = [NSFileManager defaultManager];
  self.testDir =
      [NSString stringWithFormat:@"%@santa-configurator-%d", NSTemporaryDirectory(), getpid()];

  XCTAssertTrue([self.fileMgr createDirectoryAtPath:self.testDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);
}

- (void)tearDown {
  XCTAssertTrue([self.fileMgr removeItemAtPath:self.testDir error:nil]);
}

- (void)runMigrationTestsWithSyncState:(NSDictionary*)syncStatePlist
                              verifier:(void (^)(SNTConfigurator*))verifierBlock {
  NSString* syncStatePlistPath =
      [NSString stringWithFormat:@"%@/test-sync-state.plist", self.testDir];

  XCTAssertTrue([syncStatePlist writeToFile:syncStatePlistPath atomically:YES]);

  SNTConfigurator* cfg = [[SNTConfigurator alloc] initWithSyncStateFile:syncStatePlistPath
      stateFile:@"/does/not/need/to/exist"
      oldStateFile:@"/does/not/need/to/exist"
      syncStateAccessAuthorizer:^{
        // Allow all access to the test plist
        return YES;
      }
      stateAccessAuthorizer:^BOOL {
        return NO;
      }];

  verifierBlock(cfg);

  XCTAssertTrue([self.fileMgr removeItemAtPath:syncStatePlistPath error:nil]);
}

- (void)testInitMigratesSyncStateKeys {
  // SyncCleanRequired = YES
  [self runMigrationTestsWithSyncState:@{@"SyncCleanRequired" : [NSNumber numberWithBool:YES]}
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertEqual(cfg.syncState.count, 1);
                                XCTAssertNil(cfg.syncState[@"SyncCleanRequired"]);
                                XCTAssertNotNil(cfg.syncState[@"SyncTypeRequired"]);
                                XCTAssertEqual([cfg.syncState[@"SyncTypeRequired"] integerValue],
                                               SNTSyncTypeClean);
                                XCTAssertEqual(cfg.syncState.count, 1);
                              }];

  // SyncCleanRequired = NO
  [self runMigrationTestsWithSyncState:@{@"SyncCleanRequired" : [NSNumber numberWithBool:NO]}
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertEqual(cfg.syncState.count, 1);
                                XCTAssertNil(cfg.syncState[@"SyncCleanRequired"]);
                                XCTAssertNotNil(cfg.syncState[@"SyncTypeRequired"]);
                                XCTAssertEqual([cfg.syncState[@"SyncTypeRequired"] integerValue],
                                               SNTSyncTypeNormal);
                                XCTAssertEqual(cfg.syncState.count, 1);
                              }];

  // Empty state
  [self runMigrationTestsWithSyncState:@{}
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertEqual(cfg.syncState.count, 0);
                                XCTAssertNil(cfg.syncState[@"SyncCleanRequired"]);
                                XCTAssertNil(cfg.syncState[@"SyncTypeRequired"]);
                              }];
}

- (void)testTelemetryFilterExpressions {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];

  {
    // No keys set, returns nil
    sut.configState[@"TelemetryFilterExpressions"] = nil;
    sut.syncState[@"TelemetryFilterExpressions"] = nil;
    XCTAssertNil(sut.telemetryFilterExpressions);
  }
  {
    // MDM config only, returns 1 valid expression
    sut.configState[@"TelemetryFilterExpressions"] = @[ @"true" ];
    sut.syncState[@"TelemetryFilterExpressions"] = nil;
    XCTAssertNotNil(sut.telemetryFilterExpressions);
    XCTAssertEqual(sut.telemetryFilterExpressions.count, 1);
  }
  {
    // Sync config only, returns 1 valid expression
    sut.configState[@"TelemetryFilterExpressions"] = nil;
    sut.syncState[@"TelemetryFilterExpressions"] = @[ @"true" ];
    XCTAssertNotNil(sut.telemetryFilterExpressions);
    XCTAssertEqual(sut.telemetryFilterExpressions.count, 1);
  }
  {
    // MDM & Sync config present, returns merged set, MDM config first
    sut.configState[@"TelemetryFilterExpressions"] = @[ @"true" ];
    sut.syncState[@"TelemetryFilterExpressions"] = @[ @"false" ];
    XCTAssertNotNil(sut.telemetryFilterExpressions);
    XCTAssertEqual(sut.telemetryFilterExpressions.count, 2);
    XCTAssertEqualObjects(sut.telemetryFilterExpressions[0], @"true");
    XCTAssertEqualObjects(sut.telemetryFilterExpressions[1], @"false");
  }
  {
    // Config with non-array is rejected
    sut.configState[@"TelemetryFilterExpressions"] = @"true";
    sut.syncState[@"TelemetryFilterExpressions"] = nil;
    XCTAssertNil(sut.telemetryFilterExpressions);
  }
  {
    // Config with array of non-strings is rejected
    sut.configState[@"TelemetryFilterExpressions"] = @[ @YES ];
    sut.syncState[@"TelemetryFilterExpressions"] = nil;
    XCTAssertNil(sut.telemetryFilterExpressions);
  }
}

@end
