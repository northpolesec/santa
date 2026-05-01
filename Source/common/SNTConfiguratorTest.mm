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

- (void)testInitMigratesRemovableMediaSyncStateKeys {
  // BlockUSBMount=YES + RemountUSBMode → RemovableMediaAction="Remount" + flags
  [self runMigrationTestsWithSyncState:@{
    @"BlockUSBMount" : @YES,
    @"RemountUSBMode" : @[ @"rdonly", @"noexec" ],
  }
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertNil(cfg.syncState[@"BlockUSBMount"]);
                                XCTAssertNil(cfg.syncState[@"RemountUSBMode"]);
                                XCTAssertEqualObjects(cfg.syncState[@"RemovableMediaAction"],
                                                      @"Remount");
                                XCTAssertEqualObjects(cfg.syncState[@"RemovableMediaRemountFlags"],
                                                      (@[ @"rdonly", @"noexec" ]));
                              }];

  // BlockUSBMount=YES + no RemountUSBMode → RemovableMediaAction="Block"
  [self runMigrationTestsWithSyncState:@{@"BlockUSBMount" : @YES}
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertNil(cfg.syncState[@"BlockUSBMount"]);
                                XCTAssertEqualObjects(cfg.syncState[@"RemovableMediaAction"],
                                                      @"Block");
                                XCTAssertNil(cfg.syncState[@"RemovableMediaRemountFlags"]);
                              }];

  // BlockUSBMount=NO → RemovableMediaAction="Allow"
  [self runMigrationTestsWithSyncState:@{@"BlockUSBMount" : @NO}
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertNil(cfg.syncState[@"BlockUSBMount"]);
                                XCTAssertEqualObjects(cfg.syncState[@"RemovableMediaAction"],
                                                      @"Allow");
                                XCTAssertNil(cfg.syncState[@"RemovableMediaRemountFlags"]);
                              }];

  // BlockUSBMount + RemovableMediaAction already set → does NOT overwrite
  [self runMigrationTestsWithSyncState:@{
    @"BlockUSBMount" : @YES,
    @"RemountUSBMode" : @[ @"rdonly" ],
    @"RemovableMediaAction" : @"Allow",
  }
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertNil(cfg.syncState[@"BlockUSBMount"]);
                                XCTAssertNil(cfg.syncState[@"RemountUSBMode"]);
                                // Existing value preserved, not overwritten
                                XCTAssertEqualObjects(cfg.syncState[@"RemovableMediaAction"],
                                                      @"Allow");
                                XCTAssertNil(cfg.syncState[@"RemovableMediaRemountFlags"]);
                              }];

  // No BlockUSBMount → no migration
  [self runMigrationTestsWithSyncState:@{}
                              verifier:^(SNTConfigurator* cfg) {
                                XCTAssertNil(cfg.syncState[@"RemovableMediaAction"]);
                                XCTAssertNil(cfg.syncState[@"RemovableMediaRemountFlags"]);
                              }];
}

- (void)testSyncBaseURLRejectsNonLocalhostHTTP {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];

  // HTTPS is always allowed.
  sut.configState[@"SyncBaseURL"] = @"https://example.com/api";
  XCTAssertNotNil(sut.syncBaseURL);
  XCTAssertEqualObjects(sut.syncBaseURL.host, @"example.com");

  // HTTP to localhost is allowed.
  sut.configState[@"SyncBaseURL"] = @"http://localhost:8080/api";
  XCTAssertNotNil(sut.syncBaseURL);
  XCTAssertEqualObjects(sut.syncBaseURL.host, @"localhost");

  // HTTP to 127.0.0.1 is allowed.
  sut.configState[@"SyncBaseURL"] = @"http://127.0.0.1:8080/api";
  XCTAssertNotNil(sut.syncBaseURL);
  XCTAssertEqualObjects(sut.syncBaseURL.host, @"127.0.0.1");

  // HTTP to ::1 is allowed.
  sut.configState[@"SyncBaseURL"] = @"http://[::1]:8080/api";
  XCTAssertNotNil(sut.syncBaseURL);
  XCTAssertEqualObjects(sut.syncBaseURL.host, @"::1");

  // HTTP to a non-localhost host is rejected.
  sut.configState[@"SyncBaseURL"] = @"http://example.com/api";
  XCTAssertNil(sut.syncBaseURL);

  sut.configState[@"SyncBaseURL"] = @"http://10.0.0.1/api";
  XCTAssertNil(sut.syncBaseURL);

  // Empty and missing values return nil.
  sut.configState[@"SyncBaseURL"] = @"";
  XCTAssertNil(sut.syncBaseURL);

  sut.configState[@"SyncBaseURL"] = nil;
  XCTAssertNil(sut.syncBaseURL);
}

- (void)testSyncBaseURLConfigured {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];

  // A value is configured, even if syncBaseURL rejects it.
  sut.configState[@"SyncBaseURL"] = @"http://example.com/api";
  XCTAssertNil(sut.syncBaseURL);
  XCTAssertTrue(sut.syncBaseURLConfigured);

  // A valid value is also reported as configured.
  sut.configState[@"SyncBaseURL"] = @"https://example.com/api";
  XCTAssertTrue(sut.syncBaseURLConfigured);

  // Empty and missing values are not configured.
  sut.configState[@"SyncBaseURL"] = @"";
  XCTAssertFalse(sut.syncBaseURLConfigured);

  sut.configState[@"SyncBaseURL"] = nil;
  XCTAssertFalse(sut.syncBaseURLConfigured);
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

- (void)testAllowDelegatedSignalsDefault {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];
  // Default must be NO so the bypass closes out of the box on 15.5+.
  XCTAssertFalse(sut.allowDelegatedSignals);
}

- (void)testAllowDelegatedSignalsOverride {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];

  sut.configState[@"AllowDelegatedSignals"] = @YES;
  XCTAssertTrue(sut.allowDelegatedSignals);

  sut.configState[@"AllowDelegatedSignals"] = @NO;
  XCTAssertFalse(sut.allowDelegatedSignals);
}

@end
