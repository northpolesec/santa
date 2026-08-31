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
            syncStateAccessAuthorizer:(StateFileAccessAuthorizer)syncStateAccessAuthorizer
                stateAccessAuthorizer:(StateFileAccessAuthorizer)stateAccessAuthorizer;

@property NSMutableDictionary* configState;
@property NSMutableDictionary* syncState;
@end

// Records the key paths for which KVO notifications are received.
@interface SNTKVORecordingObserver : NSObject
@property NSCountedSet<NSString*>* firedKeyPaths;
@end

@implementation SNTKVORecordingObserver
- (instancetype)init {
  self = [super init];
  if (self) {
    _firedKeyPaths = [NSCountedSet set];
  }
  return self;
}
- (void)observeValueForKeyPath:(NSString*)keyPath
                      ofObject:(id)object
                        change:(NSDictionary*)change
                       context:(void*)context {
  [self.firedKeyPaths addObject:keyPath];
}
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

- (void)testBinaryUploadFilterExpressions {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];

  {
    // No keys set, returns nil
    sut.configState[@"BinaryUploadFilterExpressions"] = nil;
    sut.syncState[@"BinaryUploadFilterExpressions"] = nil;
    XCTAssertNil(sut.binaryUploadFilterExpressions);
  }
  {
    // MDM config only, returns 1 valid expression
    sut.configState[@"BinaryUploadFilterExpressions"] = @[ @"binary.is_platform_binary" ];
    sut.syncState[@"BinaryUploadFilterExpressions"] = nil;
    XCTAssertNotNil(sut.binaryUploadFilterExpressions);
    XCTAssertEqual(sut.binaryUploadFilterExpressions.count, 1);
  }
  {
    // Sync config only, returns 1 valid expression
    sut.configState[@"BinaryUploadFilterExpressions"] = nil;
    sut.syncState[@"BinaryUploadFilterExpressions"] = @[ @"binary.is_platform_binary" ];
    XCTAssertNotNil(sut.binaryUploadFilterExpressions);
    XCTAssertEqual(sut.binaryUploadFilterExpressions.count, 1);
  }
  {
    // MDM & Sync config present, returns merged set, MDM config first
    sut.configState[@"BinaryUploadFilterExpressions"] = @[ @"binary.is_platform_binary" ];
    sut.syncState[@"BinaryUploadFilterExpressions"] = @[ @"binary.file_size > 100000000" ];
    XCTAssertNotNil(sut.binaryUploadFilterExpressions);
    XCTAssertEqual(sut.binaryUploadFilterExpressions.count, 2);
    XCTAssertEqualObjects(sut.binaryUploadFilterExpressions[0], @"binary.is_platform_binary");
    XCTAssertEqualObjects(sut.binaryUploadFilterExpressions[1], @"binary.file_size > 100000000");
  }
  {
    // Config with non-array is rejected
    sut.configState[@"BinaryUploadFilterExpressions"] = @"binary.is_platform_binary";
    sut.syncState[@"BinaryUploadFilterExpressions"] = nil;
    XCTAssertNil(sut.binaryUploadFilterExpressions);
  }
  {
    // Config with array of non-strings is rejected
    sut.configState[@"BinaryUploadFilterExpressions"] = @[ @YES ];
    sut.syncState[@"BinaryUploadFilterExpressions"] = nil;
    XCTAssertNil(sut.binaryUploadFilterExpressions);
  }
}

- (void)testAllowDelegatedSignalsDefault {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];
  // Default must be NO
  XCTAssertFalse(sut.allowDelegatedSignals);
}

- (void)testAllowDelegatedSignalsOverride {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];

  sut.configState[@"AllowDelegatedSignals"] = @YES;
  XCTAssertTrue(sut.allowDelegatedSignals);

  sut.configState[@"AllowDelegatedSignals"] = @NO;
  XCTAssertFalse(sut.allowDelegatedSignals);
}

#pragma mark - performSyncStateBatch: and clearSyncState tests

- (SNTConfigurator*)configuratorWithEmptySyncStateAtPath:(NSString*)plistPath {
  return [[SNTConfigurator alloc] initWithSyncStateFile:plistPath
      stateFile:@"/does/not/need/to/exist"
      syncStateAccessAuthorizer:^{
        return YES;
      }
      stateAccessAuthorizer:^BOOL {
        return NO;
      }];
}

- (void)observeValueForKeyPath:(NSString*)keyPath
                      ofObject:(id)object
                        change:(NSDictionary*)change
                       context:(void*)context {
  if (context != NULL) {
    NSUInteger* count = (NSUInteger*)context;
    (*count)++;
  }
}

/// Unlike configuratorWithEmptySyncStateAtPath:, this permits state-file access, which is what
/// the persisted last-sync-server record lives in.
- (SNTConfigurator*)configuratorWithStateFileAtPath:(NSString*)stateFilePath {
  return [[SNTConfigurator alloc] initWithSyncStateFile:@"/does/not/need/to/exist"
      stateFile:stateFilePath
      syncStateAccessAuthorizer:^{
        return NO;
      }
      stateAccessAuthorizer:^BOOL {
        return YES;
      }];
}

// The record has to outlive the daemon: a SyncBaseURL edited while santad was not running is the
// most common way a sync server changes, and in-memory tracking alone never sees it.
- (void)testLastSyncServerURLSurvivesARestart {
  NSString* statePath = [NSString stringWithFormat:@"%@/last-sync-server.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithStateFileAtPath:statePath];

  XCTAssertNil(cfg.savedLastSyncServerURL, @"Nothing is recorded before a sync server is seen");

  XCTAssertTrue([cfg persistLastSyncServerURL:[NSURL URLWithString:@"https://a.example.com/"]]);
  XCTAssertEqualObjects(cfg.savedLastSyncServerURL.absoluteString, @"https://a.example.com/");

  // A second configurator over the same file stands in for the next launch.
  SNTConfigurator* restarted = [self configuratorWithStateFileAtPath:statePath];
  XCTAssertEqualObjects(restarted.savedLastSyncServerURL.absoluteString, @"https://a.example.com/",
                        @"The recorded sync server must be readable after a restart");

  XCTAssertTrue([self.fileMgr removeItemAtPath:statePath error:nil]);
}

// Stored whole rather than by host, so that two tenants served from one host are distinguishable.
- (void)testLastSyncServerURLDistinguishesPathsOnTheSameHost {
  NSString* statePath = [NSString stringWithFormat:@"%@/last-sync-server-path.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithStateFileAtPath:statePath];

  [cfg persistLastSyncServerURL:[NSURL URLWithString:@"https://sync.example.com/tenant-a/"]];

  XCTAssertNotEqualObjects(cfg.savedLastSyncServerURL,
                           [NSURL URLWithString:@"https://sync.example.com/tenant-b/"]);

  XCTAssertTrue([self.fileMgr removeItemAtPath:statePath error:nil]);
}

- (void)testSyncTypeRequiredDefaultsToCleanWhenNoSyncStateExists {
  NSString* plistPath = [NSString stringWithFormat:@"%@/sync-type-default.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  // Clean, not CleanAll: SNTSyncPreflight escalates a CLEAN response to CleanAll only when the
  // client asked for CleanAll, so this leaves the server the final say.
  XCTAssertEqual(cfg.syncTypeRequired, SNTSyncTypeClean);
}

// A clean sync stays required until a server actually performs one. Postflight stamps
// FullSyncLastSuccess on every successful sync but only writes SyncTypeRequired when the server
// acknowledged the clean sync, so an explicitly recorded requirement must survive that write.
- (void)testExplicitCleanSyncTypeSurvivesUnacknowledgedSync {
  NSString* plistPath = [NSString stringWithFormat:@"%@/sync-type-sticky.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  [cfg setSyncTypeRequired:SNTSyncTypeClean];
  cfg.fullSyncLastSuccess = [NSDate now];

  XCTAssertEqual(cfg.syncTypeRequired, SNTSyncTypeClean,
                 @"A recorded clean-sync requirement must not lapse after a sync the server "
                 @"declined to perform cleanly");

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

/// Unlike the other helpers here, this models the *production* sync-state authorizer, which is
/// `syncBaseURL != nil && geteuid() == 0`. Tests that pin behaviour around a departing sync server
/// have to use it: an authorizer that always says yes hides the very gate they are about.
- (SNTConfigurator*)configuratorWithSyncStateAtPath:(NSString*)plistPath
                               syncServerConfigured:(BOOL (^)(void))syncServerConfigured {
  return [[SNTConfigurator alloc] initWithSyncStateFile:plistPath
      stateFile:@"/does/not/need/to/exist"
      syncStateAccessAuthorizer:^BOOL {
        return syncServerConfigured();
      }
      stateAccessAuthorizer:^BOOL {
        return NO;
      }];
}

// The clean-sync requirement recorded when SyncBaseURL goes away has to reach disk. It cannot be
// written through the ordinary path -- that path is gated on a configured sync server, and there
// isn't one any more, which is the whole reason this is happening. If the write is dropped the
// requirement lives only in the running daemon's memory, and a restart falls back to
// `syncTypeRequired`'s empty-state default, which lapses to Normal the moment postflight writes
// any other key (see testExplicitCleanSyncTypeSurvivesUnacknowledgedSync for that mechanism).
- (void)testCleanSyncRequirementRecordedOnSyncBaseURLRemovalIsDurable {
  NSString* plistPath = [NSString stringWithFormat:@"%@/removal-clean.plist", self.testDir];
  __block BOOL syncServerConfigured = YES;
  SNTConfigurator* cfg = [self configuratorWithSyncStateAtPath:plistPath
                                          syncServerConfigured:^BOOL {
                                            return syncServerConfigured;
                                          }];

  // A host that has been syncing: settings on disk, no clean sync pending.
  [cfg setSyncTypeRequired:SNTSyncTypeNormal];
  cfg.fullSyncLastSuccess = [NSDate now];
  XCTAssertTrue([self.fileMgr fileExistsAtPath:plistPath], @"Sanity: synced state must be on disk");

  // SyncBaseURL is removed and the grace period elapses.
  syncServerConfigured = NO;
  XCTAssertTrue([cfg clearSyncStateRequiringSyncType:SNTSyncTypeClean],
                @"The requirement must be recorded even though no sync server is configured");

  // A sync server is configured again and the daemon restarts, so everything is re-read from disk.
  syncServerConfigured = YES;
  SNTConfigurator* restarted = [self configuratorWithSyncStateAtPath:plistPath
                                                syncServerConfigured:^BOOL {
                                                  return syncServerConfigured;
                                                }];

  XCTAssertNil(restarted.fullSyncLastSuccess, @"The departed server's state must not come back");
  XCTAssertEqual(restarted.syncTypeRequired, SNTSyncTypeClean);

  // The decisive case: a server that declines the clean sync still writes other keys at postflight,
  // which is what makes the empty-state default lapse. The recorded requirement must outlast it.
  restarted.fullSyncLastSuccess = [NSDate now];
  XCTAssertEqual(restarted.syncTypeRequired, SNTSyncTypeClean,
                 @"The client must keep asking until a server actually performs the clean sync");

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

// The sync state file is only read when a sync server is configured, so a daemon that starts
// *after* SyncBaseURL was removed holds nothing in memory while the departed server's settings are
// still sitting on disk. Deciding from memory alone strands that file forever, and a later launch
// with a sync server configured would read a departed server's policy straight back in. This is
// the "removed while santad was not running" case, which is the ordinary way a fleet drops a sync
// server.
- (void)testSyncedSettingsAreFoundOnDiskWhenNoSyncServerIsConfigured {
  NSString* plistPath = [NSString stringWithFormat:@"%@/removed-while-down.plist", self.testDir];
  __block BOOL syncServerConfigured = YES;
  BOOL (^authorizer)(void) = ^BOOL {
    return syncServerConfigured;
  };

  SNTConfigurator* synced = [self configuratorWithSyncStateAtPath:plistPath
                                             syncServerConfigured:authorizer];
  [synced setSyncServerClientMode:SNTClientModeLockdown];
  XCTAssertTrue([self.fileMgr fileExistsAtPath:plistPath],
                @"Sanity: a synced setting must be on disk");

  // SyncBaseURL is removed while santad is down, then santad starts.
  syncServerConfigured = NO;
  SNTConfigurator* restarted = [self configuratorWithSyncStateAtPath:plistPath
                                                syncServerConfigured:authorizer];
  XCTAssertEqual(restarted.syncState.count, 0u,
                 @"Sanity: the file is not read into memory without a sync server");
  XCTAssertTrue(restarted.hasSyncedSettings,
                @"A departed server's settings still on disk must be recognised as droppable");

  XCTAssertTrue([restarted clearSyncStateRequiringSyncType:SNTSyncTypeClean]);

  // The next launch finds only the recorded requirement, which is not a synced setting, so it has
  // nothing to redo.
  SNTConfigurator* afterClear = [self configuratorWithSyncStateAtPath:plistPath
                                                 syncServerConfigured:authorizer];
  XCTAssertFalse(afterClear.hasSyncedSettings, @"Only the recorded clean-sync requirement is left");

  // The harm this prevents: with a sync server configured again the file *is* read, and it must no
  // longer carry the departed server's policy -- only the requirement that the next sync be clean.
  syncServerConfigured = YES;
  SNTConfigurator* nextServer = [self configuratorWithSyncStateAtPath:plistPath
                                                 syncServerConfigured:authorizer];
  XCTAssertEqual(nextServer.syncState.count, 1u,
                 @"A departed server's settings must not be read back by the next launch");
  XCTAssertEqual(nextServer.syncTypeRequired, SNTSyncTypeClean);

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

// Nothing calls it inside a batch today, but the branch that handles one is what stops a future
// caller from clobbering `syncState` and writing to disk mid-transaction, the way an unguarded
// implementation would. `clearSyncState` guards the same way for the same reason.
- (void)testClearSyncStateRequiringSyncTypeComposesWithABatch {
  NSString* plistPath = [NSString stringWithFormat:@"%@/reset-in-batch.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  cfg.fullSyncLastSuccess = [NSDate now];

  XCTAssertTrue([cfg performSyncStateBatch:^{
    XCTAssertTrue([cfg clearSyncStateRequiringSyncType:SNTSyncTypeClean]);
    // Still inside the transaction, so nothing has been published yet.
    XCTAssertNotNil(cfg.fullSyncLastSuccess);
  }]);

  XCTAssertNil(cfg.fullSyncLastSuccess, @"The batch must commit the clear");
  XCTAssertEqual(cfg.syncTypeRequired, SNTSyncTypeClean);
  XCTAssertFalse(cfg.hasSyncedSettings);

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

// `SyncTypeRequired` is this client's own bookkeeping, not something a server sent, so a state
// holding nothing else has to read as "never synced". SNTRuleTable records one when it creates the
// database, before any sync has happened, so counting it would make every host look like it holds
// a departed server's settings.
- (void)testHasSyncedSettingsIgnoresTheSyncTypeRequirement {
  NSString* plistPath = [NSString stringWithFormat:@"%@/has-synced-settings.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  XCTAssertFalse(cfg.hasSyncedSettings, @"A host that has never synced holds no settings");

  // Stands in for SNTRuleTable creating the rule database on a host with no sync server.
  [cfg setSyncTypeRequired:SNTSyncTypeCleanAll];
  XCTAssertFalse(cfg.hasSyncedSettings, @"The sync-type requirement alone is not a synced setting");

  [cfg setSyncServerClientMode:SNTClientModeLockdown];
  XCTAssertTrue(cfg.hasSyncedSettings);

  XCTAssertTrue([cfg clearSyncStateRequiringSyncType:SNTSyncTypeClean]);
  XCTAssertFalse(cfg.hasSyncedSettings,
                 @"Clearing leaves only the requirement, so there is nothing left to clear again");

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

// Sync-state writes are unconditional, so a no-op batch (e.g. a preflight whose config bundle
// carries nothing) would otherwise leave an empty plist behind. An empty plist and a missing one
// mean the same thing, so keep only the one that says so.
- (void)testSavingEmptySyncStateRemovesThePlistRatherThanWritingAnEmptyOne {
  NSString* plistPath = [NSString stringWithFormat:@"%@/empty-state.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  [cfg setSyncTypeRequired:SNTSyncTypeClean];
  XCTAssertTrue([self.fileMgr fileExistsAtPath:plistPath],
                @"Sanity: a populated sync state must be written to disk");

  // Mirrors a no-op batch committing an empty dictionary.
  XCTAssertTrue([cfg performSyncStateBatch:^{
    [cfg clearSyncState];
  }]);

  XCTAssertFalse([self.fileMgr fileExistsAtPath:plistPath],
                 @"An empty sync state must remove the plist, not write an empty one");
}

// Committing an empty state means removing the plist, so a removal that fails has not achieved
// durability any more than a failed write would have. Callers gate post-commit side effects on
// the returned flag, so it must not claim success.
- (void)testSavingEmptySyncStateReportsFailureWhenThePlistCannotBeRemoved {
  if (geteuid() == 0) {
    XCTSkip(@"Running as root defeats the directory permissions this test relies on");
  }

  NSString* lockedDir = [NSString stringWithFormat:@"%@/locked", self.testDir];
  XCTAssertTrue([self.fileMgr createDirectoryAtPath:lockedDir
                        withIntermediateDirectories:YES
                                         attributes:nil
                                              error:nil]);
  NSString* plistPath = [lockedDir stringByAppendingPathComponent:@"sync-state.plist"];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  [cfg setSyncTypeRequired:SNTSyncTypeClean];
  XCTAssertTrue([self.fileMgr fileExistsAtPath:plistPath], @"Sanity: the plist must exist");

  // A directory without write permission cannot have entries unlinked from it.
  XCTAssertTrue([self.fileMgr setAttributes:@{NSFilePosixPermissions : @0500}
                               ofItemAtPath:lockedDir
                                      error:nil]);
  BOOL committed = [cfg performSyncStateBatch:^{
    [cfg clearSyncState];
  }];
  XCTAssertTrue([self.fileMgr setAttributes:@{NSFilePosixPermissions : @0700}
                               ofItemAtPath:lockedDir
                                      error:nil]);

  XCTAssertFalse(committed, @"A plist that could not be removed must not report a durable commit");

  XCTAssertTrue([self.fileMgr removeItemAtPath:lockedDir error:nil]);
}

- (void)testSyncTypeRequiredReturnsCleanAfterSyncStateIsCleared {
  NSString* plistPath = [NSString stringWithFormat:@"%@/sync-type-cleared.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  [cfg setSyncTypeRequired:SNTSyncTypeNormal];
  XCTAssertEqual(cfg.syncTypeRequired, SNTSyncTypeNormal);

  [cfg clearSyncState];
  XCTAssertEqual(cfg.syncTypeRequired, SNTSyncTypeClean);
}

- (void)testPerformSyncStateBatchCommitsAsSingleKVOFire {
  NSString* plistPath = [NSString stringWithFormat:@"%@/batch-kvo.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  __block NSUInteger kvoCount = 0;
  [cfg addObserver:self
        forKeyPath:@"syncState"
           options:NSKeyValueObservingOptionNew
           context:&kvoCount];

  BOOL committed = [cfg performSyncStateBatch:^{
    [cfg setSyncServerClientMode:SNTClientModeLockdown];
    [cfg setEnableBundles:YES];
    [cfg setEnableTransitiveRules:YES];
  }];

  [cfg removeObserver:self forKeyPath:@"syncState" context:&kvoCount];

  XCTAssertTrue(committed, @"A successful batch must report committed=YES");
  XCTAssertEqual(kvoCount, (NSUInteger)1,
                 @"Expected exactly one KVO fire on syncState across the batch; got %lu",
                 (unsigned long)kvoCount);
  XCTAssertEqual(cfg.clientMode, SNTClientModeLockdown);
  XCTAssertTrue(cfg.enableBundles);
  XCTAssertTrue(cfg.enableTransitiveRules);

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

- (void)testPerformSyncStateBatchReturnsNoWhenDiskWriteFails {
  // Pointing the configurator at an unwritable path forces saveSyncStateToDisk
  // to fail. The in-memory commit still happens (KVO still fires) but the
  // BOOL return signals that durability was not achieved.
  NSString* plistPath = @"/this/directory/definitely/does/not/exist/batch.plist";
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  __block NSUInteger kvoCount = 0;
  [cfg addObserver:self
        forKeyPath:@"syncState"
           options:NSKeyValueObservingOptionNew
           context:&kvoCount];

  BOOL committed = [cfg performSyncStateBatch:^{
    [cfg setSyncServerClientMode:SNTClientModeLockdown];
  }];

  [cfg removeObserver:self forKeyPath:@"syncState" context:&kvoCount];

  XCTAssertFalse(committed, @"Batch must report committed=NO when the disk write fails");
  XCTAssertEqual(kvoCount, (NSUInteger)1,
                 @"In-memory state still commits before the disk write is attempted");
  XCTAssertEqual(cfg.clientMode, SNTClientModeLockdown);
}

- (void)testPerformSyncStateBatchWithClearAndWritesPersistsOnlyPostClearWrites {
  NSString* plistPath = [NSString stringWithFormat:@"%@/batch-clear.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  // Pre-populate stale state via the one-shot path.
  [cfg setSyncServerClientMode:SNTClientModeLockdown];
  [cfg setEnableBundles:YES];
  XCTAssertEqual(cfg.clientMode, SNTClientModeLockdown);
  XCTAssertTrue(cfg.enableBundles);

  // Inside the batch: clear, then write only one new key.
  [cfg performSyncStateBatch:^{
    [cfg clearSyncState];
    [cfg setSyncServerClientMode:SNTClientModeMonitor];
  }];

  // ClientMode set to the new value; EnableBundles was cleared and not rewritten.
  XCTAssertEqual(cfg.clientMode, SNTClientModeMonitor);
  XCTAssertFalse(cfg.enableBundles, @"EnableBundles should be cleared (default NO) after batch");

  // On disk: matches in-memory state, no stale keys.
  NSDictionary* onDisk = [NSDictionary dictionaryWithContentsOfFile:plistPath];
  XCTAssertEqualObjects(onDisk[@"ClientMode"], @(SNTClientModeMonitor));
  XCTAssertNil(onDisk[@"EnableBundles"], @"Stale EnableBundles key should be absent from disk");

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

- (void)testClearSyncStateRemovesDiskFileWhenOutsideBatch {
  NSString* plistPath = [NSString stringWithFormat:@"%@/clear-remove.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  // Force a disk write so the file exists.
  [cfg setSyncServerClientMode:SNTClientModeLockdown];
  XCTAssertTrue([self.fileMgr fileExistsAtPath:plistPath]);

  [cfg clearSyncState];

  XCTAssertFalse([self.fileMgr fileExistsAtPath:plistPath],
                 @"clearSyncState must remove sync-state.plist from disk");
  XCTAssertEqual(cfg.syncState.count, (NSUInteger)0);
}

- (void)testClearSyncStateIsIdempotentOnMissingFile {
  NSString* plistPath = [NSString stringWithFormat:@"%@/clear-missing.plist", self.testDir];
  SNTConfigurator* cfg = [self configuratorWithEmptySyncStateAtPath:plistPath];

  XCTAssertFalse([self.fileMgr fileExistsAtPath:plistPath]);

  // Should be a no-op, no exception, no error.
  XCTAssertNoThrow([cfg clearSyncState]);
  XCTAssertFalse([self.fileMgr fileExistsAtPath:plistPath]);

  // A second call is also a no-op.
  XCTAssertNoThrow([cfg clearSyncState]);
}

- (void)testClearSyncStateBypassesSyncStateAccessAuthorizer {
  // The production authorizer requires `syncBaseURL != nil`, but the
  // SNTSyncdQueue caller invokes clearSyncState precisely when SyncBaseURL
  // went to nil. Gating cleanup on the authorizer would make this caller a
  // no-op. Lock the bypass in with a configurator whose authorizer always
  // denies — clearSyncState must still drop in-memory state and the plist.
  NSString* plistPath = [NSString stringWithFormat:@"%@/clear-authdenied.plist", self.testDir];

  // Force a state file to exist on disk using a permissive configurator.
  SNTConfigurator* writer = [self configuratorWithEmptySyncStateAtPath:plistPath];
  [writer setSyncServerClientMode:SNTClientModeLockdown];
  XCTAssertTrue([self.fileMgr fileExistsAtPath:plistPath]);

  // Now construct a new configurator over the same path with a denying
  // authorizer and verify clearSyncState still cleans up.
  SNTConfigurator* cfg = [[SNTConfigurator alloc] initWithSyncStateFile:plistPath
      stateFile:@"/does/not/need/to/exist"
      syncStateAccessAuthorizer:^BOOL {
        return NO;
      }
      stateAccessAuthorizer:^BOOL {
        return NO;
      }];

  [cfg clearSyncState];

  XCTAssertEqual(cfg.syncState.count, (NSUInteger)0,
                 @"clearSyncState must reset in-memory state even when authorizer denies");
  XCTAssertFalse([self.fileMgr fileExistsAtPath:plistPath],
                 @"clearSyncState must remove the plist even when authorizer denies");
}

#pragma mark - keyPathsForValuesAffecting wiring

// Each of these key paths is observed by santad (Santad.mm) so that runtime
// config changes take effect. They are computed from configState, so they only
// fire if a correctly-named keyPathsForValuesAffecting<Key> declares the
// dependency. A missing or misnamed declaration silently breaks the watcher
// (e.g. the property renamed allowlist->allowed while the dependency method
// did not), so assert each fires exactly once when configState is replaced --
// the same setter path taken on a config reload.
- (void)testConfigStateChangeNotifiesDerivedKeyObservers {
  SNTConfigurator* cfg = [[SNTConfigurator alloc] init];
  SNTKVORecordingObserver* observer = [[SNTKVORecordingObserver alloc] init];

  NSArray<NSString*>* keyPaths = @[
    @"allowedPathRegex",
    @"blockedPathRegex",
    @"dnsUpstreamTimeoutSecs",
    @"enableSilentTTYMode",
    @"exportMetrics",
    @"metricExportInterval",
  ];

  for (NSString* keyPath in keyPaths) {
    [cfg addObserver:observer
          forKeyPath:keyPath
             options:NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld
             context:NULL];
  }

  // Replace configState via the property setter, exactly as a config reload does.
  cfg.configState = [@{
    @"AllowedPathRegex" : @"a",
    @"BlockedPathRegex" : @"b",
    @"DNSUpstreamTimeoutSeconds" : @(30.0),
    @"EnableSilentTTYMode" : @YES,
    @"ExportMetrics" : @YES,
    @"MetricExportInterval" : @123,
  } mutableCopy];

  for (NSString* keyPath in keyPaths) {
    [cfg removeObserver:observer forKeyPath:keyPath context:NULL];
  }

  for (NSString* keyPath in keyPaths) {
    XCTAssertEqual([observer.firedKeyPaths countForObject:keyPath], (NSUInteger)1,
                   @"configState change must notify observers of '%@' (got %lu). Check "
                   @"keyPathsForValuesAffecting<Key> in SNTConfigurator.mm.",
                   keyPath, (unsigned long)[observer.firedKeyPaths countForObject:keyPath]);
  }
}

// allowedPathRegex/blockedPathRegex fall back from syncState to configState, so
// their keyPathsForValuesAffecting methods depend on syncState too. The
// configState test above can't catch a regression that drops syncState from
// those declarations, so exercise the syncState half here.
- (void)testSyncStateChangeNotifiesSyncDerivedKeyObservers {
  SNTConfigurator* cfg = [[SNTConfigurator alloc] init];
  SNTKVORecordingObserver* observer = [[SNTKVORecordingObserver alloc] init];

  NSArray<NSString*>* keyPaths = @[
    @"allowedPathRegex",
    @"blockedPathRegex",
  ];

  for (NSString* keyPath in keyPaths) {
    [cfg addObserver:observer
          forKeyPath:keyPath
             options:NSKeyValueObservingOptionNew | NSKeyValueObservingOptionOld
             context:NULL];
  }

  // Replace syncState via the property setter, as a sync-state commit does.
  cfg.syncState = [@{
    @"AllowedPathRegex" : @"a",
    @"BlockedPathRegex" : @"b",
  } mutableCopy];

  for (NSString* keyPath in keyPaths) {
    [cfg removeObserver:observer forKeyPath:keyPath context:NULL];
  }

  for (NSString* keyPath in keyPaths) {
    XCTAssertEqual([observer.firedKeyPaths countForObject:keyPath], (NSUInteger)1,
                   @"syncState change must notify observers of '%@' (got %lu). Check "
                   @"keyPathsForValuesAffecting<Key> in SNTConfigurator.mm.",
                   keyPath, (unsigned long)[observer.firedKeyPaths countForObject:keyPath]);
  }
}

- (void)testDNSUpstreamTimeoutSecsForcedConfig {
  SNTConfigurator* sut = [[SNTConfigurator alloc] init];
  // Unset -> 0, the "use built-in default" sentinel. The default + [1,60]s clamp live downstream
  // in SNTNetworkExtensionSettings, so the configurator returns the raw forced value (or 0).
  XCTAssertEqual(sut.dnsUpstreamTimeoutSecs, 0);
  sut.configState[@"DNSUpstreamTimeoutSeconds"] = @(30.0);
  XCTAssertEqualWithAccuracy(sut.dnsUpstreamTimeoutSecs, 30.0, 0.0001);
}

- (void)testDemotedAdminsPersistReloadAndFilter {
  NSString* syncStatePath = [NSString stringWithFormat:@"%@/sync-state.plist", self.testDir];
  NSString* statePath = [NSString stringWithFormat:@"%@/state.plist", self.testDir];
  SNTConfigurator* (^makeConfigurator)(void) = ^SNTConfigurator* {
    return [[SNTConfigurator alloc] initWithSyncStateFile:syncStatePath
        stateFile:statePath
        syncStateAccessAuthorizer:^BOOL {
          return YES;
        }
        stateAccessAuthorizer:^BOOL {
          return YES;
        }];
  };

  SNTConfigurator* cfg = makeConfigurator();
  XCTAssertNil([cfg savedDemotedAdmins]);

  // Persisted record round-trips in memory and across a re-read from disk.
  NSArray<NSDictionary*>* record = @[ @{@"Username" : @"jane", @"UID" : @501} ];
  XCTAssertTrue([cfg persistDemotedAdmins:record]);
  XCTAssertEqualObjects([cfg savedDemotedAdmins], record);
  XCTAssertEqualObjects([makeConfigurator() savedDemotedAdmins], record);

  // An empty array is a present entry, distinct from nil.
  XCTAssertTrue([cfg persistDemotedAdmins:@[]]);
  XCTAssertNotNil([cfg savedDemotedAdmins]);
  XCTAssertEqual([cfg savedDemotedAdmins].count, 0u);
  XCTAssertNotNil([makeConfigurator() savedDemotedAdmins]);

  // nil deletes the entry, on disk too.
  XCTAssertTrue([cfg persistDemotedAdmins:nil]);
  XCTAssertNil([cfg savedDemotedAdmins]);
  XCTAssertNil([makeConfigurator() savedDemotedAdmins]);

  // A non-array value on disk is stripped by the readStateFromDisk allowlist.
  XCTAssertTrue([@{@"DemotedAdmins" : @"not-an-array"} writeToFile:statePath atomically:YES]);
  XCTAssertNil([makeConfigurator() savedDemotedAdmins]);
}

- (void)testDemotedAdminsPersistFailureRollsBack {
  NSString* syncStatePath = [NSString stringWithFormat:@"%@/sync-state-rb.plist", self.testDir];
  NSString* statePath = [NSString stringWithFormat:@"%@/state-rb.plist", self.testDir];
  __block BOOL allowStateWrites = NO;
  SNTConfigurator* cfg = [[SNTConfigurator alloc] initWithSyncStateFile:syncStatePath
      stateFile:statePath
      syncStateAccessAuthorizer:^BOOL {
        return YES;
      }
      stateAccessAuthorizer:^BOOL {
        return allowStateWrites;
      }];

  // Blocked disk write: reports failure and rolls back the in-memory record.
  XCTAssertFalse([cfg persistDemotedAdmins:(@[ @{@"Username" : @"jane", @"UID" : @501} ])]);
  XCTAssertNil([cfg savedDemotedAdmins]);

  // Write path recovers: the same persist succeeds and is visible.
  allowStateWrites = YES;
  XCTAssertTrue([cfg persistDemotedAdmins:(@[ @{@"Username" : @"jane", @"UID" : @501} ])]);
  XCTAssertNotNil([cfg savedDemotedAdmins]);
}

- (void)testClientModeIgnoringTemporaryMonitorMode {
  NSString* plistPath = [NSString stringWithFormat:@"%@/cm-ignoring-tmm.plist", self.testDir];
  SNTConfigurator* sut = [self configuratorWithEmptySyncStateAtPath:plistPath];
  [sut setSyncServerClientMode:SNTClientModeLockdown];

  XCTAssertEqual(sut.clientMode, SNTClientModeLockdown);
  XCTAssertEqual(sut.clientModeIgnoringTemporaryMonitorMode, SNTClientModeLockdown);

  [sut setInTemporaryMonitorMode:YES];

  // The masked getter reports Monitor during a session; the unmasked accessor
  // still reports the underlying Lockdown policy.
  XCTAssertEqual(sut.clientMode, SNTClientModeMonitor);
  XCTAssertEqual(sut.clientModeIgnoringTemporaryMonitorMode, SNTClientModeLockdown);

  [sut setInTemporaryMonitorMode:NO];
  [sut setSyncServerClientMode:SNTClientModeMonitor];
  XCTAssertEqual(sut.clientModeIgnoringTemporaryMonitorMode, SNTClientModeMonitor);

  XCTAssertTrue([self.fileMgr removeItemAtPath:plistPath error:nil]);
}

@end
