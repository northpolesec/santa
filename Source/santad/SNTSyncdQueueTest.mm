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

#import "Source/santad/SNTSyncdQueue.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"

@interface SNTSyncdQueue (Testing)
@property dispatch_queue_t syncdQueue;
@property MOLXPCConnection* syncConnection;
@property dispatch_source_t timer;
@property dispatch_source_t clearSyncStateTimer;
@property NSTimeInterval clearSyncStateGracePeriod;

- (BOOL)backoffForPrimaryHash:(NSString*)hash;
- (void)dispatchBlockOnSyncdQueue:(void (^)(void))block;
@end

@interface SNTSyncdQueueTest : XCTestCase
@end

@implementation SNTSyncdQueueTest

- (void)testBackoffForPrimaryHash {
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:256];

  // Fill up the cache.
  for (int i = 0; i < 256; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertFalse(backoff);
  }

  // These hashes should now backoff.
  for (int i = 0; i < 256; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertTrue(backoff);
  }

  // Overfill the cache, the cache should now only contain "justonemorebyte".
  XCTAssertFalse([sut backoffForPrimaryHash:@"justonemorebyte"]);
  XCTAssertTrue([sut backoffForPrimaryHash:@"justonemorebyte"]);

  // These hashes should not backoff, remember the cache was just cleared. However, only check 255
  // of the hashes, "justonemorebyte" takes us a slot. Checking the full 256 hashes here would
  // overfill the cache again.
  for (int i = 0; i < 255; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertFalse(backoff);
  }

  // Again, these hashes should now backoff.
  for (int i = 0; i < 255; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertTrue(backoff);
  }

  // A new hash arrives, and is then checked over and over.
  XCTAssertFalse([sut backoffForPrimaryHash:@"yes"]);
  for (int i = 0; i < 1000; ++i) {
    XCTAssertTrue([sut backoffForPrimaryHash:@"yes"]);
  }
}

- (void)testAddEvents {
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1024];
  sut = OCMPartialMock(sut);
  OCMStub([sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add an event, it should be dispatched to the sync service for upload.
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.fileSHA256 = @"123";
  [sut addStoredEvent:se];
  OCMVerify(times(1), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add the same event many times, they all should be dropped.
  for (int i = 0; i < 10; ++i) {
    [sut addStoredEvent:se];
  }
  OCMVerify(times(1), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Do it all again for SNTStoredFileAccessEvent
  SNTStoredFileAccessEvent* fe = [[SNTStoredFileAccessEvent alloc] init];
  fe.ruleName = @"MyRule";
  fe.ruleVersion = @"MyVersion";
  fe.process.fileSHA256 = @"123";

  [sut addStoredEvent:fe];
  OCMVerify(times(2), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add the same event many times, they all should be dropped.
  for (int i = 0; i < 10; ++i) {
    [sut addStoredEvent:fe];
  }
  OCMVerify(times(2), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);
}

- (void)testAddEventsRemovesBackoffOnFailure {
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1024];

  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  id mockProxy = OCMProtocolMock(@protocol(SNTSyncServiceXPC));
  OCMStub([mockConnection remoteObjectProxy]).andReturn(mockProxy);
  OCMStub([mockConnection isConnected]).andReturn(YES);
  sut.syncConnection = mockConnection;

  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.fileSHA256 = @"abc123";

  // First attempt: Post event, capture the reply block but don't invoke it yet
  __block void (^replyBlock)(BOOL) = nil;
  OCMStub([mockProxy postEventsToSyncServer:[OCMArg any]
                                      reply:[OCMArg checkWithBlock:^BOOL(id obj) {
                                        replyBlock = obj;
                                        return YES;
                                      }]]);
  [sut addStoredEvent:se];
  dispatch_sync(sut.syncdQueue, ^{
                });
  OCMVerify(times(1), [mockProxy postEventsToSyncServer:[OCMArg any] reply:[OCMArg any]]);

  // Second attempt: Event should be dropped due to backoff
  [sut addStoredEvent:se];
  dispatch_sync(sut.syncdQueue, ^{
                });
  OCMVerify(times(1), [mockProxy postEventsToSyncServer:[OCMArg any] reply:[OCMArg any]]);

  // Simulate the first upload failing, which should remove the backoff
  replyBlock(NO);

  // Third attempt: Since backoff was removed, event should be dispatched again
  [sut addStoredEvent:se];
  dispatch_sync(sut.syncdQueue, ^{
                });
  OCMVerify(times(2), [mockProxy postEventsToSyncServer:[OCMArg any] reply:[OCMArg any]]);

  // Fourth attempt: Event should be dropped due to backoff
  [sut addStoredEvent:se];
  dispatch_sync(sut.syncdQueue, ^{
                });
  OCMVerify(times(2), [mockProxy postEventsToSyncServer:[OCMArg any] reply:[OCMArg any]]);

  // Now simulate the second upload succeeding, which should keep the backoff
  replyBlock(YES);

  // Fifth attempt: Event should still be dropped due to backoff (success keeps backoff)
  [sut addStoredEvent:se];
  dispatch_sync(sut.syncdQueue, ^{
                });
  OCMVerify(times(2), [mockProxy postEventsToSyncServer:[OCMArg any] reply:[OCMArg any]]);
}

#pragma mark - Sync state cleanup on SyncBaseURL removal

/// Spin the main run loop until `predicate` holds or `timeout` elapses. The run loop must keep
/// turning because clearSyncState is dispatched to the main queue.
- (BOOL)waitUpTo:(NSTimeInterval)timeout forCondition:(BOOL (^)(void))predicate {
  NSDate* deadline = [NSDate dateWithTimeIntervalSinceNow:timeout];
  while ([deadline timeIntervalSinceNow] > 0) {
    if (predicate()) {
      return YES;
    }
    [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
  }
  return predicate();
}

/// A reassessment timer is one-shot, so a non-NULL `timer` must mean "armed and not yet fired".
/// Read on syncdQueue, the only place it is touched.
- (BOOL)reassessTimerArmedOn:(SNTSyncdQueue*)sut {
  __block BOOL armed = NO;
  dispatch_sync(sut.syncdQueue, ^{
    armed = (sut.timer != NULL);
  });
  return armed;
}

/// Whether a clear is armed. Read on syncdQueue, the only place clearSyncStateTimer is touched.
- (BOOL)clearIsArmedOn:(SNTSyncdQueue*)sut {
  __block BOOL armed = NO;
  dispatch_sync(sut.syncdQueue, ^{
    armed = (sut.clearSyncStateTimer != NULL);
  });
  return armed;
}

/// Stub the configurator singleton: SyncBaseURL from `urlProvider` (re-read on every call, so
/// tests can change it), and `onClear` in place of clearSyncState.
- (id)stubbedConfiguratorWithSyncBaseURLProvider:(NSURL* (^)(void))urlProvider
                                         onClear:(void (^)(void))onClear {
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator configurator]).andReturn(mockConfigurator);
  OCMStub([mockConfigurator syncBaseURL]).andDo(^(NSInvocation* invocation) {
    NSURL* url = urlProvider();
    [invocation setReturnValue:&url];
  });
  OCMStub([mockConfigurator clearSyncState]).andDo(^(NSInvocation* invocation) {
    onClear();
  });
  return mockConfigurator;
}

- (void)testSyncStateIsClearedAfterSyncBaseURLIsRemoved {
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];
  sut.clearSyncStateGracePeriod = 0.1;

  __block NSUInteger cleared = 0;
  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return nil;
      }
      onClear:^{
        ++cleared;
      }];

  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return cleared > 0;
                    }],
                @"clearSyncState must run once the grace period elapses with no SyncBaseURL");

  [mockConfigurator stopMocking];
}

// The rules left behind came from a server that is no longer an authority, so whichever server
// comes next must be asked for a clean sync. Recorded explicitly rather than left to
// `syncTypeRequired`'s empty-state default, which lapses to Normal as soon as postflight writes
// any other key.
- (void)testSyncBaseURLRemovalRecordsThatACleanSyncIsRequired {
  __block NSUInteger cleared = 0;
  __block NSMutableArray<NSNumber*>* syncTypesSet = [NSMutableArray array];

  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];
  sut.clearSyncStateGracePeriod = 0.1;

  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return nil;
      }
      onClear:^{
        ++cleared;
      }];
  OCMStub([mockConfigurator setSyncTypeRequired:SNTSyncTypeNormal])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        SNTSyncType type;
        [invocation getArgument:&type atIndex:2];
        [syncTypesSet addObject:@(type)];
      });

  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return cleared > 0;
                    }],
                @"Removing SyncBaseURL must clear the synced state");
  XCTAssertEqualObjects(syncTypesSet, (@[ @(SNTSyncTypeClean) ]),
                        @"Removing SyncBaseURL must record that a clean sync is required");

  [mockConfigurator stopMocking];
}

// The old server is no longer an authority, so its settings must not carry over. Rules are left
// alone: the requested Clean sync replaces them atomically during the new server's rule download.
- (void)testChangingSyncServerDropsPreviousServerStateAndRequestsCleanSync {
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];

  __block NSURL* syncBaseURL = [NSURL URLWithString:@"https://server-a.example.com/"];
  __block NSUInteger cleared = 0;
  __block NSMutableArray<NSNumber*>* syncTypesSet = [NSMutableArray array];

  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return syncBaseURL;
      }
      onClear:^{
        ++cleared;
      }];
  // Let the batch body run so the clear and sync-type writes inside it are observable.
  OCMStub([mockConfigurator performSyncStateBatch:[OCMArg invokeBlock]]);
  OCMStub([mockConfigurator setSyncTypeRequired:SNTSyncTypeNormal])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        SNTSyncType type;
        [invocation getArgument:&type atIndex:2];
        [syncTypesSet addObject:@(type)];
      });

  // Pretend the sync service is up, so the first pass records server A without a real XPC
  // connection.
  __block BOOL connected = YES;
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  OCMStub([mockConnection remoteObjectProxy])
      .andReturn(OCMProtocolMock(@protocol(SNTSyncServiceXPC)));
  OCMStub([mockConnection isConnected]).andDo(^(NSInvocation* invocation) {
    BOOL value = connected;
    [invocation setReturnValue:&value];
  });
  sut.syncConnection = mockConnection;

  [sut reassessSyncServiceConnectionImmediately];
  [self waitUpTo:0.2
      forCondition:^BOOL {
        return NO;
      }];
  XCTAssertEqual(cleared, 0u, @"Merely observing the current sync server must not drop state");

  // Server A -> server B. The first pass only bounces the connection.
  syncBaseURL = [NSURL URLWithString:@"https://server-b.example.com/"];
  [sut reassessSyncServiceConnectionImmediately];
  [self waitUpTo:0.2
      forCondition:^BOOL {
        return NO;
      }];
  XCTAssertEqual(cleared, 0u, @"State must not be dropped until the old sync service is down");

  // The old sync service has now exited, which is what drives the second reassessment.
  connected = NO;
  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return cleared > 0;
                    }],
                @"Changing sync servers must drop the previous server's synced state");
  XCTAssertEqualObjects(syncTypesSet, (@[ @(SNTSyncTypeClean) ]),
                        @"Changing sync servers must request exactly one Clean sync");

  [mockConfigurator stopMocking];
}

// The reassessment timer is one-shot, so every path through its handler must retire it -- not
// just the ones that reach the end. The bounce path returns early, and leaving a fired source
// parked in `timer` makes the coalescing check at the top of the next reassessment cancel an
// already-dead source, which is inert but reads as though a reassessment were still pending.
- (void)testBouncingTheSyncServiceRetiresTheReassessmentTimer {
  __block NSURL* syncBaseURL = [NSURL URLWithString:@"https://server-a.example.com/"];

  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];

  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return syncBaseURL;
      }
                                         onClear:^{
                                         }];
  OCMStub([mockConfigurator performSyncStateBatch:[OCMArg invokeBlock]]);

  // A connected sync service is what makes the change below take the bounce path.
  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  OCMStub([mockConnection remoteObjectProxy])
      .andReturn(OCMProtocolMock(@protocol(SNTSyncServiceXPC)));
  OCMStub([mockConnection isConnected]).andReturn(YES);
  sut.syncConnection = mockConnection;

  [sut reassessSyncServiceConnectionImmediately];
  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return ![self reassessTimerArmedOn:sut];
                    }],
                @"Sanity: a reassessment that runs to completion must retire its timer");

  // Server A -> server B with a live connection: the handler tears down and returns early.
  syncBaseURL = [NSURL URLWithString:@"https://server-b.example.com/"];
  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return ![self reassessTimerArmedOn:sut];
                    }],
                @"The bounce path must retire its timer too");

  [mockConfigurator stopMocking];
}

// Telemetry export is uploaded by santad via Sleigh, not by the sync service, so it has no say in
// whether synced state is kept once SyncBaseURL is gone.
- (void)testTelemetryExportDoesNotKeepSyncedStateAlive {
  __block NSUInteger cleared = 0;

  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];
  sut.clearSyncStateGracePeriod = 0.1;

  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator configurator]).andReturn(mockConfigurator);
  OCMStub([mockConfigurator syncBaseURL]).andDo(^(NSInvocation* invocation) {
    NSURL* url = nil;
    [invocation setReturnValue:&url];
  });
  OCMStub([mockConfigurator enableTelemetryExport]).andReturn(YES);
  OCMStub([mockConfigurator clearSyncState]).andDo(^(NSInvocation* invocation) {
    ++cleared;
  });

  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return cleared > 0;
                    }],
                @"Telemetry export must not keep synced state alive once SyncBaseURL is gone");

  [mockConfigurator stopMocking];
}

// A SyncBaseURL edited while santad was not running is the ordinary way a fleet changes sync
// servers -- the profile lands while the Mac is asleep or off. In-memory tracking starts empty
// every launch, so the previous server has to come from the persisted record instead.
- (void)testSyncServerChangeAcrossARestartIsDetectedFromPersistedState {
  __block NSUInteger cleared = 0;
  __block NSMutableArray<NSNumber*>* syncTypesSet = [NSMutableArray array];

  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return [NSURL URLWithString:@"https://server-b.example.com/"];
      }
      onClear:^{
        ++cleared;
      }];
  // Stands in for server A having been recorded before this launch.
  OCMStub([mockConfigurator savedLastSyncServerURL])
      .andReturn([NSURL URLWithString:@"https://server-a.example.com/"]);
  OCMStub([mockConfigurator performSyncStateBatch:[OCMArg invokeBlock]]);
  OCMStub([mockConfigurator setSyncTypeRequired:SNTSyncTypeNormal])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        SNTSyncType type;
        [invocation getArgument:&type atIndex:2];
        [syncTypesSet addObject:@(type)];
      });

  // Constructed after the stub is in place: the queue seeds itself at init.
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];

  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return cleared > 0;
                    }],
                @"A sync server change spanning a restart must drop the previous server's state");
  XCTAssertEqualObjects(syncTypesSet, (@[ @(SNTSyncTypeClean) ]),
                        @"It must request exactly one Clean sync");

  [mockConfigurator stopMocking];
}

// Removing one server and adding another is still a server change, even though SyncBaseURL passes
// through nil on the way. Swapping inside the grace period cancels the pending clear, so without
// change detection across the gap the new server would silently inherit the old server's state.
- (void)testSwappingSyncServersViaNilStillDropsPreviousServerState {
  __block NSURL* syncBaseURL = [NSURL URLWithString:@"https://server-a.example.com/"];
  __block NSUInteger cleared = 0;
  __block NSMutableArray<NSNumber*>* syncTypesSet = [NSMutableArray array];

  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];
  // Long enough that the swap below lands well inside the grace period.
  sut.clearSyncStateGracePeriod = 60;

  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return syncBaseURL;
      }
      onClear:^{
        ++cleared;
      }];
  OCMStub([mockConfigurator performSyncStateBatch:[OCMArg invokeBlock]]);
  OCMStub([mockConfigurator setSyncTypeRequired:SNTSyncTypeNormal])
      .ignoringNonObjectArgs()
      .andDo(^(NSInvocation* invocation) {
        SNTSyncType type;
        [invocation getArgument:&type atIndex:2];
        [syncTypesSet addObject:@(type)];
      });

  // Observe server A. Reassessments coalesce, so this must be given time to land before the
  // removal below, or server A is never recorded in the first place.
  [sut reassessSyncServiceConnectionImmediately];
  [self waitUpTo:0.2
      forCondition:^BOOL {
        return NO;
      }];

  // Remove it. Removal only arms a clear; nothing is dropped yet.
  syncBaseURL = nil;
  [sut reassessSyncServiceConnectionImmediately];
  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return [self clearIsArmedOn:sut];
                    }],
                @"Removing SyncBaseURL must arm a pending sync state clear");
  XCTAssertEqual(cleared, 0u, @"The grace period must not have elapsed yet");

  // Server B arrives inside the grace period, cancelling that pending clear.
  syncBaseURL = [NSURL URLWithString:@"https://server-b.example.com/"];
  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return cleared > 0;
                    }],
                @"Swapping servers via nil must still drop the previous server's synced state");
  XCTAssertEqualObjects(syncTypesSet, (@[ @(SNTSyncTypeClean) ]),
                        @"Swapping servers via nil must request exactly one Clean sync");

  [mockConfigurator stopMocking];
}

// A SyncBaseURL landing during the hop to the main queue arrives too late for
// -cancelPendingClearSyncStateSerialized to stop the clear, so the far side must re-check.
- (void)testClearIsSkippedWhenSyncBaseURLReturnsDuringMainQueueHop {
  __block NSURL* syncBaseURL = nil;
  __block NSUInteger cleared = 0;

  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];
  sut.clearSyncStateGracePeriod = 1;

  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return syncBaseURL;
      }
      onClear:^{
        ++cleared;
      }];

  // Arm a clear, and wait for it so restoring the URL below genuinely happens after arming.
  [sut reassessSyncServiceConnectionImmediately];
  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return [self clearIsArmedOn:sut];
                    }],
                @"Removing SyncBaseURL must arm a pending sync state clear");

  // No reassessment, so nothing calls -cancelPendingClearSyncStateSerialized: the armed clear
  // fires anyway and must catch this itself after the hop.
  syncBaseURL = [NSURL URLWithString:@"https://sync.example.com/"];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return ![self clearIsArmedOn:sut];
                    }],
                @"The armed clear must fire rather than stay armed");
  [[NSRunLoop currentRunLoop] runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];
  XCTAssertEqual(cleared, 0u,
                 @"A SyncBaseURL that lands during the main-queue hop must cancel the clear");

  [mockConfigurator stopMocking];
}

- (void)testPendingSyncStateClearIsCancelledWhenSyncBaseURLReturns {
  SNTSyncdQueue* sut = [[SNTSyncdQueue alloc] initWithCacheSize:1];
  sut.clearSyncStateGracePeriod = 30;

  __block NSURL* syncBaseURL = nil;
  __block NSUInteger cleared = 0;
  id mockConfigurator = [self
      stubbedConfiguratorWithSyncBaseURLProvider:^NSURL* {
        return syncBaseURL;
      }
      onClear:^{
        ++cleared;
      }];

  // Wait for the clear to be armed, otherwise the cancellation below races nothing and the test
  // is vacuous.
  [sut reassessSyncServiceConnectionImmediately];
  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return [self clearIsArmedOn:sut];
                    }],
                @"Removing SyncBaseURL must arm a pending sync state clear");

  // SyncBaseURL comes back within the grace period; the pending clear must be dropped.
  syncBaseURL = [NSURL URLWithString:@"https://sync.example.com/"];
  [sut reassessSyncServiceConnectionImmediately];

  XCTAssertTrue([self waitUpTo:5
                    forCondition:^BOOL {
                      return ![self clearIsArmedOn:sut];
                    }],
                @"A returning SyncBaseURL must disarm the pending sync state clear");
  XCTAssertEqual(cleared, 0u, @"Sync state must survive a SyncBaseURL that returns in time");

  [mockConfigurator stopMocking];
}

@end
