/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santad/SNTSyncdQueue.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"

@interface SNTSyncdQueue (Testing)
@property dispatch_queue_t syncdQueue;
@property MOLXPCConnection *syncConnection;

- (BOOL)backoffForPrimaryHash:(NSString *)hash;
- (void)dispatchBlockOnSyncdQueue:(void (^)(void))block;
@end

@interface SNTSyncdQueueTest : XCTestCase
@end

@implementation SNTSyncdQueueTest

- (void)testBackoffForPrimaryHash {
  SNTSyncdQueue *sut = [[SNTSyncdQueue alloc] initWithCacheSize:256];

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
  SNTSyncdQueue *sut = [[SNTSyncdQueue alloc] initWithCacheSize:1024];
  sut = OCMPartialMock(sut);
  OCMStub([sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add an event, it should be dispatched to the sync service for upload.
  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];
  se.fileSHA256 = @"123";
  [sut addStoredEvent:se];
  OCMVerify(times(1), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add the same event many times, they all should be dropped.
  for (int i = 0; i < 10; ++i) {
    [sut addStoredEvent:se];
  }
  OCMVerify(times(1), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Do it all again for SNTStoredFileAccessEvent
  SNTStoredFileAccessEvent *fe = [[SNTStoredFileAccessEvent alloc] init];
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
  SNTSyncdQueue *sut = [[SNTSyncdQueue alloc] initWithCacheSize:1024];

  id mockConnection = OCMClassMock([MOLXPCConnection class]);
  id mockProxy = OCMProtocolMock(@protocol(SNTSyncServiceXPC));
  OCMStub([mockConnection remoteObjectProxy]).andReturn(mockProxy);
  OCMStub([mockConnection isConnected]).andReturn(YES);
  sut.syncConnection = mockConnection;

  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];
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

  // Now simulate the first upload failing, which should remove the backoff
  replyBlock(NO);

  // Third attempt: Since backoff was removed, event should be dispatched again
  [sut addStoredEvent:se];
  dispatch_sync(sut.syncdQueue, ^{
                });
  OCMVerify(times(2), [mockProxy postEventsToSyncServer:[OCMArg any] reply:[OCMArg any]]);
}

@end
