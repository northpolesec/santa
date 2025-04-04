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

#include <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import <OCMock/OCMock.h>

#import "Source/common/SNTStoredEvent.h"

@interface SNTSyncdQueue (Testing)
- (BOOL)backoffForPrimaryHash:(NSString *)hash;
- (void)dispatchBlockOnSyncdQueue:(void (^)(void))block;
@end

@interface SNTSyncdQueueTest : XCTestCase
@end

@implementation SNTSyncdQueueTest

- (void)testBackoffForPrimaryHash {
  SNTSyncdQueue *sut = [[SNTSyncdQueue alloc] init];

  // Fill up the cache.
  for (int i = 0; i < 128; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertFalse(backoff);
  }

  // These hashes should now backoff.
  for (int i = 0; i < 128; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertTrue(backoff);
  }

  // Overfill the cache, the cache should now only contain "justonemorebyte".
  XCTAssertFalse([sut backoffForPrimaryHash:@"justonemorebyte"]);
  XCTAssertTrue([sut backoffForPrimaryHash:@"justonemorebyte"]);

  // These hashes should not backoff, remember the cache was just cleared. However, only check 127
  // of the hashes, "justonemorebyte" takes us a slot. Checking the full 128 hashes here would
  // overfill the cache again.
  for (int i = 0; i < 127; ++i) {
    BOOL backoff = [sut backoffForPrimaryHash:[NSString stringWithFormat:@"%d", i]];
    XCTAssertFalse(backoff);
  }

  // Again, these hashes should now backoff.
  for (int i = 0; i < 127; ++i) {
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
  SNTSyncdQueue *sut = [[SNTSyncdQueue alloc] init];
  sut = OCMPartialMock(sut);
  OCMStub([sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add an event, it should be dispatched to the sync service for upload.
  SNTStoredEvent *se = [[SNTStoredEvent alloc] init];
  se.fileSHA256 = @"123";
  [sut addEvents:@[ se ] isFromBundle:false];
  OCMVerify(times(1), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);

  // Add the same event many times, they all should be dropped.
  for (int i = 0; i < 1000; ++i) {
    [sut addEvents:@[ se ] isFromBundle:false];
  }
  OCMVerify(times(1), [sut dispatchBlockOnSyncdQueue:[OCMArg any]]);
}

@end
