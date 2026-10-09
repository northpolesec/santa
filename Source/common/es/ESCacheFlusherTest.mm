/// Copyright 2026 North Pole Security, Inc.
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

#include "Source/common/es/ESCacheFlusher.h"

#include <EndpointSecurity/EndpointSecurity.h>
#import <OSLog/OSLog.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <vector>

#include "Source/common/TestUtils.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/common/es/SNTEndpointSecurityClient.h"

using santa::ESCacheClearStrategy;
using santa::ESCacheFlusher;
using santa::StrategyForVersion;

namespace {

// Each client gets its own mock API so that clears can be attributed to the
// client that performed them.
struct TestClient {
  std::shared_ptr<MockEndpointSecurityAPI> api;
  SNTEndpointSecurityClient* client;
};

TestClient MakeClient() {
  auto api = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient* client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:api
                                               metrics:nullptr
                                             processor:santa::Processor::kUnknown];
  return {api, client};
}

// Expects exactly `times` clears of `tc`, each signaling `sema`.
void ExpectClears(const TestClient& tc, int times, dispatch_semaphore_t sema, bool result = true) {
  EXPECT_CALL(*tc.api, ClearCache).Times(times).WillRepeatedly([sema, result] {
    dispatch_semaphore_signal(sema);
    return result;
  });
}

// Waits for `count` signals, giving up at the first one that does not arrive.
bool WaitForSignals(dispatch_semaphore_t sema, int count) {
  for (int i = 0; i < count; i++) {
    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
      return false;
    }
  }
  return true;
}

NSArray<OSLogEntryLog*>* LogEntriesContaining(NSString* text, NSDate* since) {
  NSError* err;
  OSLogStore* store = [OSLogStore storeWithScope:OSLogStoreCurrentProcessIdentifier error:&err];
  if (!store) {
    return nil;
  }
  OSLogEnumerator* entries =
      [store entriesEnumeratorWithOptions:0
                                 position:[store positionWithDate:since]
                                predicate:[NSPredicate predicateWithFormat:@"subsystem == %@",
                                                                           @SNT_LOG_SUBSYSTEM]
                                    error:&err];
  NSMutableArray<OSLogEntryLog*>* matches = [NSMutableArray array];
  for (OSLogEntry* entry in entries) {
    if ([entry isKindOfClass:[OSLogEntryLog class]] &&
        [entry.composedMessage containsString:text]) {
      [matches addObject:(OSLogEntryLog*)entry];
    }
  }
  return matches;
}

}  // namespace

@interface ESCacheFlusherTest : XCTestCase
@end

@implementation ESCacheFlusherTest

- (void)testStrategyForVersion {
  // The verified major.minor version, its patch releases, and older versions
  XCTAssertEqual(StrategyForVersion({27, 0, 0}), ESCacheClearStrategy::kSingleClient);
  XCTAssertEqual(StrategyForVersion({27, 0, 7}), ESCacheClearStrategy::kSingleClient);
  XCTAssertEqual(StrategyForVersion({26, 9, 0}), ESCacheClearStrategy::kSingleClient);
  XCTAssertEqual(StrategyForVersion({14, 0, 0}), ESCacheClearStrategy::kSingleClient);

  // The next minor and major versions
  XCTAssertEqual(StrategyForVersion({27, 1, 0}), ESCacheClearStrategy::kEveryClient);
  XCTAssertEqual(StrategyForVersion({28, 0, 0}), ESCacheClearStrategy::kEveryClient);
  XCTAssertEqual(StrategyForVersion({28, 0, 1}), ESCacheClearStrategy::kEveryClient);
}

- (void)testEveryClientClearsEachLiveClientOncePerPass {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  dispatch_semaphore_t lastSema = dispatch_semaphore_create(0);

  TestClient a = MakeClient();
  TestClient b = MakeClient();
  TestClient c = MakeClient();
  TestClient unregistered = MakeClient();
  ExpectClears(a, 3, sema);
  ExpectClears(b, 3, sema);
  // The last registered client is cleared last in each pass
  ExpectClears(c, 3, lastSema);
  EXPECT_CALL(*unregistered.api, ClearCache).Times(0);

  flusher->AddClient(a.client);
  flusher->AddClient(b.client);
  flusher->AddClient(c.client);

  // The requester does not change which clients are cleared
  flusher->Flush();
  flusher->Flush(b.client);
  flusher->Flush(unregistered.client);

  XCTAssertTrue(WaitForSignals(lastSema, 3), "Passes did not complete");

  XCTBubbleMockVerifyAndClearExpectations(a.api.get());
  XCTBubbleMockVerifyAndClearExpectations(b.api.get());
  XCTBubbleMockVerifyAndClearExpectations(c.api.get());
  XCTBubbleMockVerifyAndClearExpectations(unregistered.api.get());
}

- (void)testSingleClientClearsOnlyTheLiveRegisteredRequester {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  dispatch_semaphore_t bSema = dispatch_semaphore_create(0);
  dispatch_semaphore_t cSema = dispatch_semaphore_create(0);

  TestClient a = MakeClient();
  TestClient b = MakeClient();
  TestClient c = MakeClient();
  EXPECT_CALL(*a.api, ClearCache).Times(0);
  ExpectClears(b, 1, bSema);
  ExpectClears(c, 1, cSema);

  flusher->AddClient(a.client);
  flusher->AddClient(b.client);
  flusher->AddClient(c.client);

  flusher->Flush(b.client);
  XCTAssertSemaTrue(bSema, 5, "Requester was not cleared");

  // A second pass that clears only c shows the first pass cleared nothing else
  flusher->Flush(c.client);
  XCTAssertSemaTrue(cSema, 5, "Requester was not cleared");

  XCTBubbleMockVerifyAndClearExpectations(a.api.get());
  XCTBubbleMockVerifyAndClearExpectations(b.api.get());
  XCTBubbleMockVerifyAndClearExpectations(c.api.get());
}

- (void)testSingleClientClearsFirstClientWithoutLiveRequester {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  dispatch_semaphore_t aSema = dispatch_semaphore_create(0);
  dispatch_semaphore_t gate = dispatch_semaphore_create(0);

  TestClient a = MakeClient();
  TestClient b = MakeClient();
  EXPECT_CALL(*b.api, ClearCache).Times(0);

  // The first clear of `a` holds the queue until the released requester is gone
  EXPECT_CALL(*a.api, ClearCache)
      .WillOnce([aSema, gate] {
        dispatch_semaphore_wait(gate, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        dispatch_semaphore_signal(aSema);
        return true;
      })
      .WillOnce([aSema] {
        dispatch_semaphore_signal(aSema);
        return true;
      });

  flusher->AddClient(a.client);
  flusher->AddClient(b.client);

  flusher->Flush();

  // A requester released before its pass runs
  @autoreleasepool {
    TestClient transient = MakeClient();
    EXPECT_CALL(*transient.api, ClearCache).Times(0);
    flusher->Flush(transient.client);
  }
  dispatch_semaphore_signal(gate);

  XCTAssertTrue(WaitForSignals(aSema, 2), "First client was not cleared");

  XCTBubbleMockVerifyAndClearExpectations(a.api.get());
  XCTBubbleMockVerifyAndClearExpectations(b.api.get());
}

- (void)testFlushBeforeRegistrationIsNoOp {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  dispatch_semaphore_t lastSema = dispatch_semaphore_create(0);

  // Nothing is registered, so no ES calls are made and nothing is held back
  // for clients that register later.
  flusher->Flush();
  flusher->Flush(nil);

  TestClient a = MakeClient();
  TestClient last = MakeClient();
  ExpectClears(a, 1, sema);
  ExpectClears(last, 1, lastSema);

  // A flush after queued registration sees the registered clients
  flusher->AddClient(a.client);
  flusher->AddClient(last.client);
  flusher->Flush();

  XCTAssertSemaTrue(lastSema, 5, "Pass did not complete");
  XCTAssertSemaTrue(sema, 0, "Registered client was not cleared");

  XCTBubbleMockVerifyAndClearExpectations(a.api.get());
  XCTBubbleMockVerifyAndClearExpectations(last.api.get());
}

- (void)testReleasedClientsAreSkipped {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  dispatch_semaphore_t lastSema = dispatch_semaphore_create(0);

  TestClient released = MakeClient();
  TestClient last = MakeClient();
  EXPECT_CALL(*released.api, ClearCache).Times(0);
  ExpectClears(last, 1, lastSema);

  // Registration does not keep the client alive
  __weak SNTEndpointSecurityClient* weakReleased;
  @autoreleasepool {
    SNTEndpointSecurityClient* client = released.client;
    released.client = nil;
    weakReleased = client;
    flusher->AddClient(client);
  }
  flusher->AddClient(last.client);
  XCTAssertNil(weakReleased);

  flusher->Flush();
  XCTAssertSemaTrue(lastSema, 5, "Pass did not complete");

  XCTBubbleMockVerifyAndClearExpectations(released.api.get());
  XCTBubbleMockVerifyAndClearExpectations(last.api.get());
}

- (void)testConcurrentAddClientAndFlushLoseNoRegistration {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  dispatch_semaphore_t lastSema = dispatch_semaphore_create(0);
  auto inFlight = std::make_shared<std::atomic<int>>(0);
  auto overlapped = std::make_shared<std::atomic<bool>>(false);

  constexpr size_t kNumClients = 32;
  std::vector<TestClient> clients;
  for (size_t i = 0; i < kNumClients; i++) {
    clients.push_back(MakeClient());
    EXPECT_CALL(*clients.back().api, ClearCache)
        .Times(testing::AtLeast(1))
        .WillRepeatedly([inFlight, overlapped] {
          if (inFlight->fetch_add(1) != 0) {
            overlapped->store(true);
          }
          inFlight->fetch_sub(1);
          return true;
        });
  }

  dispatch_apply(kNumClients * 2, DISPATCH_APPLY_AUTO, ^(size_t i) {
    if (i % 2 == 0) {
      flusher->AddClient(clients[i / 2].client);
    } else {
      flusher->Flush();
    }
  });

  // Registered after every earlier request is queued, so this client is only
  // cleared by the final pass, after every other client.
  TestClient last = MakeClient();
  ExpectClears(last, 1, lastSema);
  flusher->AddClient(last.client);
  flusher->Flush();

  XCTAssertSemaTrue(lastSema, 5, "Final pass did not complete");
  XCTAssertFalse(overlapped->load());

  for (const TestClient& tc : clients) {
    XCTBubbleMockVerifyAndClearExpectations(tc.api.get());
  }
  XCTBubbleMockVerifyAndClearExpectations(last.api.get());
}

- (void)testConcurrentFlushesNeverOverlap {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  auto inFlight = std::make_shared<std::atomic<int>>(0);
  auto overlapped = std::make_shared<std::atomic<bool>>(false);
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  constexpr int kNumFlushes = 64;
  std::vector<TestClient> clients;
  for (int i = 0; i < 3; i++) {
    clients.push_back(MakeClient());
    EXPECT_CALL(*clients.back().api, ClearCache)
        .Times(kNumFlushes)
        .WillRepeatedly([inFlight, overlapped, sema] {
          if (inFlight->fetch_add(1) != 0) {
            overlapped->store(true);
          }
          inFlight->fetch_sub(1);
          dispatch_semaphore_signal(sema);
          return true;
        });
    flusher->AddClient(clients.back().client);
  }

  dispatch_apply(kNumFlushes, DISPATCH_APPLY_AUTO, ^(size_t) {
    flusher->Flush();
  });

  XCTAssertTrue(WaitForSignals(sema, kNumFlushes * 3), "Passes did not complete");
  XCTAssertFalse(overlapped->load());

  for (const TestClient& tc : clients) {
    XCTBubbleMockVerifyAndClearExpectations(tc.api.get());
  }
}

- (void)testFlushReturnsBeforeESWorkCompletes {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  dispatch_semaphore_t gate = dispatch_semaphore_create(0);
  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  auto gateOpened = std::make_shared<std::atomic<bool>>(false);

  TestClient a = MakeClient();
  EXPECT_CALL(*a.api, ClearCache).WillOnce([gate, done, gateOpened] {
    // The gate only opens after Flush returns. A synchronous Flush would block
    // here until the wait times out.
    gateOpened->store(
        dispatch_semaphore_wait(gate, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
    dispatch_semaphore_signal(done);
    return true;
  });

  flusher->AddClient(a.client);
  flusher->Flush();
  dispatch_semaphore_signal(gate);

  XCTAssertSemaTrue(done, 10, "Pass did not complete");
  XCTAssertTrue(gateOpened->load());

  XCTBubbleMockVerifyAndClearExpectations(a.api.get());
}

- (void)testFailuresAreLoggedOnceAndDoNotStopRemainingClears {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  dispatch_semaphore_t lastSema = dispatch_semaphore_create(0);
  NSDate* start = [NSDate date];

  TestClient failsFirst = MakeClient();
  TestClient failsSecond = MakeClient();
  TestClient succeeds = MakeClient();
  // Exactly one attempt each: failures are not retried, and earlier failures
  // do not prevent clearing the remaining clients. The succeeding client is
  // cleared last, so its signal follows both failures being logged.
  ExpectClears(failsFirst, 1, sema, false);
  ExpectClears(failsSecond, 1, sema, false);
  ExpectClears(succeeds, 1, lastSema);

  flusher->AddClient(failsFirst.client);
  flusher->AddClient(failsSecond.client);
  flusher->AddClient(succeeds.client);
  flusher->Flush();

  XCTAssertSemaTrue(lastSema, 5, "Pass did not complete");
  XCTAssertSemaTrue(sema, 0, "Client was not cleared");
  XCTAssertSemaTrue(sema, 0, "Client was not cleared");

  for (SNTEndpointSecurityClient* failed in @[ failsFirst.client, failsSecond.client ]) {
    NSArray<OSLogEntryLog*>* logs = LogEntriesContaining([failed description], start);
    XCTAssertEqual(logs.count, 1);
    XCTAssertEqual(logs.firstObject.level, OSLogEntryLogLevelError);
  }
  XCTAssertEqual(LogEntriesContaining([succeeds.client description], start).count, 0);

  XCTBubbleMockVerifyAndClearExpectations(failsFirst.api.get());
  XCTBubbleMockVerifyAndClearExpectations(succeeds.api.get());
  XCTBubbleMockVerifyAndClearExpectations(failsSecond.api.get());
}

@end
