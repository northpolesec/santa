/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <time.h>

#include <memory>
#include <vector>

#include <mach/machine.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/ESCacheFlusher.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/common/es/SNTEndpointSecurityClient.h"
#include "Source/santad/EventProviders/AuthResultCache.h"

using santa::AuthResultCache;
using santa::ESCacheClearStrategy;
using santa::ESCacheFlusher;
using santa::FlushCacheMode;
using santa::FlushCacheReason;

namespace santa {
extern NSString* const FlushCacheReasonToString(FlushCacheReason reason);
}  // namespace santa

using santa::FlushCacheReasonToString;

// Grab the st_dev number of the root volume to match the root cache
static uint64_t RootDevno() {
  static dispatch_once_t once_token;
  static uint64_t devno;
  dispatch_once(&once_token, ^{
    struct stat sb;
    stat("/", &sb);
    devno = sb.st_dev;
  });
  return devno;
}

static inline santa::ExecTarget MakeTarget(uint64_t devno, uint64_t ino,
                                           cpu_type_t cputype = CPU_TYPE_ARM64,
                                           uint8_t cdhashByte = 0xAA, time_t identTime = 100) {
  santa::ExecTarget t{};
  t.key.vnode = SantaVnode{.fsid = (dev_t)devno, .fileid = ino};
  t.key.cputype = cputype;
  t.key.cpusubtype = 0;
  t.identity.cdhash.fill(cdhashByte);
  t.identity.mtime = t.identity.ctime = t.identity.btime = {.tv_sec = identTime, .tv_nsec = 0};
  t.identity.size = 1000;
  return t;
}

static inline void AssertCacheCounts(std::shared_ptr<AuthResultCache> cache, uint64_t root_count,
                                     uint64_t nonroot_count) {
  NSArray<NSNumber*>* counts = cache->CacheCounts();

  XCTAssertNotNil(counts);
  XCTAssertEqual([counts count], 2);
  XCTAssertNotNil(counts[0]);
  XCTAssertNotNil(counts[1]);
  XCTAssertEqual([counts[0] unsignedLongLongValue], root_count);
  XCTAssertEqual([counts[1] unsignedLongLongValue], nonroot_count);
}

@interface AuthResultCacheTest : XCTestCase
@end

@implementation AuthResultCacheTest

- (void)testEmptyCacheExpectedNumberOfCacheCounts {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  AssertCacheCounts(cache, 0, 0);
}

- (void)testBasicOperation {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);
  santa::ExecTarget nonrootTarget = MakeTarget(RootDevno() + 123, 222);

  // Add the root file to the cache
  uint64_t rootToken = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(rootToken, 0);

  AssertCacheCounts(cache, 1, 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);
  XCTAssertEqual(cache->CheckCache(nonrootTarget).action, SNTActionUnset);

  // Now add the non-root file
  uint64_t nonrootToken = cache->Reserve(nonrootTarget, {});
  XCTAssertNotEqual(nonrootToken, 0);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);
  XCTAssertEqual(cache->CheckCache(nonrootTarget).action, SNTActionRequestBinary);

  // Update the cached values
  cache->AddToCache(rootTarget, SNTActionRespondAllow, nil, rootToken);
  cache->AddToCache(nonrootTarget, SNTActionRespondDeny, nil, nonrootToken);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCacheForVnode(rootTarget.key.vnode).action, SNTActionRespondAllow);
  XCTAssertEqual(cache->CheckCacheForVnode(nonrootTarget.key.vnode).action, SNTActionRespondDeny);
}

- (void)testDenyOnceLeavesNoEntry {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  // A long deny interval so that a retained deny could not expire on its own
  // during the test.
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil, 600000);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  // Like the other terminal actions, this one is only reachable from the
  // in-flight state.
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondDenyOnce, nil, 0));

  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondDenyOnce, nil, r));

  // No entry at all, so the result cannot reach a later execution of this vnode
  // and does not depend on elapsed time.
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

- (void)testDenyIsStillRetained {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil, 600000);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondDeny, nil, r));

  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondDeny);
  AssertCacheCounts(cache, 1, 0);
}

- (void)testFlushCache {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  auto clientAPI = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient* client =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:clientAPI
                                               metrics:nullptr
                                             processor:santa::Processor::kUnknown];
  auto lastAPI = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient* lastClient =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:lastAPI
                                               metrics:nullptr
                                             processor:santa::Processor::kUnknown];

  // Only the full flush requests central invalidation
  EXPECT_CALL(*clientAPI, ClearCache).WillOnce(testing::Return(true));
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*lastAPI, ClearCache).WillOnce([sema] {
    dispatch_semaphore_signal(sema);
    return true;
  });

  flusher->AddClient(client);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);
  santa::ExecTarget nonrootTarget = MakeTarget(RootDevno() + 123, 111);

  XCTAssertNotEqual(cache->Reserve(rootTarget, {}), 0);
  XCTAssertNotEqual(cache->Reserve(nonrootTarget, {}), 0);

  AssertCacheCounts(cache, 1, 1);

  // Flush non-root only
  cache->FlushCache(FlushCacheMode::kNonRootOnly, FlushCacheReason::kClientModeChanged);

  AssertCacheCounts(cache, 1, 0);

  // Add back the non-root file
  XCTAssertNotEqual(cache->Reserve(nonrootTarget, {}), 0);

  AssertCacheCounts(cache, 1, 1);

  // Registered after the non-root flush and cleared last, so once it is cleared
  // any invalidation requested by the non-root flush has also run.
  flusher->AddClient(lastClient);

  // Flush all caches. Local caches clear synchronously, and the ES caches are
  // invalidated asynchronously.
  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kClientModeChanged);

  AssertCacheCounts(cache, 0, 0);

  XCTAssertSemaTrue(sema, 5, "ClearCache wasn't called within expected time window");

  XCTBubbleMockVerifyAndClearExpectations(clientAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(lastAPI.get());
}

- (void)testCacheStateMachine {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  // Cached items must first be in the SNTActionRequestBinary state
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllow, nil, 1));
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllowCompiler, nil, 1));
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondDeny, nil, 1));
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondHold, nil, 1));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);

  XCTAssertNotEqual(cache->Reserve(rootTarget, {}), 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

  // Items in the `SNTActionRequestBinary` state cannot reenter the same state
  XCTAssertEqual(cache->Reserve(rootTarget, {}), 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

  std::vector<SNTAction> allowedTransitions = {
      SNTActionRespondAllow,
      SNTActionRespondAllowCompiler,
      SNTActionRespondDeny,
      SNTActionRespondAllowNoCache,
  };

  for (const SNTAction transition : allowedTransitions) {
    // First make sure the item doesn't exist
    cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kExplicitCommand);
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);

    // Now add the item to be in the first allowed state
    uint64_t r = cache->Reserve(rootTarget, {});
    XCTAssertNotEqual(r, 0);
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

    // Now assert the allowed transition
    XCTAssertTrue(cache->AddToCache(rootTarget, transition, nil, r));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, transition);
  }

  allowedTransitions = {
      SNTActionHoldAllowed,
      SNTActionHoldDenied,
  };

  // Check hold-related states
  for (const SNTAction transition : allowedTransitions) {
    // First make sure the item doesn't exist and move into the starting state
    cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kExplicitCommand);
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
    uint64_t r = cache->Reserve(rootTarget, {});
    XCTAssertNotEqual(r, 0);
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

    // Check the item can transition to the new hold state
    XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondHold, nil, r));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);

    // Now assert the allowed transition returns YES and that the cache entry is removed.
    XCTAssertTrue(cache->AddToCache(rootTarget, transition, nil, r));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  }

  // Ensure improper transitions from the hold state are disallowed
  // First, get into the hold state
  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kExplicitCommand);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondHold, nil, r));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);

  // Ensure all the following state transition attempts fail
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondHold, nil, r));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllow, nil, r));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllowCompiler, nil, r));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondDeny, nil, r));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllowNoCache, nil, r));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertEqual(cache->Reserve(rootTarget, {}), 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
}

- (void)testAllowNoCacheWithDecision {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"abc123";
  cd.certSHA256 = @"cert456";

  // SNTActionRespondAllowNoCache transitions from RequestBinary
  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondAllowNoCache, cd, r));

  // CheckCache returns AllowNoCache with the cached decision
  santa::CachedAuthResult entry = cache->CheckCache(rootTarget);
  XCTAssertEqual(entry.action, SNTActionRespondAllowNoCache);
  XCTAssertNotNil(entry.cached_decision);
  XCTAssertEqualObjects(entry.cached_decision.sha256, @"abc123");
  XCTAssertEqualObjects(entry.cached_decision.certSHA256, @"cert456");

  // FlushCache clears decisions
  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);
  XCTAssertNil(cache->CheckCache(rootTarget).cached_decision);
}

// A transitive hold keeps its decision, so a concurrent execution can tell what
// the hold is waiting for. Any other hold keeps none.
- (void)testHoldKeepsOnlyATransitiveHoldsDecision {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.heldForTransitiveRule = YES;
  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondHold, cd, r));
  santa::CachedAuthResult entry = cache->CheckCache(rootTarget);
  XCTAssertEqual(entry.action, SNTActionRespondHold);
  XCTAssertTrue(entry.cached_decision.heldForTransitiveRule);

  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionHoldDenied, nil, r));
  cd.heldForTransitiveRule = NO;
  r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondHold, cd, r));
  entry = cache->CheckCache(rootTarget);
  XCTAssertEqual(entry.action, SNTActionRespondHold);
  XCTAssertNil(entry.cached_decision);
}

- (void)testCompilerNoCacheIsNarrowedAndNeverTerminal {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 222);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"deadbeef";
  cd.certSHA256 = @"cert789";

  // Transitions out of RequestBinary exactly like SNTActionRespondAllowNoCache.
  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondAllowCompilerNoCache, cd, r));

  santa::CachedAuthResult entry = cache->CheckCache(rootTarget);

  // The compiler grant applied to the process that was just authorized, not to
  // this vnode, so it must not be observable from the cache at all.
  XCTAssertNotEqual(entry.action, SNTActionRespondAllowCompilerNoCache);
  XCTAssertEqual(entry.action, SNTActionRespondAllowNoCache);

  // The stored entry must never be a terminal (reusable) result: policy has to
  // run again on the next execution of this vnode.
  XCTAssertFalse(RESPONSE_VALID(entry.action));

  // Identity data is retained so the next execution can skip re-hashing while
  // still re-running policy.
  XCTAssertNotNil(entry.cached_decision);
  XCTAssertEqualObjects(entry.cached_decision.sha256, @"deadbeef");
  XCTAssertEqualObjects(entry.cached_decision.certSHA256, @"cert789");
}

- (void)testCacheExpiry {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  // Create a cache with a lowered cache expiry value
  uint64_t expiryMS = 250;
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil, expiryMS);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  // Add a file to the cache and put into the SNTActionRespondDeny state
  uint64_t r = cache->Reserve(rootTarget, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondDeny, nil, r));

  // Ensure the file exists
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondDeny);

  // Wait for the item to expire
  SleepMS(expiryMS);

  // Check cache counts to make sure the item still exists
  AssertCacheCounts(cache, 1, 0);

  // Now check the cache, which will remove the item
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

- (void)testSlicesAreIndependentEntries {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget arm = MakeTarget(RootDevno(), 111, CPU_TYPE_ARM64);
  santa::ExecTarget x86 = MakeTarget(RootDevno(), 111, CPU_TYPE_X86_64);

  uint64_t armToken = cache->Reserve(arm, {});
  cache->AddToCache(arm, SNTActionRespondAllow, nil, armToken);
  XCTAssertEqual(cache->CheckCache(arm).action, SNTActionRespondAllow);
  // The other slice of the same vnode is a distinct state machine.
  XCTAssertEqual(cache->CheckCache(x86).action, SNTActionUnset);

  uint64_t x86Token = cache->Reserve(x86, {});
  cache->AddToCache(x86, SNTActionRespondDeny, nil, x86Token);
  XCTAssertEqual(cache->CheckCache(x86).action, SNTActionRespondDeny);
  XCTAssertEqual(cache->CheckCache(arm).action, SNTActionRespondAllow);
}

- (void)testCheckCacheForVnodeFindsAnySlice {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget arm = MakeTarget(RootDevno(), 222, CPU_TYPE_ARM64);
  uint64_t r = cache->Reserve(arm, {});
  cache->AddToCache(arm, SNTActionRespondAllow, nil, r);

  XCTAssertEqual(cache->CheckCacheForVnode(arm.key.vnode).action, SNTActionRespondAllow);
  XCTAssertEqual(
      cache->CheckCacheForVnode(SantaVnode{.fsid = (dev_t)RootDevno(), .fileid = 999}).action,
      SNTActionUnset);
}

// Pins the storage half of identity verification: each `set` arm in AddToCache
// must carry the target's identity into the stored value.
- (void)testIdentityIsStoredByEveryTransition {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 111, CPU_TYPE_ARM64, 0xBB, 4242);

  std::vector<SNTAction> transitions = {
      SNTActionRespondAllow, SNTActionRespondAllowCompiler, SNTActionRespondDeny,
      SNTActionRespondHold,  SNTActionRespondAllowNoCache,  SNTActionRespondAllowCompilerNoCache,
  };

  for (const SNTAction transition : transitions) {
    cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kExplicitCommand);

    uint64_t r = cache->Reserve(target, {});
    XCTAssertNotEqual(r, 0);
    XCTAssertTrue(cache->CheckCache(target).identity == target.identity,
                  @"RequestBinary entry must carry the target's identity");

    XCTAssertTrue(cache->AddToCache(target, transition, nil, r));
    XCTAssertTrue(cache->CheckCache(target).identity == target.identity,
                  @"entry stored for action %ld must carry the target's identity", transition);
  }
}

- (void)testReservationTokensAreUnique {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);
  santa::ExecTarget nonrootTarget = MakeTarget(RootDevno() + 123, 111);

  uint64_t rootToken = cache->Reserve(rootTarget, {});
  uint64_t nonrootToken = cache->Reserve(nonrootTarget, {});
  XCTAssertNotEqual(rootToken, 0);
  XCTAssertNotEqual(nonrootToken, 0);
  XCTAssertNotEqual(rootToken, nonrootToken);

  // An occupied slot is not reserved again.
  XCTAssertEqual(cache->Reserve(rootTarget, {}), 0);
  XCTAssertEqual(cache->Reserve(nonrootTarget, {}), 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).timestamp, rootToken);
}

- (void)testUnreservedDenyLeavesAnotherExecsMarker {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333);
  uint64_t r = cache->Reserve(a, {});
  XCTAssertNotEqual(r, 0);

  XCTAssertFalse(cache->AddToCache(a, SNTActionRespondDeny, nil, 0));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRequestBinary);

  XCTAssertTrue(cache->AddToCache(a, SNTActionRespondDeny, nil, r));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRespondDeny);
}

- (void)testPublishRequiresTheCurrentReservation {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333);
  uint64_t r1 = cache->Reserve(a, {});
  XCTAssertNotEqual(r1, 0);

  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);

  uint64_t r2 = cache->Reserve(a, {});
  XCTAssertNotEqual(r2, 0);
  XCTAssertNotEqual(r2, r1);

  XCTAssertFalse(cache->AddToCache(a, SNTActionRespondAllow, nil, r1));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRequestBinary);
  XCTAssertTrue(cache->AddToCache(a, SNTActionRespondAllow, nil, r2));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRespondAllow);
}

- (void)testReplantedMarkerBlocksTheOriginalPublish {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333, CPU_TYPE_ARM64, 0x11, 100);
  santa::ExecTarget aPrime = MakeTarget(RootDevno(), 333, CPU_TYPE_ARM64, 0x22, 200);
  XCTAssertTrue(a.key == aPrime.key);
  XCTAssertFalse(a.identity == aPrime.identity);

  uint64_t ra = cache->Reserve(a, {});
  XCTAssertNotEqual(ra, 0);

  // The differing identity evicts a's marker, which aPrime then re-plants.
  XCTAssertEqual(cache->CheckCache(aPrime).action, SNTActionUnset);
  uint64_t rb = cache->Reserve(aPrime, {});
  XCTAssertNotEqual(rb, 0);

  XCTAssertFalse(cache->AddToCache(a, SNTActionRespondAllow, nil, ra));
  XCTAssertEqual(cache->CheckCache(aPrime).action, SNTActionRequestBinary);
}

- (void)testHoldAndDenyOnceRequireTheReservation {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333);
  uint64_t r = cache->Reserve(a, {});
  XCTAssertNotEqual(r, 0);

  XCTAssertFalse(cache->AddToCache(a, SNTActionRespondHold, nil, r + 1));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRequestBinary);
  XCTAssertFalse(cache->AddToCache(a, SNTActionRespondDenyOnce, nil, r + 1));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRequestBinary);

  XCTAssertTrue(cache->AddToCache(a, SNTActionRespondDenyOnce, nil, r));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionUnset);
}

- (void)testHoldExitRequiresTheReservation {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333);
  uint64_t r = cache->Reserve(a, {});
  XCTAssertTrue(cache->AddToCache(a, SNTActionRespondHold, nil, r));
  XCTAssertEqual(cache->CheckCache(a).timestamp, r);

  XCTAssertFalse(cache->AddToCache(a, SNTActionHoldAllowed, nil, r + 1));
  XCTAssertFalse(cache->AddToCache(a, SNTActionHoldDenied, nil, r + 1));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionRespondHold);

  XCTAssertTrue(cache->AddToCache(a, SNTActionHoldDenied, nil, r));
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionUnset);
}

- (void)testStaleHoldExitLeavesTheCurrentReservation {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333);
  uint64_t r1 = cache->Reserve(a, {});
  XCTAssertTrue(cache->AddToCache(a, SNTActionRespondHold, nil, r1));

  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);
  uint64_t r2 = cache->Reserve(a, {});
  XCTAssertNotEqual(r2, 0);

  XCTAssertFalse(cache->AddToCache(a, SNTActionHoldAllowed, nil, r1));
  santa::CachedAuthResult entry = cache->CheckCache(a);
  XCTAssertEqual(entry.action, SNTActionRequestBinary);
  XCTAssertEqual(entry.timestamp, r2);
}

- (void)testReserveReplacesOnlyTheExpectedEntry {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333);
  uint64_t r1 = cache->Reserve(a, {});
  XCTAssertTrue(cache->AddToCache(a, SNTActionRespondAllowNoCache, nil, r1));
  santa::CachedAuthResult noCache = cache->CheckCache(a);
  XCTAssertEqual(noCache.action, SNTActionRespondAllowNoCache);

  // An occupied slot is not taken as empty.
  XCTAssertEqual(cache->Reserve(a, {}), 0);

  uint64_t r2 = cache->Reserve(a, noCache);
  XCTAssertNotEqual(r2, 0);
  santa::CachedAuthResult entry = cache->CheckCache(a);
  XCTAssertEqual(entry.action, SNTActionRequestBinary);
  XCTAssertEqual(entry.timestamp, r2);

  // The entry has been replaced, so a second Reserve over it fails.
  XCTAssertEqual(cache->Reserve(a, noCache), 0);
  XCTAssertEqual(cache->CheckCache(a).timestamp, r2);
}

- (void)testIdentityMismatchIsMissAndRemoves {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 333);
  uint64_t r = cache->Reserve(original, {});
  cache->AddToCache(original, SNTActionRespondAllow, nil, r);
  XCTAssertEqual(cache->CheckCache(original).action, SNTActionRespondAllow);

  // Same key, different ctime: simulates recycled/overwritten content.
  santa::ExecTarget recycled = original;
  recycled.identity.ctime.tv_sec += 1;
  XCTAssertEqual(cache->CheckCache(recycled).action, SNTActionUnset);
  // The stale entry was removed, so even the original identity now misses.
  XCTAssertEqual(cache->CheckCache(original).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

- (void)testCdhashMismatchIsMiss {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 444, CPU_TYPE_ARM64, 0xAA);
  uint64_t r = cache->Reserve(original, {});
  cache->AddToCache(original, SNTActionRespondAllow, nil, r);

  santa::ExecTarget forged = MakeTarget(RootDevno(), 444, CPU_TYPE_ARM64, 0xBB);
  XCTAssertEqual(cache->CheckCache(forged).action, SNTActionUnset);
}

- (void)testSizeMismatchIsMiss {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 666);
  uint64_t r = cache->Reserve(original, {});
  cache->AddToCache(original, SNTActionRespondAllow, nil, r);

  santa::ExecTarget resized = original;
  resized.identity.size += 1;
  XCTAssertEqual(cache->CheckCache(resized).action, SNTActionUnset);
}

- (void)testIdentityMismatchOnInFlightMarkerRemovesIt {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 555);
  uint64_t r = cache->Reserve(original, {});

  santa::ExecTarget replaced = original;
  replaced.identity.ctime.tv_nsec += 1;
  // Content changed under an in-flight marker: marker is dead, treat as miss.
  XCTAssertEqual(cache->CheckCache(replaced).action, SNTActionUnset);

  // The original exec's terminal CAS (previous == its reserved marker) must now
  // fail: its result must NOT be cached after the marker was invalidated.
  cache->AddToCache(original, SNTActionRespondAllow, nil, r);
  XCTAssertEqual(cache->CheckCache(original).action, SNTActionUnset);
}

// Verification is uniform across cached states: a mismatch under a hold marker
// means the hold refers to content that no longer exists. Uniformity is
// structural today (the check sits above every state-specific branch); this
// guards a future reordering.
- (void)testIdentityMismatchUnderHoldIsMissAndRemoves {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 777);
  uint64_t r = cache->Reserve(original, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(original, SNTActionRespondHold, nil, r));
  XCTAssertEqual(cache->CheckCache(original).action, SNTActionRespondHold);

  santa::ExecTarget replaced = original;
  replaced.identity.mtime.tv_sec += 1;
  XCTAssertEqual(cache->CheckCache(replaced).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

// Deny is the one state where verification preempts an existing branch: it runs
// before the deny-expiry logic. A mismatched deny is a miss regardless of its
// TTL, so a deny cached for old content is never attributed to new content.
- (void)testIdentityMismatchUnderDenyPreemptsExpiry {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  // A long deny TTL: the entry is nowhere near expiry, so a miss here can only
  // come from identity verification running ahead of the expiry check.
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil, 600000);

  santa::ExecTarget original = MakeTarget(RootDevno(), 888);
  uint64_t r = cache->Reserve(original, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(original, SNTActionRespondDeny, nil, r));
  XCTAssertEqual(cache->CheckCache(original).action, SNTActionRespondDeny);

  santa::ExecTarget replaced = original;
  replaced.identity.btime.tv_sec += 1;
  XCTAssertEqual(cache->CheckCache(replaced).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

- (void)testFlushCacheReasonToString {
  std::map<FlushCacheReason, NSString*> reasonToString = {
      {FlushCacheReason::kClientModeChanged, @"ClientModeChanged"},
      {FlushCacheReason::kPathRegexChanged, @"PathRegexChanged"},
      {FlushCacheReason::kRulesChanged, @"RulesChanged"},
      {FlushCacheReason::kStaticRulesChanged, @"StaticRulesChanged"},
      {FlushCacheReason::kExplicitCommand, @"ExplicitCommand"},
      {FlushCacheReason::kFilesystemUnmounted, @"FilesystemUnmounted"},
      {FlushCacheReason::kEntitlementsPrefixFilterChanged, @"EntitlementsPrefixFilterChanged"},
      {FlushCacheReason::kEntitlementsTeamIDFilterChanged, @"EntitlementsTeamIDFilterChanged"},
      {FlushCacheReason::kCELFallbackRulesChanged, @"CELFallbackRulesChanged"},
      {FlushCacheReason::kTransitiveRulesChanged, @"TransitiveRulesChanged"},
  };

  for (const auto& kv : reasonToString) {
    XCTAssertEqualObjects(FlushCacheReasonToString(kv.first), kv.second);
  }

  XCTAssertThrows(FlushCacheReasonToString(
      (FlushCacheReason)(static_cast<int>(FlushCacheReason::kTransitiveRulesChanged) + 1)));
}

- (void)testExecTargetForExecEvent {
  es_file_t procFile = MakeESFile("instigator");
  struct stat sb = MakeStat();
  sb.st_dev = 42;
  sb.st_ino = 4242;
  sb.st_mtimespec = {.tv_sec = 100, .tv_nsec = 1};
  sb.st_ctimespec = {.tv_sec = 200, .tv_nsec = 2};
  sb.st_birthtimespec = {.tv_sec = 300, .tv_nsec = 3};
  sb.st_size = 12345;
  es_file_t targetFile = MakeESFile("target", sb);
  es_process_t proc = MakeESProcess(&procFile);
  es_process_t targetProc = MakeESProcess(&targetFile);
  memset(targetProc.cdhash, 0xAB, CS_CDHASH_LEN);
  targetProc.codesigning_flags = CS_SIGNED | CS_VALID | CS_KILL;
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &proc);
  esMsg.event.exec.target = &targetProc;
  esMsg.event.exec.image_cputype = CPU_TYPE_ARM64;
  // Capability bits must be masked off the stored subtype.
  esMsg.event.exec.image_cpusubtype = (cpu_subtype_t)(CPU_SUBTYPE_ARM64E | 0x80000000);

  santa::ExecTarget t = santa::ExecTarget::ForExecEvent(&esMsg);

  XCTAssertEqual(t.key.vnode.fsid, 42);
  XCTAssertEqual(t.key.vnode.fileid, 4242);
  XCTAssertEqual(t.key.cputype, CPU_TYPE_ARM64);
  XCTAssertEqual(t.key.cpusubtype, (cpu_subtype_t)(CPU_SUBTYPE_ARM64E));
  XCTAssertEqual(memcmp(t.identity.cdhash.data(), targetProc.cdhash, CS_CDHASH_LEN), 0);
  XCTAssertEqual(t.identity.ctime.tv_sec, 200);
  XCTAssertEqual(t.identity.ctime.tv_nsec, 2);
  XCTAssertEqual(t.identity.btime.tv_sec, 300);
  XCTAssertEqual(t.identity.size, 12345);
  XCTAssertTrue(t.enforced);
}

- (void)testExecIdentityEquality {
  santa::ExecIdentity a{};
  a.cdhash.fill(0x11);
  a.mtime = a.ctime = a.btime = {.tv_sec = 5, .tv_nsec = 6};
  santa::ExecIdentity b = a;
  XCTAssertTrue(a == b);
  b.ctime.tv_nsec = 7;
  XCTAssertFalse(a == b);
  b = a;
  b.cdhash[0] = 0x22;
  XCTAssertFalse(a == b);
  b = a;
  b.size = 1;
  XCTAssertFalse(a == b);
}

- (void)testUnconfirmedDecisionIsNotStoredForReuse {
  // The SNTCachedDecision from a no-cache allow is kept so the next execution
  // can skip recomputing it -- unless its identity was never confirmed.
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 456);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"unconfirmed-hash";
  cd.identityMismatched = YES;

  uint64_t r = cache->Reserve(target, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(target, SNTActionRespondAllowNoCache, cd, r));

  // The entry itself is kept, and the ExecTarget's own identity is still stored
  // so the hit above verifies. Only the decision is dropped.
  santa::CachedAuthResult entry = cache->CheckCache(target);
  XCTAssertEqual(entry.action, SNTActionRespondAllowNoCache);
  XCTAssertNil(entry.cached_decision);
}

- (void)testConfirmedDecisionIsStillStoredForReuse {
  // Regression guard for the above: a confirmed decision must still be kept.
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 457);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"confirmed-hash";

  uint64_t r = cache->Reserve(target, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(target, SNTActionRespondAllowNoCache, cd, r));

  santa::CachedAuthResult entry = cache->CheckCache(target);
  XCTAssertEqualObjects(entry.cached_decision.sha256, @"confirmed-hash");
}

- (void)testAllowStoresConfirmedSHA256 {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  for (SNTAction action : {SNTActionRespondAllow, SNTActionRespondAllowCompiler}) {
    santa::ExecTarget target = MakeTarget(RootDevno(), 460 + action);
    SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
    cd.sha256 = @"aa";

    uint64_t r = cache->Reserve(target, {});
    XCTAssertNotEqual(r, 0);
    XCTAssertTrue(cache->AddToCache(target, action, cd, r));
    XCTAssertEqualObjects(cache->CheckCache(target).sha256, @"aa");
  }
}

- (void)testUnconfirmedAllowStoresNoSHA256 {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget mismatched = MakeTarget(RootDevno(), 470);
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aa";
  cd.identityMismatched = YES;
  uint64_t r = cache->Reserve(mismatched, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(mismatched, SNTActionRespondAllow, cd, r));
  XCTAssertEqual(cache->CheckCache(mismatched).action, SNTActionRespondAllow);
  XCTAssertNil(cache->CheckCache(mismatched).sha256);

  santa::ExecTarget noDecision = MakeTarget(RootDevno(), 471);
  r = cache->Reserve(noDecision, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(noDecision, SNTActionRespondAllow, nil, r));
  XCTAssertEqual(cache->CheckCache(noDecision).action, SNTActionRespondAllow);
  XCTAssertNil(cache->CheckCache(noDecision).sha256);
}

- (void)testDenyStoresNoSHA256 {
  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kEveryClient);
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(flusher, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 480);
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"aa";
  uint64_t r = cache->Reserve(target, {});
  XCTAssertNotEqual(r, 0);
  XCTAssertTrue(cache->AddToCache(target, SNTActionRespondDeny, cd, r));
  XCTAssertEqual(cache->CheckCache(target).action, SNTActionRespondDeny);
  XCTAssertNil(cache->CheckCache(target).sha256);
}

@end
