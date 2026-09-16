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
#import <OCMock/OCMock.h>
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
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/common/es/SNTEndpointSecurityClientBase.h"
#include "Source/santad/EventProviders/AuthResultCache.h"

using santa::AuthResultCache;
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
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  AssertCacheCounts(cache, 0, 0);
}

- (void)testBasicOperation {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);
  santa::ExecTarget nonrootTarget = MakeTarget(RootDevno() + 123, 222);

  // Add the root file to the cache
  cache->AddToCache(rootTarget, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 0);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);
  XCTAssertEqual(cache->CheckCache(nonrootTarget).action, SNTActionUnset);

  // Now add the non-root file
  cache->AddToCache(nonrootTarget, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);
  XCTAssertEqual(cache->CheckCache(nonrootTarget).action, SNTActionRequestBinary);

  // Update the cached values
  cache->AddToCache(rootTarget, SNTActionRespondAllow);
  cache->AddToCache(nonrootTarget, SNTActionRespondDeny);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCacheForVnode(rootTarget.key.vnode).action, SNTActionRespondAllow);
  XCTAssertEqual(cache->CheckCacheForVnode(nonrootTarget.key.vnode).action, SNTActionRespondDeny);

  // Remove the root file
  cache->RemoveFromCache(rootTarget);

  AssertCacheCounts(cache, 0, 1);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  XCTAssertEqual(cache->CheckCache(nonrootTarget).action, SNTActionRespondDeny);
}

- (void)testDenyOnceLeavesNoEntry {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  // A long deny interval so that a retained deny could not expire on its own
  // during the test.
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil, 600000);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  // Like the other terminal actions, this one is only reachable from the
  // in-flight state.
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondDenyOnce));

  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondDenyOnce));

  // No entry at all, so the result cannot reach a later execution of this vnode
  // and does not depend on elapsed time.
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

- (void)testDenyIsStillRetained {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil, 600000);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondDeny));

  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondDeny);
  AssertCacheCounts(cache, 1, 0);
}

- (void)testFlushCache {
  id<SNTEndpointSecurityClientBase> client =
      OCMProtocolMock(@protocol(SNTEndpointSecurityClientBase));

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil);
  cache->SetESClient(client);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);
  santa::ExecTarget nonrootTarget = MakeTarget(RootDevno() + 123, 111);

  cache->AddToCache(rootTarget, SNTActionRequestBinary);
  cache->AddToCache(nonrootTarget, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 1);

  // Flush non-root only
  cache->FlushCache(FlushCacheMode::kNonRootOnly, FlushCacheReason::kClientModeChanged);

  AssertCacheCounts(cache, 1, 0);

  // Add back the non-root file
  cache->AddToCache(nonrootTarget, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 1);

  // Flush all caches
  // The call to ClearCache is asynchronous. Use a semaphore to
  // be notified when the mock is called.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  OCMStub([client clearCache])
      .andDo(^(NSInvocation* invocation) {
        dispatch_semaphore_signal(sema);
      })
      .andReturn(true);

  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kClientModeChanged);

  XCTAssertEqual(0,
                 dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)),
                 "ClearCache wasn't called within expected time window");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());

  AssertCacheCounts(cache, 0, 0);
}

- (void)testCacheStateMachine {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  // Cached items must first be in the SNTActionRequestBinary state
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllow));
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllowCompiler));
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondDeny));
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondHold));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);

  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

  // Items in the `SNTActionRequestBinary` state cannot reenter the same state
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

  std::vector<SNTAction> allowedTransitions = {
      SNTActionRespondAllow,
      SNTActionRespondAllowCompiler,
      SNTActionRespondDeny,
      SNTActionRespondAllowNoCache,
  };

  for (const SNTAction transition : allowedTransitions) {
    // First make sure the item doesn't exist
    cache->RemoveFromCache(rootTarget);
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);

    // Now add the item to be in the first allowed state
    XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

    // Now assert the allowed transition
    XCTAssertTrue(cache->AddToCache(rootTarget, transition));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, transition);
  }

  allowedTransitions = {
      SNTActionHoldAllowed,
      SNTActionHoldDenied,
  };

  // Check hold-related states
  for (const SNTAction transition : allowedTransitions) {
    // First make sure the item doesn't exist and move into the starting state
    cache->RemoveFromCache(rootTarget);
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
    XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);

    // Check the item can transition to the new hold state
    XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondHold));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);

    // Now assert the allowed transition returns YES and that the cache entry is removed.
    XCTAssertTrue(cache->AddToCache(rootTarget, transition));
    XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  }

  // Ensure improper transitions from the hold state are disallowed
  // First, get into the hold state
  cache->RemoveFromCache(rootTarget);
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionUnset);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRequestBinary);
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondHold));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);

  // Ensure all the following state transition attempts fail
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondHold));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllow));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllowCompiler));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondDeny));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRespondAllowNoCache));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(rootTarget).action, SNTActionRespondHold);
}

- (void)testAllowNoCacheWithDecision {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"abc123";
  cd.certSHA256 = @"cert456";

  // SNTActionRespondAllowNoCache transitions from RequestBinary
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondAllowNoCache, cd));

  // CheckCache returns AllowNoCache with the cached decision
  santa::CachedAuthResult entry = cache->CheckCache(rootTarget);
  XCTAssertEqual(entry.action, SNTActionRespondAllowNoCache);
  XCTAssertNotNil(entry.cached_decision);
  XCTAssertEqualObjects(entry.cached_decision.sha256, @"abc123");
  XCTAssertEqualObjects(entry.cached_decision.certSHA256, @"cert456");

  // RemoveFromCache clears the decision
  cache->RemoveFromCache(rootTarget);
  entry = cache->CheckCache(rootTarget);
  XCTAssertEqual(entry.action, SNTActionUnset);
  XCTAssertNil(entry.cached_decision);

  // FlushCache also clears decisions
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondAllowNoCache, cd));
  XCTAssertNotNil(cache->CheckCache(rootTarget).cached_decision);

  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);
  XCTAssertNil(cache->CheckCache(rootTarget).cached_decision);
}

- (void)testCompilerNoCacheIsNarrowedAndNeverTerminal {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 222);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"deadbeef";
  cd.certSHA256 = @"cert789";

  // Transitions out of RequestBinary exactly like SNTActionRespondAllowNoCache.
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondAllowCompilerNoCache, cd));

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
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  // Create a cache with a lowered cache expiry value
  uint64_t expiryMS = 250;
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil, expiryMS);

  santa::ExecTarget rootTarget = MakeTarget(RootDevno(), 111);

  // Add a file to the cache and put into the SNTActionRespondDeny state
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(rootTarget, SNTActionRespondDeny));

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
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget arm = MakeTarget(RootDevno(), 111, CPU_TYPE_ARM64);
  santa::ExecTarget x86 = MakeTarget(RootDevno(), 111, CPU_TYPE_X86_64);

  cache->AddToCache(arm, SNTActionRequestBinary);
  cache->AddToCache(arm, SNTActionRespondAllow);
  XCTAssertEqual(cache->CheckCache(arm).action, SNTActionRespondAllow);
  // The other slice of the same vnode is a distinct state machine.
  XCTAssertEqual(cache->CheckCache(x86).action, SNTActionUnset);

  cache->AddToCache(x86, SNTActionRequestBinary);
  cache->AddToCache(x86, SNTActionRespondDeny);
  XCTAssertEqual(cache->CheckCache(x86).action, SNTActionRespondDeny);
  XCTAssertEqual(cache->CheckCache(arm).action, SNTActionRespondAllow);
}

- (void)testCheckCacheForVnodeFindsAnySlice {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget arm = MakeTarget(RootDevno(), 222, CPU_TYPE_ARM64);
  cache->AddToCache(arm, SNTActionRequestBinary);
  cache->AddToCache(arm, SNTActionRespondAllow);

  XCTAssertEqual(cache->CheckCacheForVnode(arm.key.vnode).action, SNTActionRespondAllow);
  XCTAssertEqual(
      cache->CheckCacheForVnode(SantaVnode{.fsid = (dev_t)RootDevno(), .fileid = 999}).action,
      SNTActionUnset);
}

// Pins the storage half of identity verification: each `set` arm in AddToCache
// must carry the target's identity into the stored value.
- (void)testIdentityIsStoredByEveryTransition {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 111, CPU_TYPE_ARM64, 0xBB, 4242);

  std::vector<SNTAction> transitions = {
      SNTActionRespondAllow, SNTActionRespondAllowCompiler, SNTActionRespondDeny,
      SNTActionRespondHold,  SNTActionRespondAllowNoCache,  SNTActionRespondAllowCompilerNoCache,
  };

  for (const SNTAction transition : transitions) {
    cache->RemoveFromCache(target);

    XCTAssertTrue(cache->AddToCache(target, SNTActionRequestBinary));
    XCTAssertTrue(cache->CheckCache(target).identity == target.identity,
                  @"RequestBinary entry must carry the target's identity");

    XCTAssertTrue(cache->AddToCache(target, transition));
    XCTAssertTrue(cache->CheckCache(target).identity == target.identity,
                  @"entry stored for action %ld must carry the target's identity", transition);
  }
}

// operator== compares action + timestamp only, so a stored entry whose identity
// differs from the incoming target still satisfies the CAS precondition. The CAS
// is identity-agnostic; identity is enforced on the read side, in CheckCache.
- (void)testDifferingIdentityDoesNotBlockTheCASTransition {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget a = MakeTarget(RootDevno(), 333, CPU_TYPE_ARM64, 0x11, 100);
  santa::ExecTarget aPrime = MakeTarget(RootDevno(), 333, CPU_TYPE_ARM64, 0x22, 200);
  XCTAssertTrue(a.key == aPrime.key);
  XCTAssertFalse(a.identity == aPrime.identity);

  XCTAssertTrue(cache->AddToCache(a, SNTActionRequestBinary));
  XCTAssertTrue(cache->CheckCache(a).identity == a.identity);

  // Same key, different content identity: the CAS must still succeed and the
  // newly observed identity must replace the stored one.
  XCTAssertTrue(cache->AddToCache(aPrime, SNTActionRespondAllow));

  santa::CachedAuthResult entry = cache->CheckCache(aPrime);
  XCTAssertEqual(entry.action, SNTActionRespondAllow);
  XCTAssertTrue(entry.identity == aPrime.identity);

  // A lookup carrying the superseded identity does not get the hit: CheckCache
  // verifies identity even though the CAS did not.
  XCTAssertEqual(cache->CheckCache(a).action, SNTActionUnset);
}

- (void)testIdentityMismatchIsMissAndRemoves {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 333);
  cache->AddToCache(original, SNTActionRequestBinary);
  cache->AddToCache(original, SNTActionRespondAllow);
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
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 444, CPU_TYPE_ARM64, 0xAA);
  cache->AddToCache(original, SNTActionRequestBinary);
  cache->AddToCache(original, SNTActionRespondAllow);

  santa::ExecTarget forged = MakeTarget(RootDevno(), 444, CPU_TYPE_ARM64, 0xBB);
  XCTAssertEqual(cache->CheckCache(forged).action, SNTActionUnset);
}

- (void)testSizeMismatchIsMiss {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 666);
  cache->AddToCache(original, SNTActionRequestBinary);
  cache->AddToCache(original, SNTActionRespondAllow);

  santa::ExecTarget resized = original;
  resized.identity.size += 1;
  XCTAssertEqual(cache->CheckCache(resized).action, SNTActionUnset);
}

- (void)testIdentityMismatchOnInFlightMarkerRemovesIt {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 555);
  cache->AddToCache(original, SNTActionRequestBinary);

  santa::ExecTarget replaced = original;
  replaced.identity.ctime.tv_nsec += 1;
  // Content changed under an in-flight marker: marker is dead, treat as miss.
  XCTAssertEqual(cache->CheckCache(replaced).action, SNTActionUnset);

  // The original exec's terminal CAS (previous == RequestBinary) must now
  // fail: its result must NOT be cached after the marker was invalidated.
  cache->AddToCache(original, SNTActionRespondAllow);
  XCTAssertEqual(cache->CheckCache(original).action, SNTActionUnset);
}

// Verification is uniform across cached states: a mismatch under a hold marker
// means the hold refers to content that no longer exists. Uniformity is
// structural today (the check sits above every state-specific branch); this
// guards a future reordering.
- (void)testIdentityMismatchUnderHoldIsMissAndRemoves {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  santa::ExecTarget original = MakeTarget(RootDevno(), 777);
  XCTAssertTrue(cache->AddToCache(original, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(original, SNTActionRespondHold));
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
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  // A long deny TTL: the entry is nowhere near expiry, so a miss here can only
  // come from identity verification running ahead of the expiry check.
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil, 600000);

  santa::ExecTarget original = MakeTarget(RootDevno(), 888);
  XCTAssertTrue(cache->AddToCache(original, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(original, SNTActionRespondDeny));
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
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 456);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"unconfirmed-hash";
  cd.identityMismatched = YES;

  XCTAssertTrue(cache->AddToCache(target, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(target, SNTActionRespondAllowNoCache, cd));

  // The entry itself is kept, and the ExecTarget's own identity is still stored
  // so the hit above verifies. Only the decision is dropped.
  santa::CachedAuthResult entry = cache->CheckCache(target);
  XCTAssertEqual(entry.action, SNTActionRespondAllowNoCache);
  XCTAssertNil(entry.cached_decision);
}

- (void)testConfirmedDecisionIsStillStoredForReuse {
  // Regression guard for the above: a confirmed decision must still be kept.
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil);

  santa::ExecTarget target = MakeTarget(RootDevno(), 457);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"confirmed-hash";

  XCTAssertTrue(cache->AddToCache(target, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(target, SNTActionRespondAllowNoCache, cd));

  santa::CachedAuthResult entry = cache->CheckCache(target);
  XCTAssertEqualObjects(entry.cached_decision.sha256, @"confirmed-hash");
}

@end
