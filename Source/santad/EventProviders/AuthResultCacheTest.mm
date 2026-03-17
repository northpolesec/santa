/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
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

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/EndpointSecurity/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityClientBase.h"

using santa::AuthResultCache;
using santa::FlushCacheMode;
using santa::FlushCacheReason;

namespace santa {
extern NSString *const FlushCacheReasonToString(FlushCacheReason reason);
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

static inline es_file_t MakeCacheableFile(uint64_t devno, uint64_t ino) {
  return es_file_t{
      .path = {}, .path_truncated = false, .stat = {.st_dev = (dev_t)devno, .st_ino = ino}};
}

static inline void AssertCacheCounts(std::shared_ptr<AuthResultCache> cache, uint64_t root_count,
                                     uint64_t nonroot_count) {
  NSArray<NSNumber *> *counts = cache->CacheCounts();

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

  es_file_t rootFile = MakeCacheableFile(RootDevno(), 111);
  es_file_t nonrootFile = MakeCacheableFile(RootDevno() + 123, 222);

  // Add the root file to the cache
  cache->AddToCache(&rootFile, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 0);
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);
  XCTAssertEqual(cache->CheckCache(&nonrootFile).action, SNTActionUnset);

  // Now add the non-root file
  cache->AddToCache(&nonrootFile, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);
  XCTAssertEqual(cache->CheckCache(&nonrootFile).action, SNTActionRequestBinary);

  // Update the cached values
  cache->AddToCache(&rootFile, SNTActionRespondAllow);
  cache->AddToCache(&nonrootFile, SNTActionRespondDeny);

  AssertCacheCounts(cache, 1, 1);
  XCTAssertEqual(cache->CheckCache(SantaVnode::VnodeForFile(&rootFile)).action,
                 SNTActionRespondAllow);
  XCTAssertEqual(cache->CheckCache(SantaVnode::VnodeForFile(&nonrootFile)).action,
                 SNTActionRespondDeny);

  // Remove the root file
  cache->RemoveFromCache(&rootFile);

  AssertCacheCounts(cache, 0, 1);
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);
  XCTAssertEqual(cache->CheckCache(&nonrootFile).action, SNTActionRespondDeny);
}

- (void)testFlushCache {
  id<SNTEndpointSecurityClientBase> client =
      OCMProtocolMock(@protocol(SNTEndpointSecurityClientBase));

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil);
  cache->SetESClient(client);

  es_file_t rootFile = MakeCacheableFile(RootDevno(), 111);
  es_file_t nonrootFile = MakeCacheableFile(RootDevno() + 123, 111);

  cache->AddToCache(&rootFile, SNTActionRequestBinary);
  cache->AddToCache(&nonrootFile, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 1);

  // Flush non-root only
  cache->FlushCache(FlushCacheMode::kNonRootOnly, FlushCacheReason::kClientModeChanged);

  AssertCacheCounts(cache, 1, 0);

  // Add back the non-root file
  cache->AddToCache(&nonrootFile, SNTActionRequestBinary);

  AssertCacheCounts(cache, 1, 1);

  // Flush all caches
  // The call to ClearCache is asynchronous. Use a semaphore to
  // be notified when the mock is called.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  OCMStub([client clearCache])
      .andDo(^(NSInvocation *invocation) {
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

  es_file_t rootFile = MakeCacheableFile(RootDevno(), 111);

  // Cached items must first be in the SNTActionRequestBinary state
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondAllow));
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondAllowCompiler));
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondDeny));
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondHold));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);

  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);

  // Items in the `SNTActionRequestBinary` state cannot reenter the same state
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);

  std::vector<SNTAction> allowedTransitions = {
      SNTActionRespondAllow,
      SNTActionRespondAllowCompiler,
      SNTActionRespondDeny,
      SNTActionRespondAllowNoCache,
  };

  for (const SNTAction transition : allowedTransitions) {
    // First make sure the item doesn't exist
    cache->RemoveFromCache(&rootFile);
    XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);

    // Now add the item to be in the first allowed state
    XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
    XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);

    // Now assert the allowed transition
    XCTAssertTrue(cache->AddToCache(&rootFile, transition));
    XCTAssertEqual(cache->CheckCache(&rootFile).action, transition);
  }

  allowedTransitions = {
      SNTActionHoldAllowed,
      SNTActionHoldDenied,
  };

  // Check hold-related states
  for (const SNTAction transition : allowedTransitions) {
    // First make sure the item doesn't exist and move into the starting state
    cache->RemoveFromCache(&rootFile);
    XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);
    XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
    XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);

    // Check the item can transition to the new hold state
    XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRespondHold));
    XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);

    // Now assert the allowed transition returns YES and that the cache entry is removed.
    XCTAssertTrue(cache->AddToCache(&rootFile, transition));
    XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);
  }

  // Ensure improper transitions from the hold state are disallowed
  // First, get into the hold state
  cache->RemoveFromCache(&rootFile);
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRequestBinary);
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRespondHold));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);

  // Ensure all the following state transition attempts fail
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondHold));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondAllow));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondAllowCompiler));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondDeny));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRespondAllowNoCache));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);
  XCTAssertFalse(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondHold);
}

- (void)testAllowNoCacheWithDecision {
  auto esapi = std::make_shared<MockEndpointSecurityAPI>();
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(esapi, nil);

  es_file_t rootFile = MakeCacheableFile(RootDevno(), 111);

  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"abc123";
  cd.certSHA256 = @"cert456";

  // SNTActionRespondAllowNoCache transitions from RequestBinary
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRespondAllowNoCache, cd));

  // CheckCache returns AllowNoCache with the cached decision
  santa::CachedAuthResult entry = cache->CheckCache(&rootFile);
  XCTAssertEqual(entry.action, SNTActionRespondAllowNoCache);
  XCTAssertNotNil(entry.cached_decision);
  XCTAssertEqualObjects(entry.cached_decision.sha256, @"abc123");
  XCTAssertEqualObjects(entry.cached_decision.certSHA256, @"cert456");

  // RemoveFromCache clears the decision
  cache->RemoveFromCache(&rootFile);
  entry = cache->CheckCache(&rootFile);
  XCTAssertEqual(entry.action, SNTActionUnset);
  XCTAssertNil(entry.cached_decision);

  // FlushCache also clears decisions
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRespondAllowNoCache, cd));
  XCTAssertNotNil(cache->CheckCache(&rootFile).cached_decision);

  cache->FlushCache(FlushCacheMode::kAllCaches, FlushCacheReason::kRulesChanged);
  XCTAssertNil(cache->CheckCache(&rootFile).cached_decision);
}

- (void)testCacheExpiry {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  // Create a cache with a lowered cache expiry value
  uint64_t expiryMS = 250;
  std::shared_ptr<AuthResultCache> cache = AuthResultCache::Create(mockESApi, nil, expiryMS);

  es_file_t rootFile = MakeCacheableFile(RootDevno(), 111);

  // Add a file to the cache and put into the SNTActionRespondDeny state
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRequestBinary));
  XCTAssertTrue(cache->AddToCache(&rootFile, SNTActionRespondDeny));

  // Ensure the file exists
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionRespondDeny);

  // Wait for the item to expire
  SleepMS(expiryMS);

  // Check cache counts to make sure the item still exists
  AssertCacheCounts(cache, 1, 0);

  // Now check the cache, which will remove the item
  XCTAssertEqual(cache->CheckCache(&rootFile).action, SNTActionUnset);
  AssertCacheCounts(cache, 0, 0);
}

- (void)testFlushCacheReasonToString {
  std::map<FlushCacheReason, NSString *> reasonToString = {
      {FlushCacheReason::kClientModeChanged, @"ClientModeChanged"},
      {FlushCacheReason::kPathRegexChanged, @"PathRegexChanged"},
      {FlushCacheReason::kRulesChanged, @"RulesChanged"},
      {FlushCacheReason::kStaticRulesChanged, @"StaticRulesChanged"},
      {FlushCacheReason::kExplicitCommand, @"ExplicitCommand"},
      {FlushCacheReason::kFilesystemUnmounted, @"FilesystemUnmounted"},
      {FlushCacheReason::kEntitlementsPrefixFilterChanged, @"EntitlementsPrefixFilterChanged"},
      {FlushCacheReason::kEntitlementsTeamIDFilterChanged, @"EntitlementsTeamIDFilterChanged"},
      {FlushCacheReason::kCELFallbackRulesChanged, @"CELFallbackRulesChanged"},
  };

  for (const auto &kv : reasonToString) {
    XCTAssertEqualObjects(FlushCacheReasonToString(kv.first), kv.second);
  }

  XCTAssertThrows(FlushCacheReasonToString(
      (FlushCacheReason)(static_cast<int>(FlushCacheReason::kCELFallbackRulesChanged) + 1)));
}

@end
