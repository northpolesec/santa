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

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#import "Source/common/SNTCachedDecision.h"

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SantaVnode.h"
#include "Source/common/TestUtils.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/EntitlementsFilter.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"

SNTCachedDecision* MakeCachedDecision(struct stat sb, SNTEventState decision) {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];

  cd.decision = decision;
  cd.sha256 = @"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  cd.vnodeId = {
      .fsid = sb.st_dev,
      .fileid = sb.st_ino,
  };

  return cd;
}

@interface SNTDecisionCache (TestSupport)
- (void)waitForCachePopulateQueueForTesting;
- (NSUInteger)pendingRehydrateCountForTesting;
- (dispatch_queue_t)cachePopulateQ;
- (void)resetEntitlementsFilterForTesting;
@end

@interface SNTDecisionCacheTest : XCTestCase
@property id mockDatabaseController;
@property id mockRuleDatabase;
@end

@implementation SNTDecisionCacheTest

- (void)setUp {
  self.mockDatabaseController = OCMClassMock([SNTDatabaseController class]);
  self.mockRuleDatabase = OCMStrictClassMock([SNTRuleTable class]);
}

- (void)testBasicOperation {
  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];

  struct stat sb = MakeStat();

  // First make sure the item isn't in the cache
  XCTAssertNil([dc cachedDecisionForFile:sb]);

  // Add the item to the cache
  SNTCachedDecision* cd = MakeCachedDecision(sb, SNTEventStateAllowTeamID);
  [dc cacheDecision:cd];

  // Ensure the item exists in the cache
  SNTCachedDecision* cachedCD = [dc cachedDecisionForFile:sb];
  XCTAssertNotNil(cachedCD);
  XCTAssertEqual(cachedCD.decision, cd.decision);
  XCTAssertEqual(cachedCD.vnodeId.fileid, cd.vnodeId.fileid);

  // Delete the item from the cache and ensure it no longer exists
  [dc forgetCachedDecisionForVnode:SantaVnode::VnodeForFile(sb)];
  XCTAssertNil([dc cachedDecisionForFile:sb]);
}

- (void)testResetTimestampForCachedDecision {
  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];
  struct stat sb = MakeStat();
  SNTCachedDecision* cd = MakeCachedDecision(sb, SNTEventStateAllowTransitive);

  [dc cacheDecision:cd];

  OCMStub([self.mockDatabaseController ruleTable]).andReturn(self.mockRuleDatabase);

  OCMExpect([self.mockRuleDatabase
      resetTimestampForExecutionRule:[OCMArg checkWithBlock:^BOOL(SNTRule* rule) {
        return [rule.identifier isEqualToString:cd.sha256] &&
               rule.state == SNTRuleStateAllowTransitive && rule.type == SNTRuleTypeBinary;
      }]]);

  [dc resetTimestampForCachedDecision:sb];

  // Timestamps should not be reset so frequently. Call a second time quickly
  // but do not register a second expectation so that the test will fail if
  // timestamps are actually reset a second time.
  [dc resetTimestampForCachedDecision:sb];

  XCTAssertTrue(OCMVerifyAll(self.mockRuleDatabase));
}

- (void)testRehydrateAndCacheDecisionForFileInfo {
  NSString* tmpDir = NSTemporaryDirectory();
  NSString* tmpPath = [tmpDir
      stringByAppendingPathComponent:[NSString stringWithFormat:@"snt415-%@",
                                                                [[NSUUID UUID] UUIDString]]];
  NSData* contents = [@"hello santa" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertTrue([contents writeToFile:tmpPath atomically:YES]);

  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:tmpPath];
  XCTAssertNotNil(fi);
  XCTAssertNotNil(fi.SHA256);

  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];
  [dc forgetCachedDecisionForVnode:fi.vnode];  // start clean

  SNTCachedDecision* cd = [dc rehydrateAndCacheDecisionForFileInfo:fi];
  XCTAssertNotNil(cd);
  XCTAssertEqualObjects(cd.sha256, fi.SHA256);
  XCTAssertEqual(cd.decision, SNTEventStateUnknown);
  XCTAssertEqual(cd.cacheable, NO);

  // Verify it landed in the cache.
  SNTCachedDecision* cached = [dc cachedDecisionForVnode:fi.vnode];
  XCTAssertNotNil(cached);
  XCTAssertEqualObjects(cached.sha256, fi.SHA256);
  XCTAssertEqual(cached, cd);

  [dc forgetCachedDecisionForVnode:fi.vnode];
  [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
}

- (void)testAsyncRehydrateAndCacheDecisionForFileInfo {
  NSString* tmpDir = NSTemporaryDirectory();
  NSString* tmpPath = [tmpDir
      stringByAppendingPathComponent:[NSString stringWithFormat:@"snt415-async-%@",
                                                                [[NSUUID UUID] UUIDString]]];
  NSData* contents = [@"hello async santa" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertTrue([contents writeToFile:tmpPath atomically:YES]);

  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:tmpPath];
  XCTAssertNotNil(fi);

  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];
  [dc forgetCachedDecisionForVnode:fi.vnode];

  [dc asyncRehydrateAndCacheDecisionForFileInfo:fi];
  // Issue a second call before the queue drains — must be deduped.
  [dc asyncRehydrateAndCacheDecisionForFileInfo:fi];

  // Drain the rehydrate queue by waiting on a sync barrier.
  [dc waitForCachePopulateQueueForTesting];

  SNTCachedDecision* cached = [dc cachedDecisionForVnode:fi.vnode];
  XCTAssertNotNil(cached);
  XCTAssertEqualObjects(cached.sha256, fi.SHA256);
  XCTAssertEqual(cached.decision, SNTEventStateUnknown);
  XCTAssertEqual(cached.cacheable, NO);

  [dc forgetCachedDecisionForVnode:fi.vnode];
  [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
}

- (void)testAsyncRehydrateDedupesInFlight {
  NSString* tmpDir = NSTemporaryDirectory();
  NSString* tmpPath = [tmpDir
      stringByAppendingPathComponent:[NSString stringWithFormat:@"snt415-dedup-%@",
                                                                [[NSUUID UUID] UUIDString]]];
  NSData* contents = [@"dedup test" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertTrue([contents writeToFile:tmpPath atomically:YES]);

  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:tmpPath];
  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];
  [dc forgetCachedDecisionForVnode:fi.vnode];

  // Block the queue with a long-running sync work item, then enqueue
  // multiple async rehydrates. After unblocking, only one should have
  // gotten past the dedup check.
  dispatch_semaphore_t blocker = dispatch_semaphore_create(0);
  dispatch_async(dc.cachePopulateQ, ^{
    dispatch_semaphore_wait(blocker, DISPATCH_TIME_FOREVER);
  });

  [dc asyncRehydrateAndCacheDecisionForFileInfo:fi];
  [dc asyncRehydrateAndCacheDecisionForFileInfo:fi];
  [dc asyncRehydrateAndCacheDecisionForFileInfo:fi];

  XCTAssertEqual([dc pendingRehydrateCountForTesting], 1u);

  dispatch_semaphore_signal(blocker);
  [dc waitForCachePopulateQueueForTesting];

  XCTAssertEqual([dc pendingRehydrateCountForTesting], 0u);

  [dc forgetCachedDecisionForVnode:fi.vnode];
  [[NSFileManager defaultManager] removeItemAtPath:tmpPath error:nil];
}

// Exercises buildDecisionForFileInfo:'s codesign-success branch using a real
// Apple-signed binary. The temp-file fixtures used by the other tests are
// unsigned, so this is the only place we verify certSHA256 / cdhash /
// signingID / certChain population.
- (void)testRehydratePopulatesCodesignFieldsForSignedBinary {
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/sbin/launchd"];
  XCTAssertNotNil(fi);

  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];
  [dc forgetCachedDecisionForVnode:fi.vnode];

  SNTCachedDecision* cd = [dc rehydrateAndCacheDecisionForFileInfo:fi];
  XCTAssertNotNil(cd);
  XCTAssertNotNil(cd.sha256);

  // Codesigning success branch fields.
  XCTAssertNotNil(cd.certSHA256);
  XCTAssertNotNil(cd.cdhash);
  XCTAssertNotNil(cd.certChain);
  XCTAssertGreaterThan(cd.certChain.count, 0u);

  // launchd is a platform binary: no teamID, but signingID is retained.
  XCTAssertNil(cd.teamID);
  XCTAssertNotNil(cd.signingID);

  [dc forgetCachedDecisionForVnode:fi.vnode];
}

// Exercises the entitlements-filter branch of buildDecisionForFileInfo:. The
// other tests run with entitlementsFilter == nullptr, so the Filter() call and
// the cd.entitlementsFiltered flag have no coverage without this test.
- (void)testRehydrateAppliesEntitlementsFilter {
  SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@"/sbin/launchd"];
  XCTAssertNotNil(fi);

  SNTDecisionCache* dc = [SNTDecisionCache sharedCache];
  [dc forgetCachedDecisionForVnode:fi.vnode];

  // Pass-through filter (no teamID drops, no prefix filtering) — Filter()
  // should deep-copy entitlements rather than dropping or trimming them.
  std::shared_ptr<santa::EntitlementsFilter> filter = santa::EntitlementsFilter::Create(@[], @[]);
  [dc setEntitlementsFilter:filter];

  SNTCachedDecision* cd = [dc rehydrateAndCacheDecisionForFileInfo:fi];
  XCTAssertNotNil(cd);

  // launchd has entitlements; if it ever doesn't, the assertion below catches
  // it — the test would need a different fixture.
  XCTAssertNotNil(cd.rawEntitlements);
  XCTAssertGreaterThan(cd.rawEntitlements.count, 0u);

  // Pass-through filter: cd.entitlements is populated and matches raw count.
  XCTAssertNotNil(cd.entitlements);
  XCTAssertEqual(cd.entitlements.count, cd.rawEntitlements.count);
  XCTAssertFalse(cd.entitlementsFiltered);

  [dc forgetCachedDecisionForVnode:fi.vnode];

  // Restore the singleton's filter to nullptr — none of the other tests
  // expect it set, and the singleton state persists across tests. The
  // production -setEntitlementsFilter: is strictly set-once, so use the
  // test-only escape hatch.
  [dc resetEntitlementsFilterForTesting];
}

@end
