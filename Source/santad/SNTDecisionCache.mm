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

#import "Source/santad/SNTDecisionCache.h"

#include <dispatch/dispatch.h>
#include <libproc.h>
#include <os/lock.h>
#include <sys/param.h>
#include <sys/qos.h>

#include <cassert>
#include <optional>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#import "Source/common/SigningIDHelpers.h"
#include "Source/common/SystemResources.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"
#include "absl/container/flat_hash_set.h"

@interface SNTDecisionCache ()
// Cache for sha256 -> date of last timestamp reset.
@property NSCache<NSString*, NSDate*>* timestampResetMap;
@property dispatch_queue_t cachePopulateQ;
@end

@implementation SNTDecisionCache {
  SantaCache<SantaVnode, SNTCachedDecision*> _decisionCache;
  absl::flat_hash_set<SantaVnode> _pendingRehydrates;
  os_unfair_lock _pendingLock;
  std::shared_ptr<santa::EntitlementsFilter> _entitlementsFilter;
}

- (void)setEntitlementsFilter:(std::shared_ptr<santa::EntitlementsFilter>)filter {
  // Programming error to set twice: the filter is not safe to swap at runtime.
  // Reads on other threads are unsynchronized and rely on this set-once
  // invariant plus the happens-before edges established at daemon init. Tests
  // that need to restore singleton state use -resetEntitlementsFilterForTesting.
  assert(!_entitlementsFilter);
  _entitlementsFilter = std::move(filter);
}

#ifdef DEBUG
- (void)resetEntitlementsFilterForTesting {
  _entitlementsFilter.reset();
}
#endif

+ (instancetype)sharedCache {
  static SNTDecisionCache* cache;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    cache = [[SNTDecisionCache alloc] init];
  });
  return cache;
}

- (instancetype)init {
  self = [super init];
  if (self) {
    _timestampResetMap = [[NSCache alloc] init];
    _timestampResetMap.countLimit = 100;

    // Single serial queue shared by the one-shot startup backfill and the
    // on-demand FAA rehydrate path. NB: On an active system, with ~1K
    // processes, there is an almost 4x second delta in time to complete the
    // backfill between UTILITY and BACKGROUND QoS. Using UTILITY QoS here to
    // balance CPU and completion time.
    _cachePopulateQ = dispatch_queue_create_with_target(
        "com.northpolesec.santa.cache-populate-q", DISPATCH_QUEUE_SERIAL,
        dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));

    _pendingLock = OS_UNFAIR_LOCK_INIT;
  }
  return self;
}

- (bool)cacheDecision:(SNTCachedDecision*)cd {
  return self->_decisionCache.set(cd.vnodeId, cd);
}

- (bool)cacheDecisionIfNotSet:(SNTCachedDecision*)cd {
  return self->_decisionCache.set(cd.vnodeId, cd, nil);
}

- (SNTCachedDecision*)cachedDecisionForFile:(const struct stat&)statInfo {
  return self->_decisionCache.get(SantaVnode::VnodeForFile(statInfo));
}

- (SNTCachedDecision*)cachedDecisionForVnode:(SantaVnode)vnode {
  return self->_decisionCache.get(vnode);
}

- (void)forgetCachedDecisionForVnode:(SantaVnode)vnode {
  self->_decisionCache.remove(vnode);
}

// Whenever a cached decision resulting from a transitive allowlist rule is used to allow the
// execution of a binary, we update the timestamp on the transitive rule in the rules database.
// To prevent writing to the database too often, we space out consecutive writes by 3600 seconds.
- (SNTCachedDecision*)resetTimestampForCachedDecision:(const struct stat&)statInfo {
  SNTCachedDecision* cd = [self cachedDecisionForFile:statInfo];
  if (!cd || cd.decision != SNTEventStateAllowTransitive || !cd.sha256) {
    return cd;
  }

  NSDate* lastUpdate = [self.timestampResetMap objectForKey:cd.sha256];
  if (!lastUpdate || -[lastUpdate timeIntervalSinceNow] > 3600) {
    SNTRule* rule = [[SNTRule alloc] initWithIdentifier:cd.sha256
                                                  state:SNTRuleStateAllowTransitive
                                                   type:SNTRuleTypeBinary];
    [[SNTDatabaseController ruleTable] resetTimestampForExecutionRule:rule];
    [self.timestampResetMap setObject:[NSDate date] forKey:cd.sha256];
  }

  return cd;
}

- (nullable SNTCachedDecision*)buildDecisionForFileInfo:(SNTFileInfo*)fi {
  if (!fi || !fi.SHA256) {
    return nil;
  }

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] initWithVnode:fi.vnode];

  cd.decision = SNTEventStateUnknown;
  cd.decisionClientMode = SNTClientModeUnknown;
  cd.cacheable = NO;
  cd.holdAndAsk = NO;
  cd.sha256 = fi.SHA256;

  NSError* err;
  MOLCodesignChecker* csc = [fi codesignCheckerWithError:&err];
  if (csc && !err) {
    cd.certSHA256 = csc.leafCertificate.SHA256;
    cd.certCommonName = csc.leafCertificate.commonName;
    cd.certChain = csc.certificates;

    cd.teamID = csc.teamID;
    cd.signingID = FormatSigningID(csc);

    // Ensure that if no teamID exists but a signingID does exist, that the binary
    // is a platform binary. If not, remove the signingID.
    if (!cd.teamID && cd.signingID) {
      if (!csc.platformBinary) {
        cd.signingID = nil;
      }
    }

    cd.cdhash = csc.cdhash;

    cd.rawEntitlements = csc.entitlements;
    // In production the filter is set during daemon init via
    // [SNTDecisionCache setEntitlementsFilter:] before any rehydrate or
    // backfill caller can run. The guard protects unit tests and any
    // future caller that hasn't completed the setup.
    if (_entitlementsFilter) {
      cd.entitlements = _entitlementsFilter->Filter(
          csc.platformBinary ? santa::kPlatformTeamID.UTF8String : csc.teamID.UTF8String,
          csc.entitlements);
      cd.entitlementsFiltered = (cd.entitlements.count != csc.entitlements.count);
    }

    // NB: These are static flags, not runtime flags
    cd.codesigningFlags = csc.signatureFlags;
    cd.secureSigningTime = csc.secureSigningTime;
    cd.signingTime = csc.signingTime;
  }

  return cd;
}

- (nullable SNTCachedDecision*)rehydrateAndCacheDecisionForFileInfo:(SNTFileInfo*)fi {
  SNTCachedDecision* cd = [self buildDecisionForFileInfo:fi];
  if (!cd) return nil;
  if ([self cacheDecisionIfNotSet:cd]) return cd;
  // Lost the race; another caller's cd is the canonical one. Re-read so
  // callers always observe what's in the cache.
  return [self cachedDecisionForVnode:fi.vnode];
}

- (void)asyncRehydrateAndCacheDecisionForFileInfo:(SNTFileInfo*)fi {
  if (!fi) return;

  SantaVnode v = fi.vnode;

  os_unfair_lock_lock(&_pendingLock);
  bool inserted = _pendingRehydrates.insert(v).second;
  os_unfair_lock_unlock(&_pendingLock);
  if (!inserted) return;

  dispatch_async(self.cachePopulateQ, ^{
    SNTCachedDecision* cd = [self buildDecisionForFileInfo:fi];
    if (cd) {
      [self cacheDecisionIfNotSet:cd];
    }

    // Unconditional erase — no negative caching. If the build failed (e.g.,
    // transient I/O, file gone), the next event for this vnode is allowed to
    // retry. Permanent failures (non-regular file, etc.) simply re-enqueue
    // on each event; the cost is bounded by the cache-populate queue's
    // serial execution.
    os_unfair_lock_lock(&self->_pendingLock);
    self->_pendingRehydrates.erase(v);
    os_unfair_lock_unlock(&self->_pendingLock);
  });
}

#ifdef DEBUG
- (void)waitForCachePopulateQueueForTesting {
  dispatch_sync(self.cachePopulateQ, ^{
                });
}

- (NSUInteger)pendingRehydrateCountForTesting {
  os_unfair_lock_lock(&_pendingLock);
  NSUInteger n = _pendingRehydrates.size();
  os_unfair_lock_unlock(&_pendingLock);
  return n;
}
#endif

// Backfill the decision cache with pseudo SNTCachedDecision entries. This is done
// by getting a snapshot of PIDs and populating as much information as possible.
// IMPORTANT: Because the processes were not actually evaluated, some bits of
// information are left in an "unknown" state, such as the client mode and decision.
- (void)backfillDecisionCacheAsync {
  dispatch_async(self.cachePopulateQ, ^{
    [self backfillDecisionCacheSerialized];
  });
}

- (void)backfillDecisionCacheSerialized {
  std::optional<std::vector<pid_t>> pids = GetPidList();
  if (!pids) {
    LOGW(@"Unable to backfill data for running processes");
    return;
  }

  size_t backfilled = 0;
  size_t already_cached = 0;
  size_t skipped = 0;

  for (pid_t pid : *pids) {
    if (pid == 0) {
      skipped++;
      continue;
    }

    char pathBuf[MAXPATHLEN] = {};
    if (proc_pidpath(pid, pathBuf, sizeof(pathBuf)) <= 0) {
      continue;
    }

    SNTFileInfo* fi = [[SNTFileInfo alloc] initWithPath:@(pathBuf)];
    if (!fi) {
      continue;
    }

    if ([self cachedDecisionForVnode:fi.vnode]) {
      already_cached++;
      continue;
    }

    SNTCachedDecision* cd = [self buildDecisionForFileInfo:fi];
    if (!cd) {
      continue;
    }

    // cacheDecisionIfNotSet: is a first-writer-wins insert; a false return
    // means another caller already populated this vnode, so it's effectively
    // already cached.
    if ([self cacheDecisionIfNotSet:cd]) {
      backfilled++;
    } else {
      already_cached++;
    }
  }

  LOGI(@"Cache backfill complete. %zu total PIDs, %zu backfilled, %zu already cached, %zu skipped, "
       @"%zu failed (likely exited)",
       pids->size(), backfilled, already_cached, skipped,
       pids->size() - (backfilled + already_cached + skipped));
}

@end
