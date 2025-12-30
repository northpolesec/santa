/// Copyright 2022 Google Inc. All rights reserved.
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

#import "Source/santad/SNTDecisionCache.h"

#include <dispatch/dispatch.h>
#include <libproc.h>
#include <sys/param.h>
#include <sys/qos.h>

#include <optional>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#include "Source/common/SNTCachedDecision.h"
#include "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/SystemResources.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"

@interface SNTDecisionCache ()
// Cache for sha256 -> date of last timestamp reset.
@property NSCache<NSString *, NSDate *> *timestampResetMap;
@property dispatch_queue_t backfillQ;
@end

@implementation SNTDecisionCache {
  SantaCache<SantaVnode, SNTCachedDecision *> _decisionCache;
}

+ (instancetype)sharedCache {
  static SNTDecisionCache *cache;
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

    // NB: On an active system, with ~1K processes, there is an almost 4x second
    // delta in time to complete the backfill between UTILITY and BACKGROUND QoS.
    // Using UTILITY QoS here to balance CPU and completion time.
    _backfillQ = dispatch_queue_create("com.northpolesec.santa.backfillq", DISPATCH_QUEUE_SERIAL);
    dispatch_set_target_queue(_backfillQ, dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
  }
  return self;
}

- (bool)cacheDecision:(SNTCachedDecision *)cd {
  return self->_decisionCache.set(cd.vnodeId, cd);
}

- (bool)cacheDecisionIfNotSet:(SNTCachedDecision *)cd {
  return self->_decisionCache.set(cd.vnodeId, cd, nil);
}

- (SNTCachedDecision *)cachedDecisionForFile:(const struct stat &)statInfo {
  return self->_decisionCache.get(SantaVnode::VnodeForFile(statInfo));
}

- (SNTCachedDecision *)cachedDecisionForVnode:(SantaVnode)vnode {
  return self->_decisionCache.get(vnode);
}

- (void)forgetCachedDecisionForVnode:(SantaVnode)vnode {
  self->_decisionCache.remove(vnode);
}

// Whenever a cached decision resulting from a transitive allowlist rule is used to allow the
// execution of a binary, we update the timestamp on the transitive rule in the rules database.
// To prevent writing to the database too often, we space out consecutive writes by 3600 seconds.
- (SNTCachedDecision *)resetTimestampForCachedDecision:(const struct stat &)statInfo {
  SNTCachedDecision *cd = [self cachedDecisionForFile:statInfo];
  if (!cd || cd.decision != SNTEventStateAllowTransitive || !cd.sha256) {
    return cd;
  }

  NSDate *lastUpdate = [self.timestampResetMap objectForKey:cd.sha256];
  if (!lastUpdate || -[lastUpdate timeIntervalSinceNow] > 3600) {
    SNTRule *rule = [[SNTRule alloc] initWithIdentifier:cd.sha256
                                                  state:SNTRuleStateAllowTransitive
                                                   type:SNTRuleTypeBinary];
    [[SNTDatabaseController ruleTable] resetTimestampForExecutionRule:rule];
    [self.timestampResetMap setObject:[NSDate date] forKey:cd.sha256];
  }

  return cd;
}

// Backfill the decision cache with pseudo SNTCachedDecision entries. This is done
// by getting a snapshot of PIDs and populating as much information as possible.
// IMPORTANT: Because the processes were not actually evaluated, some bits of
// information are left in an "unknown" state, such as the client mode and decision.
- (void)backfillDecisionCacheAsyncWithEntitlementsFilter:
    (std::shared_ptr<santa::EntitlementsFilter>)entitlementsFilter {
  dispatch_async(self.backfillQ, ^{
    [self backfillDecisionCacheWithEntitlementsFilterSerialized:entitlementsFilter];
  });
}

- (void)backfillDecisionCacheWithEntitlementsFilterSerialized:
    (std::shared_ptr<santa::EntitlementsFilter>)entitlementsFilter {
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

    SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@(pathBuf)];
    if (!fi) {
      continue;
    }

    if ([self cachedDecisionForVnode:fi.vnode]) {
      // Already in the cache, move along
      already_cached++;
      continue;
    }

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] initWithVnode:fi.vnode];

    cd.decision = SNTEventStateUnknown;
    cd.decisionClientMode = SNTClientModeUnknown;
    cd.cacheable = NO;
    cd.holdAndAsk = NO;

    cd.sha256 = fi.SHA256;

    NSError *err;
    MOLCodesignChecker *csc = [fi codesignCheckerWithError:&err];
    if (csc && !err) {
      cd.certSHA256 = csc.leafCertificate.SHA256;
      cd.certCommonName = csc.leafCertificate.commonName;
      cd.certChain = csc.certificates;

      cd.teamID = csc.teamID;
      if (csc.teamID || csc.platformBinary) {
        cd.signingID = csc.signingID;
      }
      cd.cdhash = csc.cdhash;

      cd.entitlements = entitlementsFilter->Filter(
          csc.platformBinary ? santa::kPlatformTeamID.UTF8String : csc.teamID.UTF8String,
          csc.entitlements);
      cd.entitlementsFiltered = (cd.entitlements.count != csc.entitlements.count);

      // NB: These are static flags, not runtime flags
      cd.codesigningFlags = csc.signatureFlags;
      cd.secureSigningTime = csc.secureSigningTime;
      cd.signingTime = csc.signingTime;
    }

    // Only add the value to the cache if something else didn't come along
    // and add it via a normal route.
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
