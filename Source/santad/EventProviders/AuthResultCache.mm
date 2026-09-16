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

#include "Source/santad/EventProviders/AuthResultCache.h"

#include <mach/clock_types.h>

#import "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTLogging.h"
#include "Source/common/SystemResources.h"
#include "Source/common/es/Client.h"

using santa::Client;
using santa::EndpointSecurityAPI;

static NSString* const kFlushCacheReasonClientModeChanged = @"ClientModeChanged";
static NSString* const kFlushCacheReasonPathRegexChanged = @"PathRegexChanged";
static NSString* const kFlushCacheReasonRulesChanged = @"RulesChanged";
static NSString* const kFlushCacheReasonStaticRulesChanged = @"StaticRulesChanged";
static NSString* const kFlushCacheReasonExplicitCommand = @"ExplicitCommand";
static NSString* const kFlushCacheReasonFilesystemUnmounted = @"FilesystemUnmounted";
static NSString* const kFlushCacheReasonEntitlementsPrefixFilterChanged =
    @"EntitlementsPrefixFilterChanged";
static NSString* const kFlushCacheReasonEntitlementsTeamIDFilterChanged =
    @"EntitlementsTeamIDFilterChanged";
static NSString* const kFlushCacheReasonCELFallbackRulesChanged = @"CELFallbackRulesChanged";
static NSString* const kFlushCacheReasonTransitiveRulesChanged = @"TransitiveRulesChanged";

namespace santa {

ExecTarget ExecTarget::ForExecEvent(const es_message_t* msg) {
  const es_process_t* proc = msg->event.exec.target;
  const struct stat& sb = proc->executable->stat;
  ExecTarget t;
  t.key.vnode = SantaVnode::VnodeForFile(proc->executable);
  t.key.cputype = msg->event.exec.image_cputype;
  // Capability bits (e.g. arm64e ptrauth ABI versioning) would split entries
  // for the same slice; only the base subtype identifies the slice.
  t.key.cpusubtype = msg->event.exec.image_cpusubtype & ~CPU_SUBTYPE_MASK;
  memcpy(t.identity.cdhash.data(), proc->cdhash, CS_CDHASH_LEN);
  t.identity.mtime = sb.st_mtimespec;
  t.identity.ctime = sb.st_ctimespec;
  t.identity.btime = sb.st_birthtimespec;
  t.identity.size = sb.st_size;
  t.enforced = CdhashStrictlyEnforced(proc->codesigning_flags);
  return t;
}

NSString* const FlushCacheReasonToString(FlushCacheReason reason) {
  switch (reason) {
    case FlushCacheReason::kClientModeChanged: return kFlushCacheReasonClientModeChanged;
    case FlushCacheReason::kPathRegexChanged: return kFlushCacheReasonPathRegexChanged;
    case FlushCacheReason::kRulesChanged: return kFlushCacheReasonRulesChanged;
    case FlushCacheReason::kStaticRulesChanged: return kFlushCacheReasonStaticRulesChanged;
    case FlushCacheReason::kExplicitCommand: return kFlushCacheReasonExplicitCommand;
    case FlushCacheReason::kFilesystemUnmounted: return kFlushCacheReasonFilesystemUnmounted;
    case FlushCacheReason::kEntitlementsPrefixFilterChanged:
      return kFlushCacheReasonEntitlementsPrefixFilterChanged;
    case FlushCacheReason::kEntitlementsTeamIDFilterChanged:
      return kFlushCacheReasonEntitlementsTeamIDFilterChanged;
    case FlushCacheReason::kCELFallbackRulesChanged:
      return kFlushCacheReasonCELFallbackRulesChanged;
    case FlushCacheReason::kTransitiveRulesChanged: return kFlushCacheReasonTransitiveRulesChanged;
    default:
      [NSException raise:@"Invalid reason"
                  format:@"Unknown reason value: %d", static_cast<int>(reason)];
      return nil;
  }
}

std::unique_ptr<AuthResultCache> AuthResultCache::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                                         SNTMetricSet* metric_set,
                                                         uint64_t cache_deny_time_ms) {
  SNTMetricCounter* flush_count =
      [metric_set counterWithName:@"/santa/flush_count"
                       fieldNames:@[ @"Reason" ]
                         helpText:@"Count of times the auth result cache is flushed by reason"];

  return std::make_unique<AuthResultCache>(esapi, flush_count, cache_deny_time_ms);
}

AuthResultCache::AuthResultCache(std::shared_ptr<EndpointSecurityAPI> esapi,
                                 SNTMetricCounter* flush_count, uint64_t cache_deny_time_ms)
    : esapi_(esapi),
      flush_count_(flush_count),
      cache_deny_time_ns_(cache_deny_time_ms * NSEC_PER_MSEC) {
  root_cache_ = new SantaCache<AuthResultKey, CachedAuthResult>();
  nonroot_cache_ = new SantaCache<AuthResultKey, CachedAuthResult>();

  struct stat sb;
  if (stat("/", &sb) == 0) {
    root_devno_ = sb.st_dev;
  }

  q_ = dispatch_queue_create(
      "com.northpolesec.santa.daemon.auth_result_cache.q",
      dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                              QOS_CLASS_USER_INTERACTIVE, 0));
}

AuthResultCache::~AuthResultCache() {
  delete root_cache_;
  delete nonroot_cache_;
}

bool AuthResultCache::AddToCache(const ExecTarget& target, SNTAction decision,
                                 SNTCachedDecision* cd) {
  const AuthResultKey& key = target.key;
  SantaCache<AuthResultKey, CachedAuthResult>* cache = CacheForVnodeID(key.vnode);
  CachedAuthResult requestBinary = {SNTActionRequestBinary, 0, nil, target.identity};

  switch (decision) {
    // SNTActionRequestBinary and SNTActionRespondHold are not terminal states and should not
    // contain a timestamp to allow for proper transitions out of the state.
    case SNTActionRequestBinary: return cache->set(key, requestBinary, CachedAuthResult{});
    case SNTActionRespondHold:
      return cache->set(key, CachedAuthResult{SNTActionRespondHold, 0, nil, target.identity},
                        requestBinary);

    case SNTActionRespondAllow: OS_FALLTHROUGH;
    case SNTActionRespondAllowCompiler: OS_FALLTHROUGH;
    case SNTActionRespondDeny:
      return cache->set(key, CachedAuthResult{decision, GetCurrentUptime(), nil, target.identity},
                        requestBinary);

    case SNTActionRespondDenyOnce:
      // Transition out of the in-flight marker to no entry at all, so this
      // denial can never reach a later execution of the same vnode.
      //
      // A zeroed timestamp will not do instead: timestamp is a creation time and
      // GetCurrentUptime() is monotonic since boot, so such an entry would not
      // count as expired for the first deny interval after boot. The
      // three-argument form rather than remove() keeps the transition out of
      // SNTActionRequestBinary atomic for a concurrent waiter, which then sees
      // no entry and evaluates independently.
      return cache->set(key, CachedAuthResult{}, requestBinary);

    case SNTActionRespondAllowNoCache: {
      // The stored decision lets the next execution reuse this identity work.
      // One whose identity was never confirmed must not be reused that way: the
      // restrictions that applied to the execution it came from do not travel
      // with it. Keep the entry, drop the decision.
      //
      // Separate from the ExecIdentity stored alongside it. ExecIdentity comes
      // from the exec event and describes the vnode about to be executed, so it
      // is what a later hit is verified against and is always stored.
      // identityMismatched instead reports that the file santad opened was not
      // that vnode, making the decision's own hash and signing identity
      // untrustworthy under any key.
      CachedAuthResult entry = {SNTActionRespondAllowNoCache, GetCurrentUptime(),
                                cd.identityMismatched ? nil : [cd copy], target.identity};
      return cache->set(key, entry, requestBinary);
    }

    case SNTActionRespondAllowCompilerNoCache: {
      // Compiler status was granted to the process that was just authorized, not
      // to this vnode. Narrow to a plain no-cache entry so the next execution can
      // reuse the identity data but must still run policy again.
      //
      // Because this action is never stored, no cache reader can observe it.
      //
      // An unconfirmed decision is dropped for the same reason as above.
      CachedAuthResult entry = {SNTActionRespondAllowNoCache, GetCurrentUptime(),
                                cd.identityMismatched ? nil : [cd copy], target.identity};
      return cache->set(key, entry, requestBinary);
    }

    // SNTActionHoldAllowed and SNTActionHoldDenied are used for transitions, however the
    // cached action is translated to SNTActionRespondAllow or SNTActionRespondDeny respectively.
    // We do not want to cache this result and later execs need to go through this path again.
    case SNTActionHoldAllowed: OS_FALLTHROUGH;
    case SNTActionHoldDenied: cache->remove(key); return YES;

    default:
      // This is a programming error. Bail.
      LOGE(@"Invalid cache value, exiting.");
      exit(EXIT_FAILURE);
  }
}

void AuthResultCache::RemoveFromCache(const ExecTarget& target) {
  CacheForVnodeID(target.key.vnode)->remove(target.key);
}

CachedAuthResult AuthResultCache::CheckCache(const ExecTarget& target) {
  const AuthResultKey& key = target.key;
  SantaCache<AuthResultKey, CachedAuthResult>* cache = CacheForVnodeID(key.vnode);

  CachedAuthResult entry = cache->get(key);
  if (entry == CachedAuthResult{}) {
    return {};
  }

  // The key names only a location (vnode + slice), which a filesystem is free
  // to reuse for different content. Serve the entry only if the identity
  // observed at this exec matches the one it was stored for. Uniform across
  // every cached state: a mismatch under an in-flight marker means the marker
  // refers to content that no longer exists.
  if (!(entry.identity == target.identity)) {
    // CAS-remove rather than unconditional remove: evict only if the entry
    // still holds the value just examined, so one refreshed concurrently is
    // left alone. Equality here is CachedAuthResult::operator==, i.e. action +
    // timestamp only. The marker states carry no timestamp, so a marker may be
    // evicted; that is safe, because the terminal CAS that would have followed
    // it then fails and the next exec re-validates.
    cache->set(key, CachedAuthResult{}, entry);
    return {};
  }

  if (entry.action == SNTActionRespondDeny) {
    uint64_t expiry_time = entry.timestamp + cache_deny_time_ns_;
    if (expiry_time < GetCurrentUptime()) {
      cache->remove(key);
      return {};
    }
  }

  return entry;
}

// Diagnostic only. Unlike CheckCache this deliberately reports the raw contents
// of the cache: deny expiry is not applied (a deny past its TTL is still
// reported until the hot path evicts it) and, for a fat binary with divergent
// per-slice states, an arbitrary slice is returned.
CachedAuthResult AuthResultCache::CheckCacheForVnode(SantaVnode vnode) {
  CachedAuthResult result{};
  CacheForVnodeID(vnode)->foreach([&](AuthResultKey& key, CachedAuthResult& value) {
    if (result.action == SNTActionUnset && key.vnode == vnode) {
      result = value;
    }
  });
  return result;
}

SantaCache<AuthResultKey, CachedAuthResult>* AuthResultCache::CacheForVnodeID(SantaVnode vnode_id) {
  return (vnode_id.fsid == root_devno_ || root_devno_ == 0) ? root_cache_ : nonroot_cache_;
}

void AuthResultCache::FlushCache(FlushCacheMode mode, FlushCacheReason reason) {
  nonroot_cache_->clear();
  if (mode == FlushCacheMode::kAllCaches) {
    root_cache_->clear();

    // Clear the ES cache when all local caches are flushed. Assume the ES cache
    // doesn't need to be cleared when only flushing the non-root cache.
    //
    // Calling into ES should be done asynchronously since it could otherwise
    // potentially deadlock.
    auto shared_esapi = esapi_->shared_from_this();
    id<SNTEndpointSecurityClientBase> client = es_client_;
    if (client) {
      dispatch_async(q_, ^{
        [client clearCache];
      });
    }
  }

  [flush_count_ incrementForFieldValues:@[ FlushCacheReasonToString(reason) ]];
}

NSArray<NSNumber*>* AuthResultCache::CacheCounts() {
  return @[ @(root_cache_->count()), @(nonroot_cache_->count()) ];
}

void AuthResultCache::SetESClient(id<SNTEndpointSecurityClientBase> client) {
  es_client_ = client;
}

}  // namespace santa
