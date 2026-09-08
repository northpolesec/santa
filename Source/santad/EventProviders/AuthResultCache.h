/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA_SANTAD_EVENTPROVIDERS_AUTHRESULTCACHE_H
#define SANTA_SANTAD_EVENTPROVIDERS_AUTHRESULTCACHE_H

#include <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#include <dispatch/dispatch.h>
#include <mach/machine.h>
#include <sys/stat.h>
#include <array>
#include <memory>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/common/SantaCache.h"
#import "Source/common/SantaVnode.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#import "Source/common/es/SNTEndpointSecurityClientBase.h"

@class SNTCachedDecision;

namespace santa {

struct AuthResultKey {
  SantaVnode vnode = {};
  cpu_type_t cputype = 0;
  cpu_subtype_t cpusubtype = 0;

  bool operator==(const AuthResultKey& rhs) const {
    return vnode == rhs.vnode && cputype == rhs.cputype && cpusubtype == rhs.cpusubtype;
  }

  template <typename H>
  friend H AbslHashValue(H h, const AuthResultKey& k) {
    return H::combine(std::move(h), k.vnode, k.cputype, k.cpusubtype);
  }
};

struct ExecIdentity {
  std::array<uint8_t, CS_CDHASH_LEN> cdhash = {};
  struct timespec mtime = {};
  struct timespec ctime = {};
  struct timespec btime = {};
  off_t size = 0;

  bool operator==(const ExecIdentity& rhs) const {
    auto ts_eq = [](const struct timespec& a, const struct timespec& b) {
      return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
    };
    return cdhash == rhs.cdhash && size == rhs.size && ts_eq(mtime, rhs.mtime) &&
           ts_eq(ctime, rhs.ctime) && ts_eq(btime, rhs.btime);
  }
};

// The full description of an exec target for cache purposes: where it lives
// (key), what content identity was observed at exec time (identity), and
// whether the kernel enforces page integrity for it (CS_VALID with CS_HARD or
// CS_KILL; see CdhashStrictlyEnforced).
struct ExecTarget {
  AuthResultKey key;
  ExecIdentity identity;
  bool enforced = false;

  static ExecTarget ForExecEvent(const es_message_t* msg);
};

struct CachedAuthResult {
  SNTAction action = SNTActionUnset;
  uint64_t timestamp = 0;
  SNTCachedDecision* cached_decision = nil;
  // Identity is deliberately excluded from operator==: the SantaCache CAS
  // transitions compare action+timestamp only.
  ExecIdentity identity;

  // For equality purposes, only the SNTAction and timestamp are considered.
  bool operator==(const CachedAuthResult& rhs) const {
    return action == rhs.action && timestamp == rhs.timestamp;
  }
};

enum class FlushCacheMode {
  kNonRootOnly,
  kAllCaches,
};

enum class FlushCacheReason {
  kClientModeChanged,
  kPathRegexChanged,
  kRulesChanged,
  kStaticRulesChanged,
  kExplicitCommand,
  kFilesystemUnmounted,
  kEntitlementsPrefixFilterChanged,
  kEntitlementsTeamIDFilterChanged,
  kCELFallbackRulesChanged,
  kTransitiveRulesChanged,
};

// Caches authorization decisions for exec targets.
//
// Entries are keyed by (vnode, cpu slice) and, on every hit, verified against
// the identity observed for the current exec target: the cdhash plus the
// file's mtime/ctime/btime and size. A mismatch is not a hit; the entry is
// removed and the exec is re-evaluated. A vnode is a location, not a name for
// content, so the key alone is never sufficient to serve an entry.
//
// The identity fields do not all carry equal weight, and which of them are
// meaningful depends on the target.
//
// Verification happens on the hit, synchronously with the exec, which is why
// there is deliberately no event-driven invalidation here. Do not add any: an
// out-of-band invalidation path is strictly weaker than the check on the hit.
class AuthResultCache {
 public:
  // Santa currently only flushes caches when new DENY rules are added, not
  // ALLOW rules. This means cache_deny_time_ms should be low enough so that if a
  // previously denied binary is allowed, it can be re-executed by the user in a
  // timely manner. But the value should be high enough to allow the cache to be
  // effective in the event the binary is executed in rapid succession.
  static std::unique_ptr<AuthResultCache> Create(std::shared_ptr<santa::EndpointSecurityAPI> esapi,
                                                 SNTMetricSet* metric_set,
                                                 uint64_t cache_deny_time_ms = 1500);

  AuthResultCache(std::shared_ptr<santa::EndpointSecurityAPI> esapi, SNTMetricCounter* flush_count,
                  uint64_t cache_deny_time_ms = 1500);
  virtual ~AuthResultCache();

  AuthResultCache(AuthResultCache&& other) = delete;
  AuthResultCache& operator=(AuthResultCache&& rhs) = delete;
  AuthResultCache(const AuthResultCache& other) = delete;
  AuthResultCache& operator=(const AuthResultCache& other) = delete;

  virtual bool AddToCache(const ExecTarget& target, SNTAction decision,
                          SNTCachedDecision* cd = nil);
  virtual void RemoveFromCache(const ExecTarget& target);
  virtual CachedAuthResult CheckCache(const ExecTarget& target);
  // Diagnostic only (santactl checkcache): scans every entry under all bucket
  // locks. Never call on the hot path.
  virtual CachedAuthResult CheckCacheForVnode(SantaVnode vnode);

  virtual void FlushCache(FlushCacheMode mode, FlushCacheReason reason);

  virtual NSArray<NSNumber*>* CacheCounts();

  virtual void SetESClient(id<SNTEndpointSecurityClientBase> client);

 private:
  virtual SantaCache<AuthResultKey, CachedAuthResult>* CacheForVnodeID(SantaVnode vnode_id);

  SantaCache<AuthResultKey, CachedAuthResult>* root_cache_;
  SantaCache<AuthResultKey, CachedAuthResult>* nonroot_cache_;

  std::shared_ptr<santa::EndpointSecurityAPI> esapi_;
  SNTMetricCounter* flush_count_;
  uint64_t root_devno_;
  uint64_t cache_deny_time_ns_;
  dispatch_queue_t q_;
  __weak id<SNTEndpointSecurityClientBase> es_client_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_EVENTPROVIDERS_AUTHRESULTCACHE_H
