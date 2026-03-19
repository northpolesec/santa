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
#include <dispatch/dispatch.h>
#include <sys/stat.h>
#include <memory>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/common/SantaCache.h"
#import "Source/common/SantaVnode.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#import "Source/common/es/SNTEndpointSecurityClientBase.h"

@class SNTCachedDecision;

namespace santa {

struct CachedAuthResult {
  SNTAction action = SNTActionUnset;
  uint64_t timestamp = 0;
  SNTCachedDecision *cached_decision = nil;

  // For equality purposes, only the SNTAction and timestamp are considered.
  bool operator==(const CachedAuthResult &rhs) const {
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
};

class AuthResultCache {
 public:
  // Santa currently only flushes caches when new DENY rules are added, not
  // ALLOW rules. This means cache_deny_time_ms should be low enough so that if a
  // previously denied binary is allowed, it can be re-executed by the user in a
  // timely manner. But the value should be high enough to allow the cache to be
  // effective in the event the binary is executed in rapid succession.
  static std::unique_ptr<AuthResultCache> Create(std::shared_ptr<santa::EndpointSecurityAPI> esapi,
                                                 SNTMetricSet *metric_set,
                                                 uint64_t cache_deny_time_ms = 1500);

  AuthResultCache(std::shared_ptr<santa::EndpointSecurityAPI> esapi, SNTMetricCounter *flush_count,
                  uint64_t cache_deny_time_ms = 1500);
  virtual ~AuthResultCache();

  AuthResultCache(AuthResultCache &&other) = delete;
  AuthResultCache &operator=(AuthResultCache &&rhs) = delete;
  AuthResultCache(const AuthResultCache &other) = delete;
  AuthResultCache &operator=(const AuthResultCache &other) = delete;

  virtual bool AddToCache(const es_file_t *es_file, SNTAction decision,
                          SNTCachedDecision *cd = nil);
  virtual void RemoveFromCache(const es_file_t *es_file);
  virtual CachedAuthResult CheckCache(const es_file_t *es_file);
  virtual CachedAuthResult CheckCache(SantaVnode vnode_id);

  virtual void FlushCache(FlushCacheMode mode, FlushCacheReason reason);

  virtual NSArray<NSNumber *> *CacheCounts();

  virtual void SetESClient(id<SNTEndpointSecurityClientBase> client);

 private:
  virtual SantaCache<SantaVnode, CachedAuthResult> *CacheForVnodeID(SantaVnode vnode_id);

  SantaCache<SantaVnode, CachedAuthResult> *root_cache_;
  SantaCache<SantaVnode, CachedAuthResult> *nonroot_cache_;

  std::shared_ptr<santa::EndpointSecurityAPI> esapi_;
  SNTMetricCounter *flush_count_;
  uint64_t root_devno_;
  uint64_t cache_deny_time_ns_;
  dispatch_queue_t q_;
  __weak id<SNTEndpointSecurityClientBase> es_client_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_EVENTPROVIDERS_AUTHRESULTCACHE_H
