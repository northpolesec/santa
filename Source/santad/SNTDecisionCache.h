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

#include <sys/stat.h>

#import <Foundation/Foundation.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SantaVnode.h"
#include "Source/santad/EntitlementsFilter.h"

@interface SNTDecisionCache : NSObject

+ (instancetype)sharedCache;

- (bool)cacheDecision:(SNTCachedDecision*)cd;
- (SNTCachedDecision*)cachedDecisionForFile:(const struct stat&)statInfo;
- (SNTCachedDecision*)cachedDecisionForVnode:(SantaVnode)vnode;
- (void)forgetCachedDecisionForVnode:(SantaVnode)vnode;
- (SNTCachedDecision*)resetTimestampForCachedDecision:(const struct stat&)statInfo;
// Must be called exactly once, during daemon initialization, before any
// rehydrate or backfill caller can run. Subsequent calls trip an assert —
// the filter is not atomically swappable. Reads on other threads are
// unsynchronized and rely on this set-once contract plus the happens-before
// edges established by ES client enablement and the initial backfill
// dispatch.
- (void)setEntitlementsFilter:(std::shared_ptr<santa::EntitlementsFilter>)filter;
- (void)backfillDecisionCacheAsync;
// Synchronously hashes `fi` and inserts a pseudo-decision into the cache.
// Caller contract: invoke only after observing a cache miss for `fi.vnode`
// and only when the file is small enough that the SHA-256 fits within the
// ES auth deadline budget. The implementation does NOT deduplicate
// concurrent callers — two threads that both miss the cache for the same
// vnode will both hash; first writer wins the cache insert and the loser's
// decision is discarded. The redundant hash is bounded by the caller's
// size cap and the dedup cost (per-vnode in-flight tracking) is not worth
// it for the rate at which collisions actually occur on the AUTH path.
- (SNTCachedDecision*)rehydrateAndCacheDecisionForFileInfo:(SNTFileInfo*)fi;
// Dispatches a background rehydrate. Per-vnode in-flight dedup is applied
// so repeated calls for the same vnode while a rehydrate is enqueued or
// running are coalesced.
- (void)asyncRehydrateAndCacheDecisionForFileInfo:(SNTFileInfo*)fi;

@end
