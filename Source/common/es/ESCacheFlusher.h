/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA_COMMON_ES_ESCACHEFLUSHER_H
#define SANTA_COMMON_ES_ESCACHEFLUSHER_H

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <memory>
#include <vector>

#import "Source/common/es/SNTEndpointSecurityClientBase.h"

namespace santa {

enum class ESCacheClearStrategy {
  // Clear one client per pass. Used where one clear invalidates every
  // client's cached results.
  kSingleClient,
  // Clear every registered client per pass.
  kEveryClient,
};

// Returns kSingleClient for OS versions at or below the last version on which
// shared cache clearing was verified, and kEveryClient for every newer version.
// Only major and minor versions are compared.
ESCacheClearStrategy StrategyForVersion(NSOperatingSystemVersion version);

// Enforces consistent cache invalidation across authorization clients.
//
// Clients are held weakly. AddClient and Flush enqueue their work on one serial
// queue and return without waiting, so a returned Flush means the pass is
// scheduled, not that the caches are invalidated. Each Flush requests a single
// pass. A failed clear is logged and not attempted again.
//
// Instances must be created with std::make_shared because queued work retains
// the flusher through shared_from_this.
class ESCacheFlusher : public std::enable_shared_from_this<ESCacheFlusher> {
 public:
  static std::shared_ptr<ESCacheFlusher> Create();
  explicit ESCacheFlusher(ESCacheClearStrategy strategy);

  void AddClient(id<SNTEndpointSecurityClientBase> client);

  // Under kSingleClient, clears the requester if it is still live, otherwise
  // the first registered client. Under kEveryClient, clears every live
  // registered client and ignores the requester.
  void Flush(id<SNTEndpointSecurityClientBase> requester = nil);

 private:
  struct WeakClient {
    __weak id<SNTEndpointSecurityClientBase> client;
  };

  void ClearClients(id<SNTEndpointSecurityClientBase> requester);

  ESCacheClearStrategy strategy_;
  dispatch_queue_t q_;
  // Only accessed on q_
  std::vector<WeakClient> clients_;
};

}  // namespace santa

#endif  // SANTA_COMMON_ES_ESCACHEFLUSHER_H
