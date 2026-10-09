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

#include "Source/common/es/ESCacheFlusher.h"

#import "Source/common/SNTLogging.h"

namespace santa {

// The last OS version on which shared cache clearing was verified.
static constexpr NSOperatingSystemVersion kSharedCacheClearVerifiedThrough = {27, 0, 0};

ESCacheClearStrategy StrategyForVersion(NSOperatingSystemVersion version) {
  const NSOperatingSystemVersion& verified = kSharedCacheClearVerifiedThrough;
  bool isVerified = version.majorVersion < verified.majorVersion ||
                    (version.majorVersion == verified.majorVersion &&
                     version.minorVersion <= verified.minorVersion);
  return isVerified ? ESCacheClearStrategy::kSingleClient : ESCacheClearStrategy::kEveryClient;
}

static void ClearClient(id<SNTEndpointSecurityClientBase> client) {
  if (![client clearCache]) {
    LOGE(@"Failed to clear the ES cache for %@", client);
  }
}

std::shared_ptr<ESCacheFlusher> ESCacheFlusher::Create() {
  return std::make_shared<ESCacheFlusher>(
      StrategyForVersion([[NSProcessInfo processInfo] operatingSystemVersion]));
}

ESCacheFlusher::ESCacheFlusher(ESCacheClearStrategy strategy)
    : strategy_(strategy),
      q_(dispatch_queue_create(
          "com.northpolesec.santa.es_cache_flusher.q",
          dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                                  QOS_CLASS_USER_INTERACTIVE, 0))) {}

void ESCacheFlusher::AddClient(id<SNTEndpointSecurityClientBase> client) {
  std::shared_ptr<ESCacheFlusher> flusher = shared_from_this();
  __weak id<SNTEndpointSecurityClientBase> weakClient = client;
  dispatch_async(q_, ^{
    flusher->clients_.push_back({weakClient});
  });
}

void ESCacheFlusher::Flush(id<SNTEndpointSecurityClientBase> requester) {
  std::shared_ptr<ESCacheFlusher> flusher = shared_from_this();
  __weak id<SNTEndpointSecurityClientBase> weakRequester = requester;
  // Calling into ES must be done asynchronously since clearing synchronously
  // could otherwise potentially deadlock.
  dispatch_async(q_, ^{
    flusher->ClearClients(weakRequester);
  });
}

void ESCacheFlusher::ClearClients(id<SNTEndpointSecurityClientBase> requester) {
  switch (strategy_) {
    case ESCacheClearStrategy::kSingleClient: {
      // One clear invalidates every client's cached results, so any live client
      // can make the call.
      id<SNTEndpointSecurityClientBase> target =
          requester ?: (clients_.empty() ? nil : clients_.front().client);
      if (target) {
        ClearClient(target);
      }
      break;
    }
    case ESCacheClearStrategy::kEveryClient:
      for (const WeakClient& entry : clients_) {
        if (id<SNTEndpointSecurityClientBase> client = entry.client) {
          ClearClient(client);
        }
      }
      break;
  }
}

}  // namespace santa
