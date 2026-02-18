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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_BASICSTRING_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_SERIALIZERS_BASICSTRING_H

#import <Foundation/Foundation.h>
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

#include <memory>
#include <sstream>
#include <vector>

#include "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#import "Source/santad/SNTDecisionCache.h"

namespace santa {

class BasicString : public Serializer {
 public:
  static std::shared_ptr<BasicString> Create(std::shared_ptr<santa::EndpointSecurityAPI> esapi,
                                             SNTDecisionCache *decision_cache,
                                             bool prefix_time_name = true);

  BasicString(std::shared_ptr<santa::EndpointSecurityAPI> esapi, SNTDecisionCache *decision_cache,
              bool prefix_time_name);

  std::vector<uint8_t> SerializeMessage(const santa::EnrichedClose &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedExchange &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedExec &, SNTCachedDecision *) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedExit &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedFork &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLink &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedRename &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedUnlink &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedCSInvalidated &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedClone &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedCopyfile &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionLogin &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionLogout &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionLock &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginWindowSessionUnlock &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedScreenSharingAttach &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedScreenSharingDetach &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedOpenSSHLogin &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedOpenSSHLogout &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginLogin &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLoginLogout &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedAuthenticationOD &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedAuthenticationTouchID &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedAuthenticationToken &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedAuthenticationAutoUnlock &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedLaunchItem &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedXProtectDetected &) override;
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedXProtectRemediated &) override;
#if HAVE_MACOS_15
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedGatekeeperOverride &) override;
#endif  // HAVE_MACOS_15
#if HAVE_MACOS_15_4
  std::vector<uint8_t> SerializeMessage(const santa::EnrichedTCCModification &) override;
#endif  // HAVE_MACOS_15_4

  std::vector<uint8_t> SerializeNetworkFlow(SNDProcessInfo *, SNDFlowInfo *, struct timespec,
                                            struct timespec, SNTCachedDecision *) override;

  std::vector<uint8_t> SerializeFileAccess(
      const std::string &policy_version, const std::string &policy_name, const santa::Message &msg,
      const santa::EnrichedProcess &enriched_process, size_t target_index,
      std::optional<santa::EnrichedFile> enriched_event_target, FileAccessPolicyDecision decision,
      std::string_view operation_id) override;

  std::vector<uint8_t> SerializeAllowlist(const santa::Message &, const std::string_view) override;

  std::vector<uint8_t> SerializeBundleHashingEvent(SNTStoredExecutionEvent *) override;

  std::vector<uint8_t> SerializeDiskAppeared(NSDictionary *, bool) override;
  std::vector<uint8_t> SerializeDiskDisappeared(NSDictionary *) override;

 private:
  std::string CreateDefaultString(size_t reserved_size = 512);
  std::vector<uint8_t> FinalizeString(std::string &str);

  std::vector<uint8_t> SerializeMessageLaunchItemAdd(const santa::EnrichedLaunchItem &);
  std::vector<uint8_t> SerializeMessageLaunchItemRemove(const santa::EnrichedLaunchItem &);

  std::shared_ptr<santa::EndpointSecurityAPI> esapi_;
  bool prefix_time_name_;
};

}  // namespace santa

#endif
