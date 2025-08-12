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

#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <assert.h>
#include <string_view>

#import "Source/common/AuditUtilities.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/String.h"
#import "Source/santad/SNTDecisionCache.h"

namespace santa {

Serializer::Serializer(SNTDecisionCache *decision_cache) : decision_cache_(decision_cache) {
  machine_id_ = std::make_shared<std::string>("");
  saved_machine_id_ = machine_id_;

  UpdateMachineID();

  // Prime the xxHash state with invariant data
  std::string_view uuid = NSStringToUTF8StringView([SNTSystemInfo bootSessionUUID]);
  common_hash_state_.Update(uuid.data(), uuid.length());
}

void Serializer::UpdateMachineID() {
  bool should_enable = [[SNTConfigurator configurator] enableMachineIDDecoration];

  if (should_enable) {
    NSString *configured_machine_id = [[SNTConfigurator configurator] machineID] ?: @"";
    auto new_machine_id = std::make_shared<std::string>([configured_machine_id UTF8String]);

    // Atomically update the shared_ptr - relaxed ordering is sufficient
    // because we separately synchronize with the enabled_machine_id_ flag
    std::atomic_store_explicit(&machine_id_, new_machine_id, std::memory_order_relaxed);

    // Keep a reference to avoid deallocation
    saved_machine_id_ = new_machine_id;

    // Use release ordering to establish happens-before relationship with readers
    enabled_machine_id_.store(true, std::memory_order_release);
  } else {
    enabled_machine_id_.store(false, std::memory_order_release);
  }
}

bool Serializer::EnableMachineIDDecoration() const {
  return enabled_machine_id_.load(std::memory_order_acquire);
}

std::shared_ptr<std::string> Serializer::MachineID() const {
  return std::atomic_load_explicit(&machine_id_, std::memory_order_relaxed);
}

std::vector<uint8_t> Serializer::SerializeMessageTemplate(const santa::EnrichedExec &msg) {
  SNTCachedDecision *cd;
  if (msg->action_type == ES_ACTION_TYPE_NOTIFY &&
      msg->action.notify.result.auth == ES_AUTH_RESULT_ALLOW) {
    // For allowed execs, cached decision timestamps must be updated
    cd = [decision_cache_ resetTimestampForCachedDecision:msg->event.exec.target->executable->stat];
  } else {
    cd = [decision_cache_ cachedDecisionForFile:msg->event.exec.target->executable->stat];
  }

  return SerializeMessage(msg, cd);
}

std::vector<uint8_t> Serializer::SerializeFileAccess(const std::string &policy_version,
                                                     const std::string &policy_name,
                                                     const santa::Message &msg,
                                                     const santa::EnrichedProcess &enriched_process,
                                                     const std::string &target,
                                                     FileAccessPolicyDecision decision) {
  // Operations are identified by:
  //   Boot Session UUID + Pid + Pidversion + Mach Time + Thread Id
  // Together, these attributes allow the same Operation ID to be computed by
  // an operation that generated events across multiple ES clients.
  // Combine variant operation id data into a small, contigious struct to minimize the
  // number of hash updates necessary.
  struct {
    pid_t pid;
    int pidver;
    uint64_t mach_time;
    uint64_t thread_id;
  } operation_id_data = {
      .pid = Pid(msg->process->audit_token),
      .pidver = Pidversion(msg->process->audit_token),
      .mach_time = msg->mach_time,
      .thread_id = msg->thread->thread_id,
  };

  // Copy the invariant state
  Xxhash state(common_hash_state_);
  state.Update(&operation_id_data, sizeof(operation_id_data));

  return SerializeFileAccess(policy_version, policy_name, msg, enriched_process, target, decision,
                             state.HexDigest());
}

};  // namespace santa
