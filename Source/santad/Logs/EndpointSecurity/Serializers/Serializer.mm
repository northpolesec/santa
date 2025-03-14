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

#define XXH_STATIC_LINKING_ONLY
#include "xxhash.h"

namespace santa {

Serializer::Serializer(SNTDecisionCache *decision_cache) : decision_cache_(decision_cache) {
  if ([[SNTConfigurator configurator] enableMachineIDDecoration]) {
    enabled_machine_id_ = true;
    machine_id_ = [[[SNTConfigurator configurator] machineID] UTF8String] ?: "";
  }

  // Prime the xxHash state with invariant data
  common_hash_state_ = XXH3_createState();
  XXH3_128bits_reset(common_hash_state_);
  std::string_view uuid = NSStringToUTF8StringView([SNTSystemInfo bootSessionUUID]);
  XXH3_128bits_update(common_hash_state_, uuid.data(), uuid.length());
}

Serializer::~Serializer() {
  XXH3_freeState(common_hash_state_);
}

bool Serializer::EnabledMachineID() {
  return enabled_machine_id_;
}

std::string_view Serializer::MachineID() {
  return std::string_view(machine_id_);
};

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

static inline void CanonicalHashToHex(const XXH128_canonical_t *canonical, char *output) {
  static const char hex_digits[] = "0123456789abcdef";
  const unsigned char *digest = canonical->digest;

  // Fully unrolled loop for better performance
  output[0] = hex_digits[digest[0] >> 4];
  output[1] = hex_digits[digest[0] & 0xF];
  output[2] = hex_digits[digest[1] >> 4];
  output[3] = hex_digits[digest[1] & 0xF];
  output[4] = hex_digits[digest[2] >> 4];
  output[5] = hex_digits[digest[2] & 0xF];
  output[6] = hex_digits[digest[3] >> 4];
  output[7] = hex_digits[digest[3] & 0xF];
  output[8] = hex_digits[digest[4] >> 4];
  output[9] = hex_digits[digest[4] & 0xF];
  output[10] = hex_digits[digest[5] >> 4];
  output[11] = hex_digits[digest[5] & 0xF];
  output[12] = hex_digits[digest[6] >> 4];
  output[13] = hex_digits[digest[6] & 0xF];
  output[14] = hex_digits[digest[7] >> 4];
  output[15] = hex_digits[digest[7] & 0xF];
  output[16] = hex_digits[digest[8] >> 4];
  output[17] = hex_digits[digest[8] & 0xF];
  output[18] = hex_digits[digest[9] >> 4];
  output[19] = hex_digits[digest[9] & 0xF];
  output[20] = hex_digits[digest[10] >> 4];
  output[21] = hex_digits[digest[10] & 0xF];
  output[22] = hex_digits[digest[11] >> 4];
  output[23] = hex_digits[digest[11] & 0xF];
  output[24] = hex_digits[digest[12] >> 4];
  output[25] = hex_digits[digest[12] & 0xF];
  output[26] = hex_digits[digest[13] >> 4];
  output[27] = hex_digits[digest[13] & 0xF];
  output[28] = hex_digits[digest[14] >> 4];
  output[29] = hex_digits[digest[14] & 0xF];
  output[30] = hex_digits[digest[15] >> 4];
  output[31] = hex_digits[digest[15] & 0xF];

  output[32] = '\0';
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
  XXH3_state_t state;
  XXH3_copyState(&state, common_hash_state_);

  // Consume the variant data and create a digest
  XXH3_128bits_update(&state, &operation_id_data, sizeof(operation_id_data));
  XXH128_hash_t hash = XXH3_128bits_digest(&state);

  // Convert to canonical representation
  XXH128_canonical_t canonical_hash;
  XXH128_canonicalFromHash(&canonical_hash, hash);

  // Hex encode
  static_assert(sizeof(XXH128_canonical_t) == 16);
  char operation_id[sizeof(XXH128_canonical_t) * 2 + 1];
  CanonicalHashToHex(&canonical_hash, operation_id);

  return SerializeFileAccess(policy_version, policy_name, msg, enriched_process, target, decision,
                             std::string_view(operation_id, sizeof(XXH128_canonical_t) * 2));
}

};  // namespace santa
