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

#ifndef SANTA_COMMON_AUDITUTILITIES_H
#define SANTA_COMMON_AUDITUTILITIES_H

#include <bsm/libbsm.h>

#include <cstdint>
#include <optional>
#include <utility>

@class NSData;

namespace santa {

static inline pid_t Pid(const audit_token_t& tok) {
  return audit_token_to_pid(tok);
}

static inline int Pidversion(const audit_token_t& tok) {
  return audit_token_to_pidversion(tok);
}

static inline uid_t RealUser(const audit_token_t& tok) {
  return audit_token_to_ruid(tok);
}

static inline gid_t RealGroup(const audit_token_t& tok) {
  return audit_token_to_rgid(tok);
}

static inline uid_t EffectiveUser(const audit_token_t& tok) {
  return audit_token_to_euid(tok);
}

static inline gid_t EffectiveGroup(const audit_token_t& tok) {
  return audit_token_to_egid(tok);
}

static inline std::pair<pid_t, int> PidPidversion(const audit_token_t& tok) {
  return {Pid(tok), Pidversion(tok)};
}

// Runtime identity of a process: pid + pidversion, so a recycled pid can't
// alias a dead one. Value type; usable directly as a hash-map key.
struct ProcessID {
  pid_t pid = 0;
  int pidversion = 0;

  static ProcessID FromToken(const audit_token_t& tok) { return {Pid(tok), Pidversion(tok)}; }
  // Defined in AuditUtilities.mm. nullopt if the data is too short to hold an
  // audit_token_t. Used for NetworkExtension flows whose sourceAppAuditToken
  // is delivered as NSData.
  static std::optional<ProcessID> FromTokenData(NSData* tokenData);

  // Stable 64-bit packing for callers that need a scalar handle (e.g. the
  // NSNumber on the flow-event wire). Not needed to use this as a key.
  constexpr uint64_t Packed() const {
    return (static_cast<uint64_t>(static_cast<uint32_t>(pid)) << 32) |
           static_cast<uint32_t>(pidversion);
  }

  friend bool operator==(const ProcessID& a, const ProcessID& b) {
    return a.pid == b.pid && a.pidversion == b.pidversion;
  }
  template <typename H>
  friend H AbslHashValue(H h, const ProcessID& p) {
    return H::combine(std::move(h), p.pid, p.pidversion);
  }
};

static inline audit_token_t MakeStubAuditToken(pid_t pid, int pidver) {
  return audit_token_t{
      .val =
          {
              0,
              0,
              0,
              0,
              0,
              (unsigned int)pid,
              0,
              (unsigned int)pidver,
          },
  };
}

std::optional<audit_token_t> GetMyAuditToken();

/// Look up the current audit token for a running process by pid.
/// Uses mach task ports: task_name_for_pid + task_info(TASK_AUDIT_TOKEN).
/// Returns false if the process doesn't exist or the lookup fails.
bool AuditTokenForPid(pid_t pid, audit_token_t* token);

}  // namespace santa

#endif  // SANTA_COMMON_AUDITUTILITIES_H
