/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__COMMON__AUDITUTILITIES_H
#define SANTA__COMMON__AUDITUTILITIES_H

#include <bsm/libbsm.h>

#include <utility>

namespace santa {

static inline pid_t Pid(const audit_token_t &tok) {
  return audit_token_to_pid(tok);
}

static inline int Pidversion(const audit_token_t &tok) {
  return audit_token_to_pidversion(tok);
}

static inline uid_t RealUser(const audit_token_t &tok) {
  return audit_token_to_ruid(tok);
}

static inline gid_t RealGroup(const audit_token_t &tok) {
  return audit_token_to_rgid(tok);
}

static inline uid_t EffectiveUser(const audit_token_t &tok) {
  return audit_token_to_euid(tok);
}

static inline gid_t EffectiveGroup(const audit_token_t &tok) {
  return audit_token_to_egid(tok);
}

static inline std::pair<pid_t, int> PidPidversion(const audit_token_t &tok) {
  return {Pid(tok), Pidversion(tok)};
}

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

}  // namespace santa

#endif  // SANTA__COMMON__AUDITUTILITIES_H
