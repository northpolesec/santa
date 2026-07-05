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

#include "Source/common/CSOpsHelper.h"

#include <arpa/inet.h>
#include <bsm/libbsm.h>

#include <cstring>

#include "Source/common/String.h"

namespace santa {

namespace {

static constexpr size_t kTeamIDLength = 10;
static constexpr uint32_t kBlobWrapperOverhead = sizeof(struct csops_blob) + 1;

std::optional<std::string> CSOpsGetBlobString(pid_t pid, unsigned int op, size_t max_len,
                                              CSOpsFunc csops_func) {
  std::vector<uint8_t> buf(max_len);
  if (csops_func(pid, op, buf.data(), buf.size()) != 0) {
    return std::nullopt;
  }
  auto* blob = reinterpret_cast<csops_blob*>(buf.data());
  uint32_t data_len = ntohl(blob->len);
  if (data_len <= kBlobWrapperOverhead) {
    return std::nullopt;
  }
  return std::string(blob->data, data_len - kBlobWrapperOverhead);
}

// Adapt a token-validated csops function to the pid-keyed CSOpsFunc shape by
// binding `token`, so the token variants reuse the pid-based implementations
// (and their blob parsing) unchanged. `token` must outlive the returned
// callable; every caller below binds a local.
CSOpsFunc BindToken(audit_token_t* token, CSOpsTokenFunc csops_func) {
  return [token, csops_func = std::move(csops_func)](pid_t pid, unsigned int ops, void* addr,
                                                     size_t size) {
    return csops_func(pid, ops, addr, size, token);
  };
}

}  // namespace

std::optional<uint32_t> CSOpsStatusFlags(pid_t pid, CSOpsFunc csops_func) {
  uint32_t flags = 0;
  if (csops_func(pid, kCsopStatus, &flags, sizeof(flags)) != 0) {
    return std::nullopt;
  }
  return flags;
}

std::optional<std::string> CSOpsGetCDHash(pid_t pid, CSOpsFunc csops_func) {
  std::vector<uint8_t> cdhash(CS_CDHASH_LEN);
  if (csops_func(pid, kCsopCDHash, cdhash.data(), cdhash.size()) != 0) {
    return std::nullopt;
  }
  std::string hex = BufToHexString(cdhash.data(), cdhash.size());
  if (hex.size() != CS_CDHASH_LEN * 2) {
    return std::nullopt;
  }
  return hex;
}

std::optional<std::string> CSOpsGetTeamID(pid_t pid, CSOpsFunc csops_func) {
  auto result = CSOpsGetBlobString(pid, kCsopTeamID, 256, std::move(csops_func));
  if (result && result->size() != kTeamIDLength) {
    return std::nullopt;
  }
  return result;
}

std::optional<std::string> CSOpsGetSigningID(pid_t pid, CSOpsFunc csops_func) {
  auto result = CSOpsGetBlobString(pid, kCsopIdentity, 1024, std::move(csops_func));
  if (result && result->empty()) {
    return std::nullopt;
  }
  return result;
}

std::optional<uint32_t> CSOpsStatusFlags(const audit_token_t& tok, CSOpsTokenFunc csops_func) {
  audit_token_t token = tok;  // csops_audittoken takes a mutable pointer
  return CSOpsStatusFlags(audit_token_to_pid(token), BindToken(&token, std::move(csops_func)));
}

std::optional<std::string> CSOpsGetCDHash(const audit_token_t& tok, CSOpsTokenFunc csops_func) {
  audit_token_t token = tok;
  return CSOpsGetCDHash(audit_token_to_pid(token), BindToken(&token, std::move(csops_func)));
}

std::optional<std::string> CSOpsGetTeamID(const audit_token_t& tok, CSOpsTokenFunc csops_func) {
  audit_token_t token = tok;
  return CSOpsGetTeamID(audit_token_to_pid(token), BindToken(&token, std::move(csops_func)));
}

std::optional<std::string> CSOpsGetSigningID(const audit_token_t& tok, CSOpsTokenFunc csops_func) {
  audit_token_t token = tok;
  return CSOpsGetSigningID(audit_token_to_pid(token), BindToken(&token, std::move(csops_func)));
}

}  // namespace santa
