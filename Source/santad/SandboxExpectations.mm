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

#import "Source/santad/SandboxExpectations.h"

#include <time.h>

#include <cstring>

#import "Source/common/SNTSandboxExecRequest.h"
#include "Source/common/String.h"

namespace santa {

namespace {
uint64_t DefaultMonotonicNanos() {
  return clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW_APPROX);
}
}  // namespace

SandboxExpectations::SandboxExpectations() : clock_(DefaultMonotonicNanos) {}

SandboxExpectations::SandboxExpectations(std::function<uint64_t()> clock)
    : clock_(std::move(clock)) {}

uint64_t SandboxExpectations::KeyFromToken(const audit_token_t& token) {
  uint64_t pid = static_cast<uint64_t>(audit_token_to_pid(token));
  uint64_t pidver = static_cast<uint64_t>(audit_token_to_pidversion(token));
  return (pidver << 32) | (pid & 0xFFFFFFFFULL);
}

void SandboxExpectations::SweepExpiredLocked() {
  uint64_t now = clock_();
  absl::erase_if(entries_,
                 [now](const auto& kv) { return now - kv.second.created_at_ns > kTTLNanos; });
}

SandboxExpectations::RegisterResult SandboxExpectations::Register(const audit_token_t& token,
                                                                  SNTSandboxExecRequest* request) {
  Expectation e;
  e.dev = request.fsDev;
  e.ino = request.fsIno;
  // cdhash is copied only for signed binaries (cdhashBytes is exactly
  // CS_CDHASH_LEN bytes). Unsigned binaries leave e.cdhash zero-initialized;
  // they always fall to the fallback branch at AUTH_EXEC, so the strict
  // cdhash comparison never fires for them.
  NSData* cdhashBytes = request.identifiers.cdhashBytes;
  if (cdhashBytes.length == CS_CDHASH_LEN) {
    std::memcpy(e.cdhash.data(), cdhashBytes.bytes, CS_CDHASH_LEN);
  }
  e.sha256 = santa::NSStringToUTF8String(request.identifiers.binarySHA256);
  e.created_at_ns = clock_();

  absl::MutexLock lock(mu_);
  SweepExpiredLocked();

  uint64_t key = KeyFromToken(token);
  if (entries_.contains(key)) return RegisterResult::kDuplicate;
  if (entries_.size() >= kMaxEntries) return RegisterResult::kCapacityExceeded;

  entries_.emplace(key, std::move(e));
  return RegisterResult::kOk;
}

std::optional<SandboxExpectations::Expectation> SandboxExpectations::Consume(
    const audit_token_t& token) {
  // Consume runs on the AUTH_EXEC hot path and must return quickly. It only
  // checks TTL on the specific entry being looked up; a stranded-entry
  // expired under a different key is irrelevant to this request and can
  // wait for the next Register to be swept.
  absl::MutexLock lock(mu_);
  uint64_t key = KeyFromToken(token);
  auto it = entries_.find(key);
  if (it == entries_.end()) return std::nullopt;
  if (clock_() - it->second.created_at_ns > kTTLNanos) {
    entries_.erase(it);
    return std::nullopt;
  }
  Expectation out = std::move(it->second);
  entries_.erase(it);
  return out;
}

size_t SandboxExpectations::CountForTesting() {
  absl::MutexLock lock(mu_);
  SweepExpiredLocked();
  return entries_.size();
}

}  // namespace santa
