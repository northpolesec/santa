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

#import "Source/santad/SandboxedLineage.h"

namespace santa {

uint64_t SandboxedLineage::KeyFromToken(const audit_token_t& token) {
  uint64_t pid = static_cast<uint64_t>(audit_token_to_pid(token));
  uint64_t pidver = static_cast<uint64_t>(audit_token_to_pidversion(token));
  return (pidver << 32) | (pid & 0xFFFFFFFFULL);
}

bool SandboxedLineage::Mark(const audit_token_t& token) {
  absl::MutexLock lock(mu_);
  if (entries_.size() >= kMaxEntries && !entries_.contains(KeyFromToken(token))) {
    return false;
  }
  entries_.insert(KeyFromToken(token));
  return true;
}

bool SandboxedLineage::Contains(const audit_token_t& token) const {
  absl::MutexLock lock(mu_);
  return entries_.contains(KeyFromToken(token));
}

void SandboxedLineage::Forget(const audit_token_t& token) {
  absl::MutexLock lock(mu_);
  entries_.erase(KeyFromToken(token));
}

bool SandboxedLineage::PropagateOnFork(const audit_token_t& parent, const audit_token_t& child) {
  absl::MutexLock lock(mu_);
  if (!entries_.contains(KeyFromToken(parent))) return false;
  if (entries_.size() >= kMaxEntries && !entries_.contains(KeyFromToken(child))) {
    return false;
  }
  entries_.insert(KeyFromToken(child));
  return true;
}

bool SandboxedLineage::OnExec(const audit_token_t& pre, const audit_token_t& post) {
  absl::MutexLock lock(mu_);
  uint64_t pre_key = KeyFromToken(pre);
  if (!entries_.contains(pre_key)) return false;
  entries_.erase(pre_key);
  // Erase made room; insert always fits even at the prior cap.
  entries_.insert(KeyFromToken(post));
  return true;
}

size_t SandboxedLineage::CountForTesting() const {
  absl::MutexLock lock(mu_);
  return entries_.size();
}

}  // namespace santa
