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

#ifndef SANTA_SANTAD_SANDBOXEXPECTATIONS_H
#define SANTA_SANTAD_SANDBOXEXPECTATIONS_H

#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/synchronization/mutex.h"

@class SNTSandboxExecRequest;

namespace santa {

class SandboxExpectations {
 public:
  static constexpr size_t kMaxEntries = 128;
  static constexpr uint64_t kTTLNanos = 30ULL * 1000ULL * 1000ULL * 1000ULL;

  enum class RegisterResult {
    kOk,
    kDuplicate,         // An entry already exists for this (pid, pidversion).
    kCapacityExceeded,  // The map is at kMaxEntries after sweeping expired entries.
  };

  struct Expectation {
    uint64_t dev = 0;
    uint64_t ino = 0;
    std::array<uint8_t, CS_CDHASH_LEN> cdhash{};
    std::string sha256;
    uint64_t created_at_ns = 0;
  };

  SandboxExpectations();
  explicit SandboxExpectations(std::function<uint64_t()> clock);

  SandboxExpectations(const SandboxExpectations&) = delete;
  SandboxExpectations& operator=(const SandboxExpectations&) = delete;

  // Register an expectation for |token|, copying (dev, ino, cdhash, sha256)
  // from |request|. Sweeps expired entries first, then inserts unless an
  // entry for this token already exists or the map is at capacity — callers
  // switch on RegisterResult to distinguish these cases.
  // |request.identifiers.cdhashBytes| is copied only when exactly
  // CS_CDHASH_LEN bytes long (signed binaries); unsigned binaries leave the
  // stored cdhash zero-initialized and authorize via the fallback
  // (dev, ino, sha256) branch at AUTH_EXEC. |binarySHA256| may be empty.
  //
  // Callers that register but never Consume (e.g. santactl aborts between
  // the RPC reply and execve) leave a latent entry behind; the TTL sweep
  // reclaims it on the next Register. No explicit cleanup is needed or
  // desirable: the expectation is keyed on (pid, pidversion), which is
  // retired globally when the registering process exits, so the stranded
  // entry cannot be matched by any future AUTH_EXEC.
  RegisterResult Register(const audit_token_t& token, SNTSandboxExecRequest* request);

  // Look up and remove the expectation for |token|. Returns std::nullopt if
  // absent or expired.
  std::optional<Expectation> Consume(const audit_token_t& token);

  // Sweeps then returns the current entry count. Test/debug only.
  size_t CountForTesting();

 private:
  static uint64_t KeyFromToken(const audit_token_t& token);
  void SweepExpiredLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(mu_);

  std::function<uint64_t()> clock_;
  mutable absl::Mutex mu_;
  absl::flat_hash_map<uint64_t, Expectation> entries_ ABSL_GUARDED_BY(mu_);
};

}  // namespace santa

#endif  // SANTA_SANTAD_SANDBOXEXPECTATIONS_H
