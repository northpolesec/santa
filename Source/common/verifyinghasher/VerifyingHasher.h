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

#ifndef SANTA_COMMON_VERIFYINGHASHER_VERIFYINGHASHER_H
#define SANTA_COMMON_VERIFYINGHASHER_VERIFYINGHASHER_H

#include <CommonCrypto/CommonDigest.h>
#include <mach/machine.h>
#include <sys/types.h>

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <span>
#include <string_view>

namespace santa {

// Public facade for FD-based code-signature verification with full-file
// SHA-256. Designed for use on the AUTH EXEC path, where the caller has
// an es_event_exec_t and an fd from SNTFileInfo.
//
// Single-observation invariant: every byte of the file is read at most
// once across a successful Run() call.
class VerifyingHasher {
 public:
  enum class Status {
    kError,             // I/O failure, not Mach-O for the requested arch,
                        // no signature when signed_check was engaged,
                        // malformed signature, page-hash mismatch, stat
                        // mismatch on the Unsigned path.
    kNoMatch,           // Verified (signed_check engaged only), internally
                        // consistent, but no match.
    kMatchCDHash,       // Computed cdhash == signed_check->cdhash.
    kMatchSidTidDrift,  // cdhash differs, but signing_id + team_id both match.
                        // Requires signed_check->team_id to be non-empty;
                        // ad-hoc binaries (empty tid) are not eligible for
                        // the drift fallback.
    kMatchUnsigned,     // signed_check was nullopt, the slice has no embedded
                        // code signature, and the file's current stat matches
                        // Expected.stat exactly across all four fields
                        // (mtime compared to nanosecond precision).
  };

  // Filesystem-identity tuple captured by ES at AUTH EXEC. The facade uses
  // stat.size as the FdFileReader size hint on every call, and additionally
  // compares all four fields against fstat(fd) on the Unsigned path for the
  // late identity check.
  struct StatTuple {
    dev_t dev;
    ino_t ino;
    off_t size;
    struct timespec mtime;
  };

  // Caller-declared expectation. Stat is always required (size feeds the
  // file reader; full tuple feeds the late stat-compare on the unsigned path).
  // signed_check is engaged on the Signed path and carries the cryptographic
  // identity fields; nullopt selects the Unsigned path.
  struct Expected {
    StatTuple stat;

    struct Signed {
      std::span<const uint8_t>
          cdhash;                   // 20 bytes (CS_CDHASH_LEN); may be empty
      std::string_view signing_id;  // may be empty
      std::string_view team_id;     // may be empty
    };
    std::optional<Signed> signed_check;
  };

  struct Result {
    Status status;
    // 32-byte SHA-256 of the full file. Engaged whenever the read reached
    // EOF — i.e., for every status except a kError that bailed before
    // reading (fstat failure or stat-tuple mismatch on the Unsigned path)
    // or originated as an I/O failure mid-read. nullopt-on-early-bail and
    // nullopt-on-I/O-error both make a Status-ignoring caller fail loudly
    // (no .value()) instead of silently consuming an unverified or
    // unfinalized digest.
    std::optional<std::array<uint8_t, CC_SHA256_DIGEST_LENGTH>> sha256;
  };

  struct RunOptions {
    // Skip per-page CodeDirectory verification while still computing the
    // full-file SHA-256, cdhash, and signing-id/team-id extraction.
    // Threaded through to VerifyingHasherCore::Options::skip_page_hash;
    // see Core's documentation for the full contract. No-op on the Unsigned
    // path — an unsigned slice has no page hashes to skip.
    bool skip_page_hash = false;
  };

  static Result Run(int fd, cpu_type_t cputype, cpu_subtype_t cpusubtype,
                    const Expected& expected, const RunOptions& opts);
  // No-options overload. (We avoid `const RunOptions& opts = {}` directly
  // on the primary declaration: brace-initializing the nested aggregate as
  // a default argument inside the enclosing class definition trips the
  // "default member initializer needed within definition of enclosing
  // class outside of member functions" rule on clang.)
  static Result Run(int fd, cpu_type_t cputype, cpu_subtype_t cpusubtype,
                    const Expected& expected) {
    return Run(fd, cputype, cpusubtype, expected, RunOptions{});
  }
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_VERIFYINGHASHER_H
