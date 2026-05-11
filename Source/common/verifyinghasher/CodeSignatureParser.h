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

#ifndef SANTA_COMMON_VERIFYINGHASHER_CODESIGNATUREPARSER_H
#define SANTA_COMMON_VERIFYINGHASHER_CODESIGNATUREPARSER_H

#include <sys/cdefs.h>

__BEGIN_DECLS
#include <Kernel/kern/cs_blobs.h>
__END_DECLS

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace santa {

// `slot_hashes` is a non-owning view into the input blob passed to
// ParseCodeSignature(); the caller must keep that blob alive for as long
// as ParsedCodeDirectory is used. `cdhash` is a fixed-size in-line array,
// owned and self-contained. VerifyingHasherCore holds parsed_cd_ alongside the
// cs_blob_buf_ that backs the view, so they share the verifier's lifetime.
struct ParsedCodeDirectory {
  uint8_t hash_type = 0;  // CS_HASHTYPE_*
  uint8_t hash_size = 0;  // 20, 32, or 48
  uint32_t page_size = 0;
  uint64_t code_limit = 0;
  uint32_t page_count = 0;
  std::span<const uint8_t> slot_hashes;  // page_count * hash_size bytes
  // 20-byte truncated cdhash of this CodeDirectory blob, computed using
  // its own hashType (matches xnu's cs_cd_hash and es_cdhash_t).
  uint8_t cdhash[CS_CDHASH_LEN] = {};
  std::string
      identifier;  // signing identifier from CD identOffset (empty if absent)
  std::string team_id;  // team id from CD teamOffset (empty if absent or
                        // pre-CS_SUPPORTSTEAMID)
};

// Parse a CS_SuperBlob already pread'd into memory. `slice_size` is used
// for the codeLimit-fits-in-slice validation. Returns true on success;
// false sets `err` to a diagnostic string.
//
// Selects the strongest available CD by hashType:
//   SHA-384 > SHA-256 > SHA-256-TRUNCATED > SHA-1
// Skips alternates of unsupported types.
bool ParseCodeSignature(std::span<const uint8_t> blob, uint64_t slice_size,
                        ParsedCodeDirectory& out, std::string& err);

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_CODESIGNATUREPARSER_H
