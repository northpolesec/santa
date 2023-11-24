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

#ifndef SANTA__COMMON__XXHASH_H
#define SANTA__COMMON__XXHASH_H

#define XXH_STATIC_LINKING_ONLY
#include <string>

#include "xxhash.h"

namespace santa {

class Xxhash {
 public:
  Xxhash() { XXH3_128bits_reset(&state_); }

  Xxhash(const Xxhash &existingState) {
    XXH3_copyState(&state_, &existingState.state_);
  }

  void Update(const void *data, size_t size) {
    XXH3_128bits_update(&state_, data, size);
  }

  std::string Digest() {
    XXH128_hash_t hash = XXH3_128bits_digest(&state_);
    XXH128_canonical_t canonical_hash;
    XXH128_canonicalFromHash(&canonical_hash, hash);

    // Hex encode
    static_assert(sizeof(XXH128_canonical_t) == 16);
    char operation_id[sizeof(XXH128_canonical_t) * 2 + 1];
    CanonicalHashToHex(&canonical_hash, operation_id);

    return std::string(operation_id, sizeof(XXH128_canonical_t) * 2);
  }

  static inline void CanonicalHashToHex(const XXH128_canonical_t *canonical,
                                        char *output) {
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

 private:
  XXH3_state_t state_;
};

}  // namespace santa

#endif  // SANTA__COMMON__XXHASH_H
