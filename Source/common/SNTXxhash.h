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

using ResetFunc = XXH_errorcode (*)(XXH3_state_t *);
using UpdateFunc = XXH_errorcode (*)(XXH3_state_t *, const void *, size_t);
using DigestFunc64 = XXH64_hash_t (*)(const XXH3_state_t *);
using DigestFunc128 = XXH128_hash_t (*)(const XXH3_state_t *);
using CanonicalFunc64 = void (*)(XXH64_canonical_t *, XXH64_hash_t);
using CanonicalFunc128 = void (*)(XXH128_canonical_t *, XXH128_hash_t);

struct XxhashFuncPtrs64 {
  static constexpr ResetFunc Reset = XXH3_64bits_reset;
  static constexpr UpdateFunc Update = XXH3_64bits_update;
  static constexpr DigestFunc64 Digest = XXH3_64bits_digest;
  static constexpr CanonicalFunc64 CanonicalFromHash = XXH64_canonicalFromHash;
  using hash_type = XXH64_hash_t;
  using canonical_type = XXH64_canonical_t;
};

struct XxhashFuncPtrs128 {
  static constexpr ResetFunc Reset = XXH3_128bits_reset;
  static constexpr UpdateFunc Update = XXH3_128bits_update;
  static constexpr DigestFunc128 Digest = XXH3_128bits_digest;
  static constexpr CanonicalFunc128 CanonicalFromHash =
      XXH128_canonicalFromHash;
  using hash_type = XXH128_hash_t;
  using canonical_type = XXH128_canonical_t;
};

template <typename XxhashFuncPtrs>
class Xxhash {
 public:
  using hash_type = typename XxhashFuncPtrs::hash_type;
  using canonical_type = typename XxhashFuncPtrs::canonical_type;

  Xxhash() { XxhashFuncPtrs::Reset(&state_); }

  Xxhash(const Xxhash &existingState) {
    XXH3_copyState(&state_, &existingState.state_);
  }

  void Update(const void *data, size_t size) {
    XxhashFuncPtrs::Update(&state_, data, size);
  }

  std::string Digest() {
    hash_type hash = XxhashFuncPtrs::Digest(&state_);
    canonical_type canonical_hash;
    XxhashFuncPtrs::CanonicalFromHash(&canonical_hash, hash);

    // Hex encode
    char operation_id[sizeof(canonical_type) * 2 + 1];
    CanonicalHashToHex(&canonical_hash, operation_id);

    return std::string(operation_id, sizeof(canonical_type) * 2);
  }

  static inline void CanonicalHashToHex(const canonical_type *canonical,
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
    if constexpr (sizeof(canonical_type) == 16) {
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
    } else {
      // Fallback for unexpected sizes (should not happen with current types)
      static_assert(sizeof(canonical_type) == 8 || sizeof(canonical_type) == 16,
                    "Unsupported canonical type size");
    }

    output[sizeof(canonical_type) * 2] = '\0';
  }

 private:
  XXH3_state_t state_;
};

using Xxhash64 = Xxhash<XxhashFuncPtrs64>;
using Xxhash128 = Xxhash<XxhashFuncPtrs128>;

}  // namespace santa

#endif  // SANTA__COMMON__XXHASH_H
