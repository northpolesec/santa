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

#ifndef SANTA_COMMON_VERIFYINGHASHER_HASHTRAITS_H
#define SANTA_COMMON_VERIFYINGHASHER_HASHTRAITS_H

#include <CommonCrypto/CommonDigest.h>
#include <sys/cdefs.h>

__BEGIN_DECLS
#include <Kernel/kern/cs_blobs.h>
__END_DECLS

#include <cstddef>
#include <cstdint>

namespace santa {

// Per-CS-hashType traits. Each struct fully describes how to verify pages
// for one CS_HASHTYPE_* value: the hash *algorithm* (Ctx, Init/Update/Final,
// kDigestSize) plus the CS *storage layout* (kSlotStride: bytes-per-slot in
// the CD blob; kCompareSize: bytes to memcmp).
//
// Note that SHA-256 and SHA-256-TRUNCATED share an algorithm but differ in
// storage: TRUNCATED computes a full 32-byte SHA-256 and stores/compares
// only the first 20 bytes. The shared algorithm lives in detail::Sha256Algo
// and is composed into both traits via inheritance.
//
// CommonCrypto's *_Update and *_Final take CC_LONG (uint32_t). The traits
// expose a thin lambda wrapper so callers can pass size_t / uint8_t* without
// casting at every call site. The wrappers are static constexpr so the
// compiler inlines them as direct calls — zero indirection.

namespace detail {

// CC_*_Update accepts CC_LONG (uint32_t). For inputs > 4 GiB the cast would
// silently truncate, corrupting the digest. Wrap the underlying CC call in
// a loop that splits inputs into UINT32_MAX-sized chunks. Returns 1 on
// success, 0 on the first underlying failure (matching CC convention).
#define VERIFYINGHASHER_CC_UPDATE_LOOP(cc_update_fn, ctx, data, len)     \
  do {                                                                   \
    const auto* vh_p = static_cast<const uint8_t*>(data);                \
    size_t vh_n = (len);                                                 \
    while (vh_n > 0) {                                                   \
      const size_t vh_step_sz = (vh_n > UINT32_MAX) ? UINT32_MAX : vh_n; \
      const CC_LONG vh_step = static_cast<CC_LONG>(vh_step_sz);          \
      const int vh_rc = cc_update_fn((ctx), vh_p, vh_step);              \
      if (vh_rc != 1) return vh_rc;                                      \
      vh_p += vh_step;                                                   \
      vh_n -= vh_step_sz;                                                \
    }                                                                    \
    return 1;                                                            \
  } while (0)

struct Sha256Algo {
  using Ctx = CC_SHA256_CTX;
  static constexpr int Init(Ctx* c) { return CC_SHA256_Init(c); }
  static constexpr int Update(Ctx* c, const void* d, size_t n) {
    VERIFYINGHASHER_CC_UPDATE_LOOP(CC_SHA256_Update, c, d, n);
  }
  static constexpr int Final(unsigned char* m, Ctx* c) {
    return CC_SHA256_Final(m, c);
  }
  static constexpr size_t kDigestSize = CC_SHA256_DIGEST_LENGTH;  // 32
};

}  // namespace detail

struct Sha1Traits {
  using Ctx = CC_SHA1_CTX;
  static constexpr int Init(Ctx* c) { return CC_SHA1_Init(c); }
  static constexpr int Update(Ctx* c, const void* d, size_t n) {
    VERIFYINGHASHER_CC_UPDATE_LOOP(CC_SHA1_Update, c, d, n);
  }
  static constexpr int Final(unsigned char* m, Ctx* c) {
    return CC_SHA1_Final(m, c);
  }
  static constexpr size_t kDigestSize = CC_SHA1_DIGEST_LENGTH;  // 20
  static constexpr size_t kSlotStride = CS_SHA1_LEN;            // 20
  static constexpr size_t kCompareSize = CS_SHA1_LEN;           // 20
  static constexpr uint8_t kCsHashType = CS_HASHTYPE_SHA1;
};

struct Sha256Traits : detail::Sha256Algo {
  static constexpr size_t kSlotStride = CS_SHA256_LEN;   // 32
  static constexpr size_t kCompareSize = CS_SHA256_LEN;  // 32
  static constexpr uint8_t kCsHashType = CS_HASHTYPE_SHA256;
};

struct Sha256TruncatedTraits : detail::Sha256Algo {
  // Computes full SHA-256 (32 bytes) but stores/compares only the first 20.
  static constexpr size_t kSlotStride = CS_SHA256_TRUNCATED_LEN;   // 20
  static constexpr size_t kCompareSize = CS_SHA256_TRUNCATED_LEN;  // 20
  static constexpr uint8_t kCsHashType = CS_HASHTYPE_SHA256_TRUNCATED;
};

struct Sha384Traits {
  using Ctx = CC_SHA512_CTX;  // Apple uses CC_SHA512_CTX for SHA-384
  static constexpr int Init(Ctx* c) { return CC_SHA384_Init(c); }
  static constexpr int Update(Ctx* c, const void* d, size_t n) {
    VERIFYINGHASHER_CC_UPDATE_LOOP(CC_SHA384_Update, c, d, n);
  }
  static constexpr int Final(unsigned char* m, Ctx* c) {
    return CC_SHA384_Final(m, c);
  }
  static constexpr size_t kDigestSize = CC_SHA384_DIGEST_LENGTH;   // 48
  static constexpr size_t kSlotStride = CC_SHA384_DIGEST_LENGTH;   // 48
  static constexpr size_t kCompareSize = CC_SHA384_DIGEST_LENGTH;  // 48
  static constexpr uint8_t kCsHashType = CS_HASHTYPE_SHA384;
};

// NoopHashTraits substitutes into PageVerifierT<> to make the per-page
// hashing work disappear. Used when
// VerifyingHasherCore::Options::skip_page_hash is set — e.g., when the caller
// has independent assurance that the kernel will enforce page hashes (CS_HARD /
// CS_KILL on AUTH EXEC), or via a future configuration escape hatch.
// PageVerifierT<>::Update has an if-constexpr branch for this trait that
// bulk-advances cur_slot_/cur_page_bytes_ in O(1) per chunk instead of running
// the iterative per-page hashing loop; the iterative branch is the if-constexpr
// discarded statement for this trait and is never instantiated, which is why
// kDigestSize can be zero.
//
// Trait constants satisfy PageVerifierT's static_asserts trivially:
//   kCompareSize (0) <= kSlotStride (0) <= kDigestSize (0).
// Init/Update/Final are kept (rather than removed) only to model the trait
// concept symmetrically with the real hash traits; the discarded-statement
// rule means they're never called.
struct NoopHashTraits {
  struct Ctx {};
  static constexpr size_t kDigestSize = 0;
  static constexpr size_t kSlotStride = 0;
  static constexpr size_t kCompareSize = 0;
  static void Init(Ctx*) {}
  static void Update(Ctx*, const void*, size_t) {}
  static void Final(unsigned char*, Ctx*) {}
};

#undef VERIFYINGHASHER_CC_UPDATE_LOOP

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_HASHTRAITS_H
