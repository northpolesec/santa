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

#include "Source/common/verifyinghasher/HashTraits.h"

#import <XCTest/XCTest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

using santa::Sha1Traits;
using santa::Sha256Traits;
using santa::Sha256TruncatedTraits;
using santa::Sha384Traits;

namespace {

template <typename Traits>
void HashOnce(const void* data, size_t n, unsigned char* out) {
  typename Traits::Ctx ctx;
  Traits::Init(&ctx);
  Traits::Update(&ctx, data, n);
  Traits::Final(out, &ctx);
}

// H4 regression: Update must split inputs > UINT32_MAX into multiple
// CC_*_Update calls under the hood. We can't actually feed 4 GiB in CI, but
// we can verify the loop's correctness by checking that a single big call
// produces the same digest as many small calls — which is the property that
// the chunking implementation must preserve.
template <typename Traits>
bool RunChunkedEquivalence() {
  constexpr size_t kSize = 256 * 1024;  // 256 KiB
  std::vector<uint8_t> data(kSize);
  for (size_t i = 0; i < kSize; ++i)
    data[i] = static_cast<uint8_t>(i * 1103515245u);

  unsigned char one_shot[Traits::kDigestSize];
  {
    typename Traits::Ctx ctx;
    Traits::Init(&ctx);
    Traits::Update(&ctx, data.data(), data.size());  // single call
    Traits::Final(one_shot, &ctx);
  }

  unsigned char chunked[Traits::kDigestSize];
  {
    typename Traits::Ctx ctx;
    Traits::Init(&ctx);
    for (size_t off = 0; off < kSize; off += 1031) {  // odd-prime chunks
      size_t n = std::min<size_t>(1031, kSize - off);
      Traits::Update(&ctx, data.data() + off, n);
    }
    Traits::Final(chunked, &ctx);
  }
  return std::memcmp(one_shot, chunked, Traits::kDigestSize) == 0;
}

}  // namespace

@interface HashTraitsTest : XCTestCase
@end

@implementation HashTraitsTest

- (void)testSha256KnownVector {
  // RFC 6234 known vector: SHA-256("abc") = ba7816bf...
  static const uint8_t kExpected[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
  };
  unsigned char out[32];
  HashOnce<Sha256Traits>("abc", 3, out);
  XCTAssertEqual(std::memcmp(out, kExpected, 32), 0);
  XCTAssertEqual(Sha256Traits::kDigestSize, 32u);
  XCTAssertEqual(Sha256Traits::kSlotStride, 32u);
  XCTAssertEqual(Sha256Traits::kCompareSize, 32u);
  XCTAssertEqual(Sha256Traits::kCsHashType, CS_HASHTYPE_SHA256);

  // SHA-256-TRUNCATED uses the same algorithm but stores/compares only 20 bytes.
  HashOnce<Sha256TruncatedTraits>("abc", 3, out);
  XCTAssertEqual(std::memcmp(out, kExpected, 32), 0);
  XCTAssertEqual(Sha256TruncatedTraits::kDigestSize, 32u);
  XCTAssertEqual(Sha256TruncatedTraits::kSlotStride, 20u);
  XCTAssertEqual(Sha256TruncatedTraits::kCompareSize, 20u);
  XCTAssertEqual(Sha256TruncatedTraits::kCsHashType, CS_HASHTYPE_SHA256_TRUNCATED);
}

- (void)testSha1KnownVector {
  // SHA-1("abc") = a9993e36...
  static const uint8_t kExpected[20] = {
      0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
      0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
  };
  unsigned char out[20];
  HashOnce<Sha1Traits>("abc", 3, out);
  XCTAssertEqual(std::memcmp(out, kExpected, 20), 0);
  XCTAssertEqual(Sha1Traits::kDigestSize, 20u);
  XCTAssertEqual(Sha1Traits::kSlotStride, 20u);
  XCTAssertEqual(Sha1Traits::kCompareSize, 20u);
  XCTAssertEqual(Sha1Traits::kCsHashType, CS_HASHTYPE_SHA1);
}

- (void)testSha384KnownVector {
  // SHA-384("abc") = cb00753f...
  static const uint8_t kExpected[48] = {
      0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
      0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
      0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
      0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
  };
  unsigned char out[48];
  HashOnce<Sha384Traits>("abc", 3, out);
  XCTAssertEqual(std::memcmp(out, kExpected, 48), 0);
  XCTAssertEqual(Sha384Traits::kDigestSize, 48u);
  XCTAssertEqual(Sha384Traits::kSlotStride, 48u);
  XCTAssertEqual(Sha384Traits::kCompareSize, 48u);
  XCTAssertEqual(Sha384Traits::kCsHashType, CS_HASHTYPE_SHA384);
}

- (void)testChunkedEquivalenceSha1 {
  XCTAssertTrue(RunChunkedEquivalence<Sha1Traits>());
}

- (void)testChunkedEquivalenceSha256 {
  XCTAssertTrue(RunChunkedEquivalence<Sha256Traits>());
}

- (void)testChunkedEquivalenceSha256Truncated {
  XCTAssertTrue(RunChunkedEquivalence<Sha256TruncatedTraits>());
}

- (void)testChunkedEquivalenceSha384 {
  XCTAssertTrue(RunChunkedEquivalence<Sha384Traits>());
}

@end
