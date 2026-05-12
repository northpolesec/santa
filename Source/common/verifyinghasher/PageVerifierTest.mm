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

#include "Source/common/verifyinghasher/PageVerifier.h"

#include <CommonCrypto/CommonDigest.h>
#import <XCTest/XCTest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

#include "Source/common/verifyinghasher/HashTraits.h"

using santa::PageVerifierT;
using santa::Sha1Traits;
using santa::Sha256Traits;
using santa::Sha256TruncatedTraits;
using santa::Sha384Traits;

namespace {

// Compute slot hashes the same way the kernel / CodeSignatureParser stores
// them: hash each page with `Traits::Init/Update/Final`, then write the
// first `Traits::kSlotStride` bytes into the slot buffer (truncating for
// SHA-256-TRUNCATED).
template <typename Traits>
std::vector<uint8_t> ComputeSlots(const std::vector<uint8_t>& bytes, uint64_t lo, uint64_t hi,
                                  uint32_t page_size) {
  std::vector<uint8_t> slots;
  for (uint64_t off = lo; off < hi; off += page_size) {
    uint64_t end = std::min<uint64_t>(off + page_size, hi);
    unsigned char d[Traits::kDigestSize];
    typename Traits::Ctx ctx;
    Traits::Init(&ctx);
    Traits::Update(&ctx, bytes.data() + off, end - off);
    Traits::Final(d, &ctx);
    slots.insert(slots.end(), d, d + Traits::kSlotStride);
  }
  return slots;
}

// Generic body: same logic for any Traits.
template <typename Traits>
bool RunOneTraitsBody() {
  std::mt19937 rng(0xC0DE);
  std::vector<uint8_t> bytes(123 * 1024);  // not page-aligned: tests partial last page
  for (auto& b : bytes)
    b = static_cast<uint8_t>(rng());

  constexpr uint32_t kPage = 4096;
  const uint64_t lo = 1024, hi = bytes.size();  // skip first 1024 bytes from signed region
  auto slots = ComputeSlots<Traits>(bytes, lo, hi, kPage);

  // Pass: feed all bytes (including bytes outside [lo, hi); they should be ignored).
  PageVerifierT<Traits> pv(lo, hi, kPage, slots);
  // Feed in 17-byte chunks to exercise mid-page boundaries.
  for (uint64_t off = 0; off < bytes.size(); off += 17) {
    size_t n = std::min<size_t>(17, bytes.size() - off);
    pv.Update(bytes.data() + off, n, off);
  }
  if (pv.Mismatches() != 0) return false;
  if (!pv.Complete()) return false;

  // Mismatch: flip a byte in slot 3 and feed again.
  auto tampered = bytes;
  const uint64_t flip_off = lo + 3 * kPage + 100;
  tampered[flip_off] ^= 0xFF;
  PageVerifierT<Traits> pv2(lo, hi, kPage, slots);
  for (uint64_t off = 0; off < tampered.size(); off += 17) {
    size_t n = std::min<size_t>(17, tampered.size() - off);
    pv2.Update(tampered.data() + off, n, off);
  }
  if (pv2.Mismatches() < 1) return false;
  if (pv2.MismatchedSlots().empty()) return false;
  if (pv2.MismatchedSlots()[0] != 3) return false;
  return true;
}

}  // namespace

@interface PageVerifierTest : XCTestCase
@end

@implementation PageVerifierTest

- (void)testRunOneTraitsSha256 {
  XCTAssertTrue(RunOneTraitsBody<Sha256Traits>());
}

- (void)testRunOneTraitsSha1 {
  XCTAssertTrue(RunOneTraitsBody<Sha1Traits>());
}

- (void)testRunOneTraitsSha384 {
  XCTAssertTrue(RunOneTraitsBody<Sha384Traits>());
}

- (void)testRunOneTraitsSha256Truncated {
  XCTAssertTrue(RunOneTraitsBody<Sha256TruncatedTraits>());
}

// Regression test for the SHA-256-TRUNCATED slot-stride bug: PageVerifier
// must walk slot_hashes at stride 20 (not 32) and compare 20 bytes. With the
// stride-20 packed slot table that the parser produces, advance-by-32 reads
// the wrong slot from slot 1 onward, and OOB-reads past the buffer at higher
// slot indices.
//
// We use enough pages (>=8) so a stride-32 walker would miscompare or read
// past the slot-hashes buffer.
- (void)testSha256TruncatedStride {
  std::mt19937 rng(0xAA55);
  std::vector<uint8_t> bytes(8 * 4096);  // 8 full pages
  for (auto& b : bytes)
    b = static_cast<uint8_t>(rng());

  auto slots = ComputeSlots<Sha256TruncatedTraits>(bytes, 0, bytes.size(), 4096);
  // Storage stride is 20, not 32 — the whole point of this test.
  XCTAssertEqual(slots.size(), 8u * 20u);

  PageVerifierT<Sha256TruncatedTraits> pv(0, bytes.size(), 4096, slots);
  pv.Update(bytes.data(), bytes.size(), 0);
  XCTAssertEqual(pv.Mismatches(), 0u);

  // Tamper page 5 — the bug would either miss this (wrong slot index due
  // to stride drift) or false-positive earlier slots.
  auto tampered = bytes;
  tampered[5 * 4096 + 100] ^= 0xFF;
  PageVerifierT<Sha256TruncatedTraits> pv2(0, tampered.size(), 4096, slots);
  pv2.Update(tampered.data(), tampered.size(), 0);
  XCTAssertEqual(pv2.Mismatches(), 1u);
  XCTAssertEqual(pv2.MismatchedSlots()[0], 5u);
}

// M7 regression: a gap inside the signed region must be flagged via
// StreamCorrupt() (release-safe) rather than silently advancing cur_slot_
// against wrong page bytes.
- (void)testStreamGapDetected {
  std::vector<uint8_t> bytes(8 * 4096, 0x42);
  auto slots = ComputeSlots<Sha256Traits>(bytes, 0, bytes.size(), 4096);
  PageVerifierT<Sha256Traits> pv(0, bytes.size(), 4096, slots);
  // Feed page 0 normally, then skip page 1 entirely (gap), feed page 2.
  pv.Update(bytes.data(), 4096, 0);
  XCTAssertFalse(pv.StreamCorrupt());
  pv.Update(bytes.data() + 8192, 4096, 8192);  // gap: missing [4096, 8192)
  XCTAssertTrue(pv.StreamCorrupt());
}

@end
