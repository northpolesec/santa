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

#ifndef SANTA_COMMON_VERIFYINGHASHER_PAGEVERIFIER_H
#define SANTA_COMMON_VERIFYINGHASHER_PAGEVERIFIER_H

#include <os/overflow.h>

#include <algorithm>
#include <bit>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>
#include <vector>

#include "Source/common/verifyinghasher/HashTraits.h"

namespace santa {

inline constexpr size_t kMaxRecordedMismatches = 64;

template <typename HashTraits>
class PageVerifierT {
 public:
  PageVerifierT(uint64_t signed_lo, uint64_t signed_hi, uint32_t page_size,
                std::span<const uint8_t> slot_hashes)
      : signed_lo_(signed_lo),
        signed_hi_(signed_hi),
        page_size_(page_size),
        slot_hashes_(slot_hashes) {
    static_assert(HashTraits::kCompareSize <= HashTraits::kSlotStride,
                  "compare size must not exceed stored slot stride");
    static_assert(HashTraits::kSlotStride <= HashTraits::kDigestSize,
                  "slot stride must not exceed computed digest size");
    assert(signed_hi_ >= signed_lo_);
    assert(page_size_ > 0);
    // Apple code-signing uses pow2 page sizes (4096 or 16384). Detect once
    // so the NoopHashTraits bulk-advance path can use shift+mask instead
    // of UDIV/UREM — those are ~16-cycle latencies on Apple Silicon, and
    // putting them on the critical path of the streaming loop is wasteful
    // when the CodeDirectory format guarantees a pow2 in practice.
    // std::has_single_bit returns false for 0, so countr_zero is only
    // called on a known-nonzero input (countr_zero(0) is well-defined but
    // would yield bit_width, an invalid shift amount).
    if (std::has_single_bit(page_size_)) {
      page_size_shift_ = static_cast<int8_t>(std::countr_zero(page_size_));
      page_size_mask_ = page_size_ - 1;
    }
    HashTraits::Init(&ctx_);
  }

  // Feed bytes that start at file offset `chunk_off`. Bytes outside
  // [signed_lo_, signed_hi_) are silently dropped, but bytes *inside* the
  // signed region must arrive contiguously — a gap would silently advance
  // cur_slot_ against wrong page content and could mask tampering. If a
  // gap is detected we mark stream_corrupt_ and stop processing further
  // pages; the caller (VerifyingHasherCore) checks StreamCorrupt() and converts
  // to a malformed-signature error. Survives NDEBUG.
  //
  // When HashTraits is NoopHashTraits, the per-page hashing loop is
  // replaced with O(1) bulk advance of cur_slot_/cur_page_bytes_. The
  // gap-detect prologue is unchanged so StreamCorrupt() still fires on a
  // contract violation, and the bulk advance reaches the same end state
  // the iterative loop would have so Complete() still works correctly.
  void Update(const uint8_t* data, size_t len, uint64_t chunk_off) {
    if (stream_corrupt_) return;
    uint64_t a = std::max<uint64_t>(chunk_off, signed_lo_);
    // Saturate the chunk's end offset on overflow. With current callers
    // chunk_off + len fits in uint64_t comfortably (both bounded by
    // total_file_size), but matching the os_*_overflow pattern used for
    // the gap check below keeps the bound from silently relying on
    // caller arithmetic staying small.
    uint64_t input_end;
    if (os_add_overflow(chunk_off, static_cast<uint64_t>(len), &input_end)) {
      input_end = UINT64_MAX;
    }
    uint64_t b = std::min<uint64_t>(input_end, signed_hi_);
    if (a < b) {
      // Contract: a (file offset of the next byte to consume) must equal
      // the next-expected offset = signed_lo_ + cur_slot_*page_size_
      // + cur_page_bytes_. Compute as `a - signed_lo_` vs.
      // `cur_slot_*page_size_ + cur_page_bytes_` so the comparand stays
      // well below total_file_size, and wrap each step in os_*_overflow
      // so the check doesn't silently rely on C2/H3 keeping the multiply
      // small.
      uint64_t slot_offset, already;
      if (os_mul_overflow(static_cast<uint64_t>(cur_slot_),
                          static_cast<uint64_t>(page_size_), &slot_offset) ||
          os_add_overflow(slot_offset, cur_page_bytes_, &already) ||
          (a - signed_lo_) != already) {
        stream_corrupt_ = true;
        return;
      }
    }
    if constexpr (std::is_same_v<HashTraits, NoopHashTraits>) {
      // Bulk-advance the page counter by the in-region byte count.
      // Incremental form: cur_page_bytes_ + consumed = (pages_completed *
      // page_size) + new_cur_page_bytes. Equivalent end state to the
      // iterative loop in the else branch at O(1) per chunk; preserves
      // Complete() and StreamCorrupt() invariants because the gap-detect
      // prologue above still fires and the cur_slot_/cur_page_bytes_ end
      // state matches what the iterative loop would have produced.
      //
      // Lives in the if-branch (not after an early return) so the else
      // branch is the if-constexpr discarded statement and is not
      // instantiated for NoopHashTraits — which lets NoopHashTraits keep
      // kDigestSize=0 and avoids a zero-length-array compile concern.
      if (b > a) {
        const uint64_t consumed = b - a;
        const uint64_t new_partial = cur_page_bytes_ + consumed;
        uint32_t pages_completed;
        if (page_size_shift_ >= 0) [[likely]] {
          // Pow2 fast path (always taken in production — Apple's
          // CodeDirectory page_size is 4096 or 16384). Shift+mask have
          // 1-cycle latency each; UDIV/UREM on ARM are ~16-20 cycles and
          // would serialize against the surrounding SHA-256 stream in
          // cold-cache regimes where OoO slack is tighter.
          pages_completed =
              static_cast<uint32_t>(new_partial >> page_size_shift_);
          cur_page_bytes_ = new_partial & page_size_mask_;
        } else {
          // Non-pow2 fallback. Operates on (cur_page_bytes_ + consumed)
          // rather than reconstructing the absolute total, so the UDIV
          // dividend stays small (< chunk_size + page_size).
          pages_completed = static_cast<uint32_t>(new_partial / page_size_);
          cur_page_bytes_ = new_partial % page_size_;
        }
        cur_slot_ += pages_completed;
      }
    } else {
      while (a < b) {
        const uint64_t page_end_off =
            signed_lo_ + static_cast<uint64_t>(cur_slot_) * page_size_ +
            ExpectedPageLen(cur_slot_);
        const uint64_t chunk_end = std::min(b, page_end_off);
        const uint64_t take = chunk_end - a;
        HashTraits::Update(&ctx_, data + (a - chunk_off), take);
        cur_page_bytes_ += take;
        a += take;

        if (cur_page_bytes_ == ExpectedPageLen(cur_slot_)) {
          unsigned char digest[HashTraits::kDigestSize];
          HashTraits::Final(digest, &ctx_);
          const uint8_t* slot =
              slot_hashes_.data() +
              static_cast<size_t>(cur_slot_) * HashTraits::kSlotStride;
          if (std::memcmp(digest, slot, HashTraits::kCompareSize) != 0) {
            ++mismatches_;
            if (mismatched_slots_.size() < kMaxRecordedMismatches) {
              mismatched_slots_.push_back(cur_slot_);
            }
          }
          ++cur_slot_;
          cur_page_bytes_ = 0;
          if (signed_lo_ + static_cast<uint64_t>(cur_slot_) * page_size_ <
              signed_hi_) {
            HashTraits::Init(&ctx_);
          }
        }
      }
    }
  }

  uint32_t Mismatches() const { return mismatches_; }
  std::span<const uint32_t> MismatchedSlots() const {
    return mismatched_slots_;
  }
  // True if Update() ever observed a gap or overflow in the input stream.
  // When set, Mismatches() / MismatchedSlots() are not trustworthy — the
  // caller must treat the verification as failed.
  bool StreamCorrupt() const { return stream_corrupt_; }
  bool Complete() const {
    return signed_lo_ + static_cast<uint64_t>(cur_slot_) * page_size_ +
               cur_page_bytes_ >=
           signed_hi_;
  }

 private:
  uint64_t ExpectedPageLen(uint32_t slot) const {
    const uint64_t code_len = signed_hi_ - signed_lo_;
    const uint64_t remaining =
        code_len - static_cast<uint64_t>(slot) * page_size_;
    return remaining < page_size_ ? remaining : page_size_;
  }

  typename HashTraits::Ctx ctx_;
  uint64_t signed_lo_;
  uint64_t signed_hi_;
  uint32_t page_size_;
  std::span<const uint8_t> slot_hashes_;

  // Pow2 page-size hints set in the constructor. shift_ == -1 means
  // page_size_ is not a power of two; the bulk-advance falls back to UDIV.
  // In production, Apple's CodeDirectory's pageSize field (which the
  // parser resolves to 1 << pageSize before passing it here) is always
  // either 4096 or 16384, so the fast path is always taken.
  int8_t page_size_shift_ = -1;
  uint32_t page_size_mask_ = 0;

  uint32_t cur_slot_ = 0;
  uint64_t cur_page_bytes_ = 0;
  uint32_t mismatches_ = 0;
  bool stream_corrupt_ = false;
  std::vector<uint32_t> mismatched_slots_;
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_PAGEVERIFIER_H
