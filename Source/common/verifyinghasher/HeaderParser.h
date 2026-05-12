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

#ifndef SANTA_COMMON_VERIFYINGHASHER_HEADERPARSER_H
#define SANTA_COMMON_VERIFYINGHASHER_HEADERPARSER_H

#include <libkern/OSByteOrder.h>
#include <mach/machine.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace santa {

struct ArchSelector {
  cpu_type_t cputype = 0;
  cpu_subtype_t cpusubtype = 0;
};

struct SliceInfo {
  uint64_t slice_offset = 0;  // offset into the file
  uint64_t slice_size = 0;
  uint64_t total_file_size = 0;
  uint64_t cs_blob_offset = 0;  // absolute file offset
  uint64_t cs_blob_size = 0;
  std::string arch_name;  // "thin", "arm64", "arm64e", "x86_64", ...
};

// Push-style consumer of file bytes. Must be fed bytes in strict
// increasing file-order; chunk size is unconstrained.
//
// Outside-of-region bytes (e.g., padding between fat arch table and
// slice offset) are silently ignored — the streaming caller is
// responsible for routing them to fullCtx.
class HeaderParser {
 public:
  enum class Status { kNeedMore, kReady, kError };

  HeaderParser(ArchSelector want, uint64_t total_file_size);

  // Feed a chunk that starts at file offset `chunk_off`. Returns the
  // current state. Callers should stop feeding once kReady or kError
  // is returned.
  Status Update(const uint8_t* data, size_t len, uint64_t chunk_off);

  Status status() const { return state_; }
  std::string_view LastError() const { return error_; }

  // Valid only after Status::kReady.
  const SliceInfo& Slice() const { return slice_; }

  // Returns the slice's file offset once it's been determined — i.e., right
  // after ProcessMagic for thin Mach-Os and right after ProcessFatArchTable
  // for fat Mach-Os. nullopt before that. Lets the streaming caller drop
  // pre-slice bytes from any replay buffer without waiting for kReady.
  std::optional<uint64_t> SliceOffsetIfKnown() const;

 private:
  enum class Phase {
    kNeedMagic,
    kNeedFatHeader,
    kNeedFatArchTable,
    kNeedSliceMachHeader,
    kNeedLoadCommands,
    kReady,
    kError,
  };

  // Region the parser currently wants. Bytes inside are accumulated
  // into scratch_; bytes before are skipped silently.
  uint64_t want_off_ = 0;
  size_t want_len_ = 0;

  Phase phase_ = Phase::kNeedMagic;
  Status state_ = Status::kNeedMore;
  std::string error_;

  // Carryover scratch for the current region.
  std::vector<uint8_t> scratch_;

  // Inputs / parsed-so-far.
  ArchSelector want_;
  SliceInfo slice_;
  bool fat64_ = false;
  uint32_t nfat_ = 0;
  bool mh_is_64_ = false;
  bool mh_swap_ = false;
  uint32_t mh_ncmds_ = 0;
  uint32_t mh_sizeofcmds_ = 0;

  // Returns OSSwapInt32(value) when mh_swap_ is set, value unchanged
  // otherwise. Centralizes the conditional byteswap consulted at every
  // site that consumes a Mach-O header field whose endianness depends
  // on the slice magic.
  template <typename T>
  T SwapIfNeeded(T value) const {
    static_assert(sizeof(T) == 4, "SwapIfNeeded: only 32-bit values supported");
    if (!mh_swap_) return value;
    return static_cast<T>(OSSwapInt32(static_cast<uint32_t>(value)));
  }

  // State-handling helpers.
  Status SetError(std::string msg);
  void AdvanceToPhase(Phase p, uint64_t off, size_t len);
  void AdvanceToPhaseKeepingScratch(Phase p, uint64_t next_off,
                                    size_t total_len);
  Status ProcessMagic();
  Status ProcessFatHeader();
  Status ProcessFatArchTable();
  Status ProcessSliceMachHeader();
  Status ProcessLoadCommands();
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_HEADERPARSER_H
