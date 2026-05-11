/// Copyright 2026 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA_COMMON_VERIFYINGHASHER_VERIFYINGHASHERCORE_H
#define SANTA_COMMON_VERIFYINGHASHER_VERIFYINGHASHERCORE_H

#include <CommonCrypto/CommonDigest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "Source/common/verifyinghasher/CodeSignatureParser.h"
#include "Source/common/verifyinghasher/FileReader.h"
#include "Source/common/verifyinghasher/HeaderParser.h"
#include "Source/common/verifyinghasher/UninitBuffer.h"

namespace santa {

class VerifyingHasherCore {
 public:
  enum class Status {
    kOk,
    kPagesMismatched,
    kNoSignature,
    kSliceNotFound,
    kNotMachO,
    kIoError,
    kMalformedSignature,
  };

  struct Options {
    size_t buf_size = 1u << 20;  // pread chunk size; 1 MiB default.
                                 // Any positive value is valid.
  };

  VerifyingHasherCore(FileReader& reader, ArchSelector want);
  VerifyingHasherCore(FileReader& reader, ArchSelector want, Options opts);
  Status Run();

  // 32-byte SHA-256 of the full file. Empty span if Status == kIoError
  // (digest could not be finalized due to incomplete reads).
  std::span<const uint8_t> FullFileDigest() const;

  // 20-byte truncated cdhash of the picked CodeDirectory, computed
  // using that CD's hashType (matches xnu's cs_cd_hash and
  // es_event_exec_t.target.cdhash).
  // Empty span unless Run() reached the end of RunCsBlobPhase
  // successfully — i.e., for kOk and kPagesMismatched. Empty for
  // kIoError / kNotMachO / kNoSignature / kSliceNotFound, and for
  // kMalformedSignature when the failure was at or before the parse.
  std::span<const uint8_t> CDHash() const;

  // Valid for kOk / kPagesMismatched:
  const ParsedCodeDirectory& ParsedCD() const { return parsed_cd_; }
  const SliceInfo& Slice() const { return slice_; }
  bool PagesMatched() const { return mismatches_ == 0; }
  // Total page-hash mismatch count (uncapped). Useful for telemetry.
  uint32_t Mismatches() const { return mismatches_; }
  // Up to kMaxRecordedMismatches slot indices, for diagnostic logging.
  std::span<const uint32_t> MismatchedSlots() const;

  std::string_view LastError() const { return last_error_; }

 private:
  template <typename HashTraits>
  Status RunStreamingPhases();

  Status RunHeaderPhase();
  Status RunCsBlobPhase();
  void FinalizeDigestDrainingToEof();

  FileReader& reader_;
  ArchSelector want_;
  Options opts_;

  UninitBuffer chunk_buf_;
  UninitBuffer cs_blob_buf_;
  // Phase-1 chunks' bytes that lie inside the chosen slice — i.e., file
  // offsets >= slice_offset, accumulated until HeaderParser reaches kReady.
  // Bounded by slice_header_size + sizeofcmds (sizeofcmds is capped at
  // kMaxSizeOfCmds = 1 MiB), independent of buf_size; with small buf_size
  // these can span multiple chunks.
  // Used for two purposes after phase 1:
  //   1. Replay the signed-region overlap [slice_offset, min(cursor_,
  //   signed_hi))
  //      through PageVerifier without a second read.
  //   2. Reuse the CS blob bytes if phase 1 already read past cs_blob_end,
  //      avoiding a second pread of the same region.
  std::vector<uint8_t> header_phase_buf_;

  CC_SHA256_CTX full_ctx_;
  uint8_t full_digest_[CC_SHA256_DIGEST_LENGTH] = {};
  bool digest_finalized_ = false;
  bool cdhash_populated_ = false;

  SliceInfo slice_;
  ParsedCodeDirectory parsed_cd_;
  // Computed once in Run() after the overflow + cs-blob-overlap guard, and
  // reused in RunStreamingPhases. Carries the validation with the value so
  // a future caller that reaches the streaming logic via a different path
  // can't strip the guard. Zero before Run() validates the inputs.
  uint64_t signed_hi_ = 0;
  uint64_t cursor_ = 0;
  uint32_t mismatches_ = 0;
  std::vector<uint32_t> mismatched_slots_;
  std::string last_error_;
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_VERIFYINGHASHERCORE_H
