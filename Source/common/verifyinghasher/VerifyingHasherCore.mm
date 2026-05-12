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

#include "Source/common/verifyinghasher/VerifyingHasherCore.h"

#include <os/overflow.h>
#include <sys/cdefs.h>

__BEGIN_DECLS
#include <Kernel/kern/cs_blobs.h>
__END_DECLS

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "Source/common/verifyinghasher/HashTraits.h"
#include "Source/common/verifyinghasher/PageVerifier.h"

namespace santa {

VerifyingHasherCore::VerifyingHasherCore(FileReader& reader, ArchSelector want)
    : VerifyingHasherCore(reader, want, Options{}) {}

VerifyingHasherCore::VerifyingHasherCore(FileReader& reader, ArchSelector want, Options opts)
    : reader_(reader), want_(want), opts_(opts) {
  if (opts_.buf_size == 0) opts_.buf_size = 1u << 20;
  chunk_buf_.Allocate(opts_.buf_size);
  Sha256Traits::Init(&full_ctx_);
}

std::span<const uint8_t> VerifyingHasherCore::FullFileDigest() const {
  // Empty span when the digest hasn't been finalized (only happens on
  // kIoError). Returning the zero-initialized buffer would silently hand
  // a caller 32 zero bytes that look like a valid SHA-256 — an explicit
  // empty span makes status-ignoring misuse loud rather than silent.
  return digest_finalized_ ? std::span<const uint8_t>{full_digest_, sizeof(full_digest_)}
                           : std::span<const uint8_t>{};
}

std::span<const uint8_t> VerifyingHasherCore::CDHash() const {
  // Empty span when the parse hasn't populated cdhash. Mirrors
  // FullFileDigest()'s empty-on-unavailable: callers that ignore
  // populated_ get a loud failure mode (zero-length span) rather
  // than 20 zero bytes that look like a real cdhash.
  return cdhash_populated_ ? std::span<const uint8_t>{parsed_cd_.cdhash, CS_CDHASH_LEN}
                           : std::span<const uint8_t>{};
}

std::span<const uint32_t> VerifyingHasherCore::MismatchedSlots() const {
  return mismatched_slots_;
}

std::optional<uint32_t> VerifyingHasherCore::Mismatches() const {
  if (opts_.skip_page_hash) return std::nullopt;
  return mismatches_;
}

VerifyingHasherCore::Status VerifyingHasherCore::RunHeaderPhase() {
  const uint64_t total = static_cast<uint64_t>(reader_.Size());
  HeaderParser hp(want_, total);
  while (hp.status() == HeaderParser::Status::kNeedMore) {
    const uint64_t chunk_off = cursor_;
    ssize_t n = reader_.Pread(chunk_buf_.data(), chunk_buf_.size(), static_cast<off_t>(chunk_off));
    if (n < 0) {
      last_error_ = "pread failed in header phase";
      return Status::kIoError;
    }
    if (n > 0 && static_cast<uint64_t>(n) > total - chunk_off) {
      // Reader returned more bytes than its Size() declared remained.
      // For an fd-backed reader this is the kernel reporting a file
      // larger than fstat captured at Run() entry — the file grew mid-
      // verification, and continuing would silently hash the over-served
      // bytes. Surface as kIoError so the caller can act on the race.
      // For non-fd readers it's a contract violation. Either way, refuse
      // to publish a digest over content the reader hasn't accounted for.
      last_error_ = "reader served past reported size in header phase";
      return Status::kIoError;
    }
    if (n == 0) {
      // n == 0 with cursor_ < total means the reader returned EOF before
      // we hit the size fstat reported at Run() entry (file truncated
      // mid-verification, or a reader that misreports Size()). Mirror
      // phases 3 and 5: classify as kIoError so the partial digest
      // doesn't get finalized and returned as if it covered the full file.
      if (cursor_ < total) {
        last_error_ = "unexpected EOF in header phase";
        return Status::kIoError;
      }
      // Genuine EOF at the reader-reported size. A file too short to even
      // contain the Mach-O magic is "not a Mach-O", not an I/O error —
      // falling back to kIoError here would deny the caller a populated
      // digest (per spec, kIoError is the only status without one). The
      // "digest covers the full file" contract is preserved because cursor_
      // has reached total above.
      if (cursor_ < 4) {
        last_error_ = "file too short to be a Mach-O";
        return Status::kNotMachO;
      }
      last_error_ = "EOF before code signature found";
      return hp.LastError().find("not a Mach-O") != std::string_view::npos ? Status::kNotMachO
                                                                           : Status::kNoSignature;
    }
    Sha256Traits::Update(&full_ctx_, chunk_buf_.data(), static_cast<size_t>(n));
    hp.Update(chunk_buf_.data(), static_cast<size_t>(n), chunk_off);
    cursor_ = chunk_off + static_cast<uint64_t>(n);
    // Buffer only bytes inside the chosen slice (i.e., from slice_offset
    // onwards) for later replay through PageVerifier / CS-blob memcpy.
    // Pre-slice bytes (fat header, fat-arch table, gap to slice_offset)
    // never need to be retained — they were already fed to full_ctx_ above.
    // header_phase_buf_[0] therefore corresponds to file offset slice_offset.
    if (auto slice_off = hp.SliceOffsetIfKnown()) {
      const uint64_t lo = std::max<uint64_t>(chunk_off, *slice_off);
      const uint64_t hi = chunk_off + static_cast<uint64_t>(n);
      if (hi > lo) {
        const uint8_t* src = chunk_buf_.data() + (lo - chunk_off);
        header_phase_buf_.insert(header_phase_buf_.end(), src, src + (hi - lo));
      }
    }
  }
  if (hp.status() == HeaderParser::Status::kError) {
    last_error_ = std::string(hp.LastError());
    if (last_error_.find("not a Mach-O") != std::string::npos) return Status::kNotMachO;
    if (last_error_.find("no embedded code signature") != std::string::npos)
      return Status::kNoSignature;
    if (last_error_.find("matching slice") != std::string::npos ||
        last_error_.find("slice arch mismatch") != std::string::npos)
      return Status::kSliceNotFound;
    return Status::kMalformedSignature;
  }
  slice_ = hp.Slice();
  return Status::kOk;
}

VerifyingHasherCore::Status VerifyingHasherCore::RunCsBlobPhase() {
  const uint64_t cs_lo = slice_.cs_blob_offset;
  const uint64_t cs_hi = cs_lo + slice_.cs_blob_size;
  // header_phase_buf_[0] corresponds to file offset slice_offset.
  const uint64_t buf_base = slice_.slice_offset;

  cs_blob_buf_.Allocate(slice_.cs_blob_size);

  if (cs_hi <= cursor_) {
    // Full overlap: phase 1 already read past the CS blob.
    std::memcpy(cs_blob_buf_.data(), header_phase_buf_.data() + (cs_lo - buf_base),
                slice_.cs_blob_size);
  } else if (cs_lo < cursor_) {
    // Partial overlap: copy [cs_lo, cursor_) from buffer,
    // pread [cursor_, cs_hi) for the rest.
    const size_t already = static_cast<size_t>(cursor_ - cs_lo);
    std::memcpy(cs_blob_buf_.data(), header_phase_buf_.data() + (cs_lo - buf_base), already);
    const size_t remaining = slice_.cs_blob_size - already;
    ssize_t n =
        reader_.Pread(cs_blob_buf_.data() + already, remaining, static_cast<off_t>(cursor_));
    if (n != static_cast<ssize_t>(remaining)) {
      last_error_ = "short pread on CS blob (partial overlap)";
      return Status::kIoError;
    }
  } else {
    // No overlap: fresh pread of the whole blob.
    ssize_t n = reader_.Pread(cs_blob_buf_.data(), cs_blob_buf_.size(), static_cast<off_t>(cs_lo));
    if (n != static_cast<ssize_t>(slice_.cs_blob_size)) {
      last_error_ = "short pread on CS blob";
      return Status::kIoError;
    }
  }

  std::string err;
  if (!ParseCodeSignature(cs_blob_buf_.view(), slice_.slice_size, parsed_cd_, err)) {
    last_error_ = std::move(err);
    return Status::kMalformedSignature;
  }
  cdhash_populated_ = true;
  return Status::kOk;
}

template <typename HashTraits>
VerifyingHasherCore::Status VerifyingHasherCore::RunStreamingPhases() {
  const uint64_t signed_lo = slice_.slice_offset;
  const uint64_t signed_hi = signed_hi_;  // validated in Run() above
  const uint64_t cs_lo = slice_.cs_blob_offset;
  const uint64_t cs_hi = cs_lo + slice_.cs_blob_size;

  PageVerifierT<HashTraits> pv(signed_lo, signed_hi, parsed_cd_.page_size, parsed_cd_.slot_hashes);

  // Replay any signed-region bytes that phase 1 already consumed,
  // by feeding them to PageVerifier from header_phase_buf_. Index 0 of
  // the buffer is at file offset slice_offset == signed_lo, so the source
  // pointer is just header_phase_buf_.data().
  // (full_ctx_ already received these bytes during phase 1.)
  if (signed_lo < cursor_) {
    const uint64_t replay_end = std::min(cursor_, signed_hi);
    if (replay_end > signed_lo) {
      pv.Update(header_phase_buf_.data(), static_cast<size_t>(replay_end - signed_lo), signed_lo);
    }
  }

  // Phase 3: stream from cursor_ up to cs_blob_offset (no-op if
  // phase 1 already overshot).
  while (cursor_ < cs_lo) {
    size_t want = std::min<size_t>(chunk_buf_.size(), cs_lo - cursor_);
    ssize_t n = reader_.Pread(chunk_buf_.data(), want, static_cast<off_t>(cursor_));
    if (n < 0) {
      last_error_ = "pread failed in streaming phase";
      return Status::kIoError;
    }
    if (n == 0) {
      last_error_ = "unexpected EOF in streaming phase";
      return Status::kIoError;
    }
    if (static_cast<size_t>(n) > want) {
      // Reader violated its len contract — pread(2) caps at len, so this
      // can only happen with a misbehaving custom FileReader. Defense-
      // in-depth against silently feeding bytes past cs_lo into pv.
      last_error_ = "reader served past requested length in streaming phase";
      return Status::kIoError;
    }
    Sha256Traits::Update(&full_ctx_, chunk_buf_.data(), static_cast<size_t>(n));
    pv.Update(chunk_buf_.data(), static_cast<size_t>(n), cursor_);
    cursor_ += static_cast<uint64_t>(n);
  }

  // Phase 4: feed CS blob bytes to fullCtx — but only the portion
  // phase 1 didn't already cover.
  if (cursor_ < cs_hi) {
    const size_t already = cursor_ > cs_lo ? static_cast<size_t>(cursor_ - cs_lo) : 0;
    const size_t remaining = cs_blob_buf_.size() - already;
    if (remaining > 0) {
      Sha256Traits::Update(&full_ctx_, cs_blob_buf_.data() + already, remaining);
    }
    cursor_ = cs_hi;
  }

  // Phase 5: tail to EOF (no-op if phase 1 already reached EOF).
  const uint64_t total = static_cast<uint64_t>(reader_.Size());
  while (cursor_ < total) {
    size_t want = std::min<size_t>(chunk_buf_.size(), total - cursor_);
    ssize_t n = reader_.Pread(chunk_buf_.data(), want, static_cast<off_t>(cursor_));
    if (n < 0) {
      last_error_ = "pread failed in tail phase";
      return Status::kIoError;
    }
    // n == 0 with cursor_ < total means the underlying source returned
    // EOF before we hit the size fstat reported at Run() entry (e.g.,
    // the file was truncated mid-verification). Treat as kIoError —
    // same as phase 3 — so the partial digest doesn't get finalized
    // and returned as if it covered the full file.
    if (n == 0) {
      last_error_ = "unexpected EOF in tail phase";
      return Status::kIoError;
    }
    if (static_cast<size_t>(n) > want) {
      // Defense-in-depth against a misbehaving custom FileReader serving
      // past its declared len. For fd-backed readers pread(2) caps at
      // len so this is unreachable in production.
      last_error_ = "reader served past requested length in tail phase";
      return Status::kIoError;
    }
    Sha256Traits::Update(&full_ctx_, chunk_buf_.data(), static_cast<size_t>(n));
    cursor_ += static_cast<uint64_t>(n);
  }

  Sha256Traits::Final(full_digest_, &full_ctx_);
  digest_finalized_ = true;

  if (pv.StreamCorrupt()) {
    // PageVerifier observed a gap or arithmetic overflow in its input
    // stream. Mismatches/MismatchedSlots are not trustworthy.
    last_error_ = "PageVerifier input stream corrupted (gap or overflow)";
    return Status::kMalformedSignature;
  }
  // Defense-in-depth: today, signed_hi <= cs_blob_offset (validated in Run)
  // plus phase 3 streaming up to cs_lo guarantees pv saw [signed_lo,
  // signed_hi). This check would catch a future refactor that decoupled
  // the streaming end from cs_lo and silently left the last page(s)
  // unverified. O(1).
  if (!pv.Complete()) {
    last_error_ = "PageVerifier did not consume the full signed region";
    return Status::kMalformedSignature;
  }
  mismatches_ = pv.Mismatches();
  auto bad = pv.MismatchedSlots();
  mismatched_slots_.assign(bad.begin(), bad.end());

  return mismatches_ == 0 ? Status::kOk : Status::kPagesMismatched;
}

void VerifyingHasherCore::FinalizeDigestDrainingToEof() {
  // Best-effort digest finalization on a non-IoError failure path. If a
  // pread fails mid-drain we stop, finalize whatever we have, and the
  // returned digest may not match shasum on that file. Spec only promises
  // "populated unless kIoError" — not "byte-correct on every error path".
  if (digest_finalized_) return;
  const uint64_t total = static_cast<uint64_t>(reader_.Size());
  const uint64_t cs_lo = slice_.cs_blob_offset;
  const uint64_t cs_hi = cs_lo + slice_.cs_blob_size;
  const bool have_cs_blob = !cs_blob_buf_.empty();

  // If RunCsBlobPhase populated cs_blob_buf_ and cursor_ hasn't yet
  // crossed cs_hi, the bytes in [max(cursor_, cs_lo), cs_hi) are
  // available in memory and must NOT be re-read from disk.
  if (have_cs_blob && cursor_ < cs_hi) {
    // 1. Drain [cursor_, cs_lo) from disk.
    while (cursor_ < cs_lo) {
      size_t want = std::min<size_t>(chunk_buf_.size(), cs_lo - cursor_);
      ssize_t n = reader_.Pread(chunk_buf_.data(), want, static_cast<off_t>(cursor_));
      if (n <= 0) break;
      Sha256Traits::Update(&full_ctx_, chunk_buf_.data(), static_cast<size_t>(n));
      cursor_ += static_cast<uint64_t>(n);
    }
    // 2. Feed the not-yet-hashed remainder of cs_blob_buf_ to full_ctx_.
    if (cursor_ < cs_hi) {
      const size_t already = cursor_ > cs_lo ? static_cast<size_t>(cursor_ - cs_lo) : 0;
      const size_t remaining = cs_blob_buf_.size() - already;
      if (remaining > 0) {
        Sha256Traits::Update(&full_ctx_, cs_blob_buf_.data() + already, remaining);
      }
      cursor_ = cs_hi;
    }
  }

  // Drain remaining bytes (or all of them if no cs_blob_buf_) to EOF.
  while (cursor_ < total) {
    size_t want = std::min<size_t>(chunk_buf_.size(), total - cursor_);
    ssize_t n = reader_.Pread(chunk_buf_.data(), want, static_cast<off_t>(cursor_));
    if (n <= 0) break;
    Sha256Traits::Update(&full_ctx_, chunk_buf_.data(), static_cast<size_t>(n));
    cursor_ += static_cast<uint64_t>(n);
  }
  Sha256Traits::Final(full_digest_, &full_ctx_);
  digest_finalized_ = true;
}

VerifyingHasherCore::Status VerifyingHasherCore::Run() {
  if (Status s = RunHeaderPhase(); s != Status::kOk) {
    if (s != Status::kIoError) FinalizeDigestDrainingToEof();
    return s;
  }
  if (Status s = RunCsBlobPhase(); s != Status::kOk) {
    if (s != Status::kIoError) FinalizeDigestDrainingToEof();
    return s;
  }

  // The signed region must end at or before the embedded CS blob; otherwise
  // bytes in [cs_lo, signed_hi) are skipped from PageVerifier (RunStreamingPhases
  // streams only up to cs_lo) and tampering inside that range goes undetected.
  // Stash the validated sum on the verifier so RunStreamingPhases can reuse
  // it without recomputing — keeps the guard and the value paired.
  if (os_add_overflow(slice_.slice_offset, parsed_cd_.code_limit, &signed_hi_) ||
      signed_hi_ > slice_.cs_blob_offset) {
    last_error_ = "CodeDirectory codeLimit overlaps embedded code signature";
    FinalizeDigestDrainingToEof();
    return Status::kMalformedSignature;
  }

  if (opts_.skip_page_hash) {
    // Substitute NoopHashTraits so the existing PageVerifierT<>
    // streaming machinery runs without crypto work. Status::kPagesMismatched
    // is structurally unreachable under this dispatch.
    return RunStreamingPhases<NoopHashTraits>();
  }
  switch (parsed_cd_.hash_type) {
    case CS_HASHTYPE_SHA1: return RunStreamingPhases<Sha1Traits>();
    case CS_HASHTYPE_SHA256: return RunStreamingPhases<Sha256Traits>();
    case CS_HASHTYPE_SHA256_TRUNCATED: return RunStreamingPhases<Sha256TruncatedTraits>();
    case CS_HASHTYPE_SHA384: return RunStreamingPhases<Sha384Traits>();
    default:
      last_error_ = "unsupported CD hashType";
      FinalizeDigestDrainingToEof();
      return Status::kMalformedSignature;
  }
}

}  // namespace santa
