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

#include "Source/common/verifyinghasher/HeaderParser.h"

#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <os/overflow.h>

#include <algorithm>
#include <cstring>

namespace santa {

namespace {

// Cap on LC_CODE_SIGNATURE.datasize. xnu has no explicit cap, but its
// load_code_signature (mach_loader.c:3861) routes the allocation through
// ubc_cs_blob_allocate which uses kernel memory (kalloc/kmem_alloc) —
// kernel memory pressure is xnu's implicit cap. Userspace heap is much
// larger, so without a cap a malicious datasize would drive a multi-GB
// cs_blob_buf_ allocation that xnu would have rejected at the allocator.
// 64 MiB is Santa's userspace equivalent of xnu's implicit kernel-memory
// bound: comfortably above any realistic CS blob (a 5 GiB binary on
// Apple Silicon has ~10 MiB of slot hashes; on Intel ~40 MiB) while
// bounding worst-case memory on the ES_AUTH_EXEC hot path.
constexpr uint32_t kMaxCsBlobSize = 64u * 1024 * 1024;

// Cap on the load-commands region (mach_header.sizeofcmds). xnu has a
// structural cap (parse_machfile in mach_loader.c:1373-1377 rejects when
// page-rounded `mach_header_sz + sizeofcmds > INT_MAX`, ~2 GiB), then
// allocates kernel memory via kalloc_data which is bounded implicitly by
// kernel-memory pressure. Userspace heap is much larger, so without our
// own cap a malicious slice can declare sizeofcmds up to slice_size and
// force multi-MB-to-GB allocations in HeaderParser::scratch_ and
// VerifyingHasherCore::header_phase_buf_ on Santa's ES_AUTH_EXEC hot path.
//
// Sampling Apple-shipped + 3rd-party + Xcode binaries, the
// largest observed sizeofcmds is ~19 KiB (CoreRE.framework, 377 ncmds);
// most binaries are well under 10 KiB regardless of file size. 1 MiB
// gives ~55x headroom over the worst real binary while keeping the
// per-call memory budget tight — sizeofcmds doesn't scale with binary
// size, so a tight cap costs nothing in false-positives.
constexpr uint32_t kMaxSizeOfCmds = 1u << 20;  // 1 MiB

constexpr cpu_subtype_t MaskSubtype(cpu_subtype_t s) {
  return static_cast<cpu_subtype_t>(s & ~CPU_SUBTYPE_MASK);
}

const char* ArchName(cpu_type_t t) {
  switch (t) {
    case CPU_TYPE_ARM64: return "arm64";  // arm64 vs arm64e disambiguated by cpusubtype
    case CPU_TYPE_X86_64: return "x86_64";
    default: return "unknown";
  }
}

}  // namespace

HeaderParser::HeaderParser(ArchSelector want, uint64_t total_file_size) : want_(want) {
  slice_.total_file_size = total_file_size;
  AdvanceToPhase(Phase::kNeedMagic, /*off=*/0, /*len=*/4);
}

std::optional<uint64_t> HeaderParser::SliceOffsetIfKnown() const {
  switch (phase_) {
    case Phase::kNeedSliceMachHeader:
    case Phase::kNeedLoadCommands:
    case Phase::kReady: return slice_.slice_offset;
    default: return std::nullopt;
  }
}

HeaderParser::Status HeaderParser::SetError(std::string msg) {
  error_ = std::move(msg);
  phase_ = Phase::kError;
  state_ = Status::kError;
  return state_;
}

void HeaderParser::AdvanceToPhase(Phase p, uint64_t off, size_t len) {
  phase_ = p;
  want_off_ = off;
  want_len_ = len;
  scratch_.clear();
  scratch_.reserve(len);
}

void HeaderParser::AdvanceToPhaseKeepingScratch(Phase p, uint64_t next_off, size_t total_len) {
  // Keep scratch_ contents (already-consumed bytes) and extend the region
  // so that future bytes from `next_off` onward fill the remainder of
  // total_len. Used when the next phase's region overlaps with bytes
  // already collected (e.g., the magic at file offset 0 is the first 4
  // bytes of the fat_header / mach_header that starts at file offset 0).
  phase_ = p;
  want_off_ = next_off;
  want_len_ = total_len;
  scratch_.reserve(total_len);
}

HeaderParser::Status HeaderParser::Update(const uint8_t* data, size_t len, uint64_t chunk_off) {
  while (len > 0 && state_ == Status::kNeedMore) {
    // Skip bytes before want_off_.
    if (chunk_off + len <= want_off_) return state_;
    if (chunk_off < want_off_) {
      uint64_t skip = want_off_ - chunk_off;
      data += skip;
      len -= skip;
      chunk_off += skip;
    }
    // Now chunk_off >= want_off_; check we haven't drifted past want_off_.
    if (chunk_off > want_off_) {
      return SetError("chunk past expected offset (out-of-order feed?)");
    }
    // Copy what we can.
    size_t need = want_len_ - scratch_.size();
    size_t take = std::min(len, need);
    scratch_.insert(scratch_.end(), data, data + take);
    data += take;
    len -= take;
    chunk_off += take;
    // Advance want_off_ so it always points at the next file offset
    // we expect to receive. This way, partial reads across chunk
    // boundaries don't trip the "chunk past expected offset" check.
    want_off_ += take;

    if (scratch_.size() < want_len_) return state_;

    // Region complete; dispatch.
    Status s = state_;
    switch (phase_) {
      case Phase::kNeedMagic: s = ProcessMagic(); break;
      case Phase::kNeedFatHeader: s = ProcessFatHeader(); break;
      case Phase::kNeedFatArchTable: s = ProcessFatArchTable(); break;
      case Phase::kNeedSliceMachHeader: s = ProcessSliceMachHeader(); break;
      case Phase::kNeedLoadCommands: s = ProcessLoadCommands(); break;
      case Phase::kReady:
      case Phase::kError: break;
    }
    state_ = s;
    if (state_ != Status::kNeedMore) break;
  }
  return state_;
}

HeaderParser::Status HeaderParser::ProcessMagic() {
  if (slice_.total_file_size < 4) return SetError("file too small for magic");
  uint32_t magic = 0;
  std::memcpy(&magic, scratch_.data(), 4);
  if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
    // Thin Mach-O. Magic is the first 4 bytes of mach_header; keep it
    // and read the rest of the header from offset 4.
    slice_.slice_offset = 0;
    slice_.slice_size = slice_.total_file_size;
    slice_.arch_name = "thin";
    AdvanceToPhaseKeepingScratch(Phase::kNeedSliceMachHeader,
                                 /*next_off=*/4, sizeof(struct mach_header));
    return Status::kNeedMore;
  }
  if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
    fat64_ = false;
    AdvanceToPhaseKeepingScratch(Phase::kNeedFatHeader,
                                 /*next_off=*/4, sizeof(struct fat_header));
    return Status::kNeedMore;
  }
  if (magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
    // xnu's exec path doesn't handle fat64 — mach_loader.c's fat
    // dispatch and fatfile_validate_fatarches both only recognize
    // FAT_MAGIC. dyld in userspace does load fat64 dylibs, so we
    // accept it here for dylib verification. For exec, the gap is
    // benign: a fat64 binary we accept but xnu rejects simply fails
    // LOAD_BADMACHO at exec time (Santa-permissive, no execution gained).
    fat64_ = true;
    AdvanceToPhaseKeepingScratch(Phase::kNeedFatHeader,
                                 /*next_off=*/4, sizeof(struct fat_header));
    return Status::kNeedMore;
  }
  char buf[40];
  std::snprintf(buf, sizeof(buf), "not a Mach-O (magic=0x%08x)", magic);
  return SetError(buf);
}

HeaderParser::Status HeaderParser::ProcessFatHeader() {
  struct fat_header fh{};
  std::memcpy(&fh, scratch_.data(), sizeof(fh));
  nfat_ = OSSwapBigToHostInt32(fh.nfat_arch);
  if (nfat_ > 64) return SetError("corrupt fat header (implausible arch count)");
  const size_t entry_sz = fat64_ ? sizeof(struct fat_arch_64) : sizeof(struct fat_arch);
  AdvanceToPhase(Phase::kNeedFatArchTable, sizeof(fh), nfat_ * entry_sz);
  return Status::kNeedMore;
}

HeaderParser::Status HeaderParser::ProcessFatArchTable() {
  if (fat64_) {
    const auto* archs = reinterpret_cast<const struct fat_arch_64*>(scratch_.data());
    for (uint32_t i = 0; i < nfat_; ++i) {
      cpu_type_t ct = static_cast<cpu_type_t>(OSSwapBigToHostInt32(archs[i].cputype));
      cpu_subtype_t st = static_cast<cpu_subtype_t>(OSSwapBigToHostInt32(archs[i].cpusubtype));
      uint64_t off = OSSwapBigToHostInt64(archs[i].offset);
      uint64_t sz = OSSwapBigToHostInt64(archs[i].size);
      if (ct == want_.cputype && MaskSubtype(st) == MaskSubtype(want_.cpusubtype)) {
        if (off > slice_.total_file_size || sz > slice_.total_file_size - off) {
          return SetError("corrupt fat header (slice out of range)");
        }
        slice_.slice_offset = off;
        slice_.slice_size = sz;
        slice_.arch_name = ArchName(ct);
        AdvanceToPhase(Phase::kNeedSliceMachHeader, off, sizeof(struct mach_header));
        return Status::kNeedMore;
      }
    }
  } else {
    const auto* archs = reinterpret_cast<const struct fat_arch*>(scratch_.data());
    for (uint32_t i = 0; i < nfat_; ++i) {
      cpu_type_t ct = static_cast<cpu_type_t>(OSSwapBigToHostInt32(archs[i].cputype));
      cpu_subtype_t st = static_cast<cpu_subtype_t>(OSSwapBigToHostInt32(archs[i].cpusubtype));
      uint64_t off = OSSwapBigToHostInt32(archs[i].offset);
      uint64_t sz = OSSwapBigToHostInt32(archs[i].size);
      if (ct == want_.cputype && MaskSubtype(st) == MaskSubtype(want_.cpusubtype)) {
        if (off > slice_.total_file_size || sz > slice_.total_file_size - off) {
          return SetError("corrupt fat header (slice out of range)");
        }
        slice_.slice_offset = off;
        slice_.slice_size = sz;
        slice_.arch_name = ArchName(ct);
        AdvanceToPhase(Phase::kNeedSliceMachHeader, off, sizeof(struct mach_header));
        return Status::kNeedMore;
      }
    }
  }
  return SetError("no matching slice in fat binary");
}

HeaderParser::Status HeaderParser::ProcessSliceMachHeader() {
  if (scratch_.size() < sizeof(struct mach_header)) {
    return SetError("slice too small for mach_header");
  }
  struct mach_header mh{};
  std::memcpy(&mh, scratch_.data(), sizeof(mh));

  switch (mh.magic) {
    case MH_MAGIC:
      mh_is_64_ = false;
      mh_swap_ = false;
      break;
    case MH_CIGAM:
      mh_is_64_ = false;
      mh_swap_ = true;
      break;
    case MH_MAGIC_64:
      mh_is_64_ = true;
      mh_swap_ = false;
      break;
    case MH_CIGAM_64:
      mh_is_64_ = true;
      mh_swap_ = true;
      break;
    default: return SetError("bad slice mach_header magic");
  }

  // Validate arch when slice was reached via thin path (no fat-table check).
  // For fat slices we deliberately do NOT cross-check the inner mach_header
  // cputype/cpusubtype against the fat_arch entry that selected this slice,
  // even though xnu does (kern_exec.c sets imgp->ip_origcputype from
  // fat_arch.cputype, then enforces inner-vs-outer equality after
  // parse_machfile, returning EBADARCH on mismatch).
  //
  // We skip it because CD verification doesn't depend on the inner cputype:
  // slot hashes are over the slice bytes regardless of what cputype claims,
  // so our verdict is correct either way. Skipping keeps us out of the
  // false-positive direction — if a binary slipped past us with mismatched
  // inner metadata, xnu's EBADARCH still blocks exec, so nothing runs.
  if (slice_.arch_name == "thin") {
    cpu_type_t ct = static_cast<cpu_type_t>(
        mh_swap_ ? OSSwapInt32(static_cast<uint32_t>(mh.cputype)) : mh.cputype);
    cpu_subtype_t st = static_cast<cpu_subtype_t>(
        mh_swap_ ? OSSwapInt32(static_cast<uint32_t>(mh.cpusubtype)) : mh.cpusubtype);
    if (ct != want_.cputype || MaskSubtype(st) != MaskSubtype(want_.cpusubtype)) {
      return SetError("thin slice arch mismatch");
    }
    slice_.arch_name = ArchName(ct);
  }

  mh_ncmds_ = mh_swap_ ? OSSwapInt32(mh.ncmds) : mh.ncmds;
  mh_sizeofcmds_ = mh_swap_ ? OSSwapInt32(mh.sizeofcmds) : mh.sizeofcmds;

  const uint64_t hdr_sz = mh_is_64_ ? sizeof(struct mach_header_64) : sizeof(struct mach_header);
  if (hdr_sz + mh_sizeofcmds_ > slice_.slice_size) {
    return SetError("load commands extend past slice");
  }
  if (mh_sizeofcmds_ > kMaxSizeOfCmds) {
    return SetError("sizeofcmds implausibly large");
  }
  AdvanceToPhase(Phase::kNeedLoadCommands, slice_.slice_offset + hdr_sz, mh_sizeofcmds_);
  return Status::kNeedMore;
}

HeaderParser::Status HeaderParser::ProcessLoadCommands() {
  const uint8_t* p = scratch_.data();
  const uint8_t* end = p + scratch_.size();
  bool found_cs = false;
  uint64_t cs_off = 0;
  uint32_t cs_size = 0;
  for (uint32_t i = 0; i < mh_ncmds_; ++i) {
    // Use subtraction-safe `N > end - p` rather than `p + N > end`. The
    // latter computes p + lc.cmdsize before bounds-checking it, and
    // lc.cmdsize is attacker-controllable up to UINT32_MAX — the
    // resulting pointer can land far past one-past-the-end of scratch_,
    // which is undefined behavior. `end - p` is always within scratch_.
    if (sizeof(struct load_command) > static_cast<size_t>(end - p)) {
      return SetError("truncated load command");
    }
    struct load_command lc;
    std::memcpy(&lc, p, sizeof(lc));
    if (mh_swap_) {
      lc.cmd = OSSwapInt32(lc.cmd);
      lc.cmdsize = OSSwapInt32(lc.cmdsize);
    }
    if (lc.cmdsize < sizeof(struct load_command) || lc.cmdsize > static_cast<size_t>(end - p)) {
      return SetError("malformed load command size");
    }
    // Intentionally NOT enforcing cmdsize alignment. Apple's spec says
    // it must be a multiple of 4 (32-bit) or 8 (64-bit), but xnu doesn't
    // enforce it either (bsd/kern/mach_loader.c parse_machfile validates
    // cmdsize >= sizeof(load_command) + bounds, then walks via
    // p += cmdsize regardless of alignment). Adding the check here would
    // reject binaries xnu happily loads — a Santa false-positive — without
    // closing any attack, since our iteration matches xnu's exactly.
    // xnu silently uses the first LC_CODE_SIGNATURE via its per-vnode
    // CS blob cache (load_code_signature in mach_loader.c:3765 hits
    // the cache after the first add and never re-reads dataoff/datasize
    // of duplicates). Match that behavior — skip subsequent entries
    // rather than rejecting, since rejecting would be a Santa-only
    // false-positive on binaries xnu accepts.
    if (lc.cmd == LC_CODE_SIGNATURE && !found_cs) {
      // xnu requires exact equality (load_code_signature in
      // mach_loader.c: cmdsize != sizeof(linkedit_data_command) =>
      // LOAD_BADMACHO). Match that. Padding bytes wouldn't be read
      // anyway, but rejecting here keeps our verdict in lockstep
      // with xnu's, and any hypothetical future LC_CODE_SIGNATURE
      // extension would require coordinated changes here and in
      // xnu — so accepting `>` doesn't actually buy forward-compat.
      if (lc.cmdsize != sizeof(struct linkedit_data_command)) {
        return SetError("LC_CODE_SIGNATURE has wrong cmdsize");
      }
      struct linkedit_data_command led;
      std::memcpy(&led, p, sizeof(led));
      if (mh_swap_) {
        led.dataoff = OSSwapInt32(led.dataoff);
        led.datasize = OSSwapInt32(led.datasize);
      }
      // Bound the CS-blob region inside the slice (overflow-safe), and
      // cap its size at a sane upper bound. Without these checks a
      // malicious Mach-O could request a multi-GB allocation in
      // VerifyingHasherCore::cs_blob_buf_ or place the blob outside the slice.
      if (led.dataoff > slice_.slice_size || led.datasize > slice_.slice_size - led.dataoff) {
        return SetError("LC_CODE_SIGNATURE region outside slice");
      }
      if (led.datasize > kMaxCsBlobSize) {
        return SetError("LC_CODE_SIGNATURE datasize implausibly large");
      }
      if (os_add_overflow(slice_.slice_offset, static_cast<uint64_t>(led.dataoff), &cs_off)) {
        return SetError("LC_CODE_SIGNATURE offset overflows");
      }
      cs_size = led.datasize;
      found_cs = true;
    }
    p += lc.cmdsize;
  }
  if (!found_cs) return SetError("no embedded code signature");
  slice_.cs_blob_offset = cs_off;
  slice_.cs_blob_size = cs_size;
  phase_ = Phase::kReady;
  return Status::kReady;
}

}  // namespace santa
