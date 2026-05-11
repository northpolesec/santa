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

#include <CommonCrypto/CommonDigest.h>

__BEGIN_DECLS
#include <Kernel/kern/cs_blobs.h>
__END_DECLS

#import <XCTest/XCTest.h>

#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "Source/common/ScopedFile.h"
#include "Source/common/verifyinghasher/CountingMemoryFileReader.h"
#include "Source/common/verifyinghasher/FileReader.h"
#include "Source/common/verifyinghasher/MemoryFileReader.h"

using santa::ArchSelector;
using santa::CountingMemoryFileReader;
using santa::FdFileReader;
using santa::MemoryFileReader;
using santa::VerifyingHasherCore;

namespace {

#if defined(__arm64__) || defined(__aarch64__)
// macOS system binaries on arm64 are arm64e-only, so prefer arm64e here.
constexpr ArchSelector kHostArch = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E};
#else
constexpr ArchSelector kHostArch = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
#endif

std::vector<uint8_t> Slurp(const char* path) {
  santa::ScopedFile sf(::open(path, O_RDONLY | O_CLOEXEC));
  if (sf.UnsafeFD() < 0) return {};
  struct stat st{};
  if (::fstat(sf.UnsafeFD(), &st) != 0) return {};
  std::vector<uint8_t> v(st.st_size);
  ssize_t n = ::pread(sf.UnsafeFD(), v.data(), v.size(), 0);
  if (n != static_cast<ssize_t>(v.size())) return {};
  return v;
}

std::string HexLower(std::span<const uint8_t> bytes) {
  static const char* kHex = "0123456789abcdef";
  std::string s(bytes.size() * 2, '\0');
  for (size_t i = 0; i < bytes.size(); ++i) {
    s[2 * i] = kHex[(bytes[i] >> 4) & 0xF];
    s[2 * i + 1] = kHex[bytes[i] & 0xF];
  }
  return s;
}

std::string ShasumOf(const char* path) {
  std::string cmd = std::string("shasum -a 256 ") + path + " | awk '{print $1}' | tr -d '\n'";
  FILE* p = popen(cmd.c_str(), "r");
  if (!p) return {};
  std::string out;
  char buf[256];
  while (size_t n = fread(buf, 1, sizeof(buf), p))
    out.append(buf, n);
  pclose(p);
  return out;
}

// Walks a CS SuperBlob, finds the picked CodeDirectory (highest hashRank),
// and returns its 20-byte cdhash. Independent of CodeSignatureParser.
// Returns empty vector on any structural problem — the test uses real
// signed binaries where the structure is known good.
std::vector<uint8_t> ReferenceCdHash(std::span<const uint8_t> cs_blob) {
  if (cs_blob.size() < sizeof(CS_SuperBlob)) return {};
  const auto* sb = reinterpret_cast<const CS_SuperBlob*>(cs_blob.data());
  if (OSSwapBigToHostInt32(sb->magic) != CSMAGIC_EMBEDDED_SIGNATURE) return {};
  const uint32_t sb_len = OSSwapBigToHostInt32(sb->length);
  const uint32_t sb_count = OSSwapBigToHostInt32(sb->count);
  if (sb_len > cs_blob.size()) return {};

  auto rank = [](uint8_t ht) -> int {
    switch (ht) {
      case CS_HASHTYPE_SHA1: return 1;
      case CS_HASHTYPE_SHA256_TRUNCATED: return 2;
      case CS_HASHTYPE_SHA256: return 3;
      case CS_HASHTYPE_SHA384: return 4;
      default: return 0;
    }
  };

  const auto* idxs = reinterpret_cast<const CS_BlobIndex*>(cs_blob.data() + sizeof(CS_SuperBlob));
  const uint8_t* picked_base = nullptr;
  size_t picked_len = 0;
  uint8_t picked_type = 0;
  int picked_rank = 0;
  for (uint32_t i = 0; i < sb_count; ++i) {
    const uint32_t slot = OSSwapBigToHostInt32(idxs[i].type);
    const uint32_t off = OSSwapBigToHostInt32(idxs[i].offset);
    const bool is_canon = (slot == CSSLOT_CODEDIRECTORY);
    const bool is_alt =
        (slot >= CSSLOT_ALTERNATE_CODEDIRECTORIES && slot < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT);
    if (!is_canon && !is_alt) continue;
    if (off + 8 > sb_len) return {};
    const auto* cd = reinterpret_cast<const CS_CodeDirectory*>(cs_blob.data() + off);
    if (OSSwapBigToHostInt32(cd->magic) != CSMAGIC_CODEDIRECTORY) continue;
    const uint32_t cd_len = OSSwapBigToHostInt32(cd->length);
    if (off + cd_len > sb_len) return {};
    const int r = rank(cd->hashType);
    if (r > picked_rank) {
      picked_rank = r;
      picked_base = cs_blob.data() + off;
      picked_len = cd_len;
      picked_type = cd->hashType;
    }
  }
  if (!picked_base) return {};

  uint8_t full[CC_SHA384_DIGEST_LENGTH];
  switch (picked_type) {
    case CS_HASHTYPE_SHA1: CC_SHA1(picked_base, static_cast<CC_LONG>(picked_len), full); break;
    case CS_HASHTYPE_SHA256:
    case CS_HASHTYPE_SHA256_TRUNCATED:
      CC_SHA256(picked_base, static_cast<CC_LONG>(picked_len), full);
      break;
    case CS_HASHTYPE_SHA384: CC_SHA384(picked_base, static_cast<CC_LONG>(picked_len), full); break;
    default: return {};
  }
  return std::vector<uint8_t>(full, full + CS_CDHASH_LEN);
}

// Locates the CS blob bytes inside `bytes` for the host slice and returns
// them. Mirrors the test-private helper in CodeSignatureParserTest. Used
// in cdhash tests to build a reference value without calling our parser.
std::vector<uint8_t> ExtractCsBlobBytes(std::span<const uint8_t> bytes, cpu_type_t want) {
  if (bytes.size() < 4) return {};
  uint32_t magic = 0;
  std::memcpy(&magic, bytes.data(), 4);

  uint64_t slice_off = 0;
  if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
    if (bytes.size() < sizeof(struct fat_header)) return {};
    struct fat_header fh{};
    std::memcpy(&fh, bytes.data(), sizeof(fh));
    uint32_t n = OSSwapBigToHostInt32(fh.nfat_arch);
    if (sizeof(fh) + n * sizeof(struct fat_arch) > bytes.size()) return {};
    for (uint32_t i = 0; i < n; ++i) {
      struct fat_arch a{};
      std::memcpy(&a, bytes.data() + sizeof(fh) + i * sizeof(a), sizeof(a));
      cpu_type_t ct = static_cast<cpu_type_t>(OSSwapBigToHostInt32(a.cputype));
      if (ct == want) {
        slice_off = OSSwapBigToHostInt32(a.offset);
        break;
      }
    }
  }
  if (slice_off + sizeof(struct mach_header_64) > bytes.size()) return {};
  struct mach_header_64 mh{};
  std::memcpy(&mh, bytes.data() + slice_off, sizeof(mh));
  bool is64 = (mh.magic == MH_MAGIC_64);
  size_t hdr_sz = is64 ? sizeof(mh) : sizeof(struct mach_header);
  if (slice_off + hdr_sz + mh.sizeofcmds > bytes.size()) return {};
  const uint8_t* p = bytes.data() + slice_off + hdr_sz;
  uint64_t sig_off = 0, sig_size = 0;
  for (uint32_t i = 0; i < mh.ncmds; ++i) {
    struct load_command lcmd{};
    std::memcpy(&lcmd, p, sizeof(lcmd));
    if (lcmd.cmd == LC_CODE_SIGNATURE) {
      struct linkedit_data_command led{};
      std::memcpy(&led, p, sizeof(led));
      sig_off = slice_off + led.dataoff;
      sig_size = led.datasize;
      break;
    }
    p += lcmd.cmdsize;
  }
  if (sig_size == 0 || sig_off + sig_size > bytes.size()) return {};
  return std::vector<uint8_t>(bytes.data() + sig_off, bytes.data() + sig_off + sig_size);
}

// Simulates a file truncated between fstat() and a later pread(): Size()
// reports a larger value than the data actually contains, so a read past
// data_.size() returns 0 (EOF) while the verifier still believes there
// are more bytes to consume.
class TruncatedMemoryFileReader : public santa::FileReader {
 public:
  TruncatedMemoryFileReader(std::vector<uint8_t> data, off_t claimed_size)
      : data_(std::move(data)), claimed_size_(claimed_size) {}
  ssize_t Pread(void* buf, size_t len, off_t off) override {
    if (off < 0) {
      errno = EINVAL;
      return -1;
    }
    if (static_cast<size_t>(off) >= data_.size()) return 0;
    size_t available = data_.size() - static_cast<size_t>(off);
    size_t n = std::min(len, available);
    std::memcpy(buf, data_.data() + off, n);
    return static_cast<ssize_t>(n);
  }
  off_t Size() const override { return claimed_size_; }

 private:
  std::vector<uint8_t> data_;
  off_t claimed_size_;
};

// Mirror of TruncatedMemoryFileReader in the opposite direction: the
// reader holds `data` bytes but reports Size() < data.size(). Pread
// still honors `len`, so over-serving manifests via `n > claimed_size_
// - off` rather than `n > len`. Models the production scenario where
// the file has grown between fstat (at Run() entry) and a later pread.
class OverservingMemoryFileReader : public santa::FileReader {
 public:
  OverservingMemoryFileReader(std::vector<uint8_t> data, off_t claimed_size)
      : data_(std::move(data)), claimed_size_(claimed_size) {}
  ssize_t Pread(void* buf, size_t len, off_t off) override {
    if (off < 0) {
      errno = EINVAL;
      return -1;
    }
    if (static_cast<size_t>(off) >= data_.size()) return 0;
    size_t available = data_.size() - static_cast<size_t>(off);
    size_t n = std::min(len, available);
    std::memcpy(buf, data_.data() + off, n);
    return static_cast<ssize_t>(n);
  }
  off_t Size() const override { return claimed_size_; }

 private:
  std::vector<uint8_t> data_;
  off_t claimed_size_;
};

}  // namespace

@interface VerifyingHasherCoreTest : XCTestCase
@end

@implementation VerifyingHasherCoreTest

- (void)testRunOnRealSignedBinary {
  auto bytes = Slurp("/usr/bin/yes");
  XCTAssertFalse(bytes.empty());
  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kOk, @"Run: %s",
                 std::string(v.LastError()).c_str());
  XCTAssertTrue(v.PagesMatched());

  std::string mine = HexLower(v.FullFileDigest());
  std::string sha = ShasumOf("/usr/bin/yes");
  XCTAssertEqual(mine, sha);
}

- (void)testDetectsTamperOnCopy {
  const char* tmp = std::getenv("TMPDIR");
  if (!tmp) tmp = "/tmp";
  std::string tampered = std::string(tmp) + "/yes_tampered_cdverifier";
  std::string cp = "cp /usr/bin/yes " + tampered;
  XCTAssertEqual(std::system(cp.c_str()), 0);

  // Flip a byte 3/4 of the way through the file. /usr/bin/yes is a
  // fat binary with x86_64 in the lower half and arm64e in the upper
  // half, so this reliably lands inside the arm64e signed region.
  auto bytes = Slurp(tampered.c_str());
  if (bytes.empty()) {
    XCTFail(@"Slurp returned empty bytes for %s", tampered.c_str());
    std::remove(tampered.c_str());
    return;
  }
  bytes[3 * bytes.size() / 4] ^= 0xFF;

  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kPagesMismatched);
  XCTAssertFalse(v.PagesMatched());
  XCTAssertGreaterThanOrEqual(v.Mismatches(), 1u);
  XCTAssertGreaterThanOrEqual(v.MismatchedSlots().size(), 1u);
  std::remove(tampered.c_str());
}

- (void)testRejectsNonMachO {
  auto bytes = Slurp("/etc/hosts");
  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kNotMachO);
  // Digest must still be populated.
  XCTAssertFalse(v.FullFileDigest().empty());
  XCTAssertEqual(v.FullFileDigest().size(), 32u);
}

- (void)testArchMismatchOnFat {
  auto bytes = Slurp("/usr/bin/file");
  MemoryFileReader r(bytes);
  ArchSelector bogus{static_cast<cpu_type_t>(0xDEADBEEFu), 0};
  VerifyingHasherCore v(r, bogus);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kSliceNotFound);
}

- (void)testIoErrorPropagated {
  auto bytes = Slurp("/usr/bin/yes");
  MemoryFileReader r(bytes);
  r.ScheduleErrorOnNextPread();  // first Pread (header phase) will fail
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kIoError);
  // F8: digest must be empty on kIoError (not 32 zero bytes), so a caller
  // that ignores Status can't silently consume an unfinalized digest.
  XCTAssertTrue(v.FullFileDigest().empty());
}

// Phase 5 (tail) used to silently `break` when pread returned 0 with
// cursor_ < total, finalizing the digest over only a prefix of the
// file. The fix classifies that as kIoError, matching phases 1 and 3.
// We simulate the trigger with a reader that claims a larger Size()
// than its actual data — the verifier completes header / cs-blob /
// signed-region phases normally, then the tail drain hits EOF early.
- (void)testTailEofClassifiedAsIoError {
  auto bytes = Slurp("/usr/bin/yes");
  XCTAssertFalse(bytes.empty());
  const off_t real_size = static_cast<off_t>(bytes.size());
  TruncatedMemoryFileReader r(std::move(bytes), real_size + 1024 * 1024);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kIoError);
  XCTAssertTrue(v.FullFileDigest().empty());
  XCTAssertNotEqual(std::string(v.LastError()).find("tail"), std::string::npos,
                    @"LastError should point at the tail phase: %s",
                    std::string(v.LastError()).c_str());
}

// Header-phase analog of testTailEofClassifiedAsIoError. A reader that
// claims a larger Size() than its data can serve must trigger kIoError
// (not kNotMachO / kNoSignature) if Pread returns 0 while cursor_ <
// total — otherwise FinalizeDigestDrainingToEof would publish a digest
// over only a prefix of the file. Truncating /usr/bin/yes to ~100 bytes
// (fat header + arch table + partial slice load commands) is mid-header:
// HeaderParser stays in kNeedMore after the first Pread, then the next
// Pread hits EOF early.
- (void)testHeaderEofClassifiedAsIoError {
  auto bytes = Slurp("/usr/bin/yes");
  XCTAssertFalse(bytes.empty());
  const off_t real_size = static_cast<off_t>(bytes.size());
  bytes.resize(100);
  TruncatedMemoryFileReader r(std::move(bytes), real_size);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kIoError);
  XCTAssertTrue(v.FullFileDigest().empty());
  XCTAssertNotEqual(std::string(v.LastError()).find("header"), std::string::npos,
                    @"LastError should point at the header phase: %s",
                    std::string(v.LastError()).c_str());
}

// Symmetric to testHeaderEofClassifiedAsIoError: a reader that holds more
// bytes than its Size() declares (modeling fstat / pread divergence when
// the file grows mid-verification) must trip kIoError in the header
// phase rather than silently hashing the over-served bytes. The fix
// closes a soundness gap that would otherwise produce kOk with a
// SHA-256 over more bytes than Size() reported.
- (void)testHeaderOverservingClassifiedAsIoError {
  auto bytes = Slurp("/usr/bin/yes");
  XCTAssertFalse(bytes.empty());
  // Claim one fewer byte than we hold. The first Pread will serve the
  // full buffer (claimed_size + 1 bytes), tripping the over-serve check.
  const off_t claimed = static_cast<off_t>(bytes.size() - 1);
  OverservingMemoryFileReader r(std::move(bytes), claimed);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kIoError);
  XCTAssertTrue(v.FullFileDigest().empty());
  XCTAssertNotEqual(std::string(v.LastError()).find("header"), std::string::npos,
                    @"LastError should point at the header phase: %s",
                    std::string(v.LastError()).c_str());
}

- (void)testSinglePassInvariant {
  auto bytes = Slurp("/usr/bin/yes");
  XCTAssertFalse(bytes.empty());
  CountingMemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertTrue(s == VerifyingHasherCore::Status::kOk ||
                s == VerifyingHasherCore::Status::kPagesMismatched);
  const uint32_t mx = r.MaxReadsAnyByte();
  XCTAssertLessThanOrEqual(mx, 1u, @"single-pass invariant violated: max reads = %u", mx);
}

// Verifies that the digest is populated on kMalformedSignature, per spec
// "always populated unless kIoError".
- (void)testDigestPopulatedOnMalformedCs {
  // Take /usr/bin/yes, scribble all-zeros over the embedded CS blob to
  // force kMalformedSignature. Use a real-binary copy and locate the CS
  // blob bounds via a quick read of the load commands. (Easier path:
  // synthetically corrupt the leading 4 bytes of the blob region in the
  // in-memory bytes copy after VerifyingHasherCore has parsed enough — but we
  // can't access internal state. Instead, just zero the last 4 KB of
  // the file, which lands in or near the CS blob for /usr/bin/yes.)
  auto bytes = Slurp("/usr/bin/yes");
  if (bytes.size() < 32768u) {
    XCTFail(@"Slurp returned %zu bytes; need >= 32768", bytes.size());
    return;
  }
  // Zero the last 32 KB to corrupt the CS blob (which sits at the end
  // of the host slice; arm64e CS blob is ~18 KB, so 32 KB is enough to
  // wipe the SuperBlob/CodeDirectory magic regardless of selected slice).
  std::memset(bytes.data() + bytes.size() - 32768, 0, 32768);

  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  // Should not be kOk. Common outcomes: kMalformedSignature.
  XCTAssertNotEqual(s, VerifyingHasherCore::Status::kOk);
  XCTAssertNotEqual(s, VerifyingHasherCore::Status::kIoError);
  // Spec: digest populated for any non-IoError outcome.
  XCTAssertEqual(v.FullFileDigest().size(), 32u);
  // Confirm it's not all-zero (i.e., really finalized).
  bool all_zero = true;
  for (uint8_t b : v.FullFileDigest()) {
    if (b != 0) {
      all_zero = false;
      break;
    }
  }
  XCTAssertFalse(all_zero);
}

// Forces phase 1 to stop early (small buf_size on a real fat binary),
// so phase 3 streams, phase 4 feeds CS blob remainder, phase 5 drains
// the tail. Asserts the single-pass invariant on all paths.
- (void)testSinglePassInvariantSmallBuffer {
  auto bytes = Slurp("/usr/bin/file");  // fat, ~120-200 KB per slice
  XCTAssertFalse(bytes.empty());
  CountingMemoryFileReader r(bytes);
  VerifyingHasherCore::Options opts;
  opts.buf_size = 4096;  // forces multi-chunk phase 1 + non-trivial phases 3/5
  VerifyingHasherCore v(r, kHostArch, opts);
  auto s = v.Run();
  XCTAssertTrue(s == VerifyingHasherCore::Status::kOk ||
                s == VerifyingHasherCore::Status::kPagesMismatched);
  const uint32_t mx = r.MaxReadsAnyByte();
  XCTAssertLessThanOrEqual(mx, 1u, @"small-buffer SP invariant violated: max reads = %u", mx);
}

// Specifically exercises C1: malformed CS blob with a small buffer
// (so phase 1 doesn't reach cs_lo, RunCsBlobPhase takes the no-overlap
// branch and preads [cs_lo, cs_hi), then ParseCodeSignature fails and
// FinalizeDigestDrainingToEof must NOT re-read [cs_lo, cs_hi)).
- (void)testSinglePassOnMalformedCsSmallBuffer {
  auto bytes = Slurp("/usr/bin/file");
  if (bytes.size() < 32u * 1024u) {
    XCTFail(@"Slurp returned %zu bytes; need >= %u", bytes.size(), 32u * 1024u);
    return;
  }
  // Corrupt the trailing 32 KB to break the CS blob (sits near end).
  std::memset(bytes.data() + bytes.size() - 32 * 1024, 0, 32 * 1024);

  CountingMemoryFileReader r(bytes);
  VerifyingHasherCore::Options opts;
  opts.buf_size = 4096;
  VerifyingHasherCore v(r, kHostArch, opts);
  auto s = v.Run();
  // The corruption should land us at non-Ok / non-IoError.
  XCTAssertNotEqual(s, VerifyingHasherCore::Status::kOk);
  XCTAssertNotEqual(s, VerifyingHasherCore::Status::kIoError);
  // Single-pass invariant must hold even on failure paths.
  const uint32_t mx = r.MaxReadsAnyByte();
  XCTAssertLessThanOrEqual(mx, 1u, @"malformed-CS small-buf invariant violated: max reads = %u",
                           mx);
  // Digest must still be populated (spec: always except kIoError).
  XCTAssertEqual(v.FullFileDigest().size(), 32u);
  bool all_zero = true;
  for (uint8_t b : v.FullFileDigest()) {
    if (b != 0) {
      all_zero = false;
      break;
    }
  }
  XCTAssertFalse(all_zero);
}

// C4 regression: a CodeDirectory whose codeLimit overshoots the embedded CS
// blob's offset declares the blob itself as part of the signed region. The
// streaming pipeline only feeds [cursor_, cs_lo) into PageVerifier, so any
// pages whose bytes lie in [cs_lo, signed_hi) would silently miss tamper
// detection. VerifyingHasherCore must reject the CD before reaching that pipeline.
//
// We synthesize a thin 64-bit Mach-O with one LC_CODE_SIGNATURE pointing at
// an in-line valid SuperBlob/CodeDirectory whose codeLimit > dataoff. Slot
// hashes can be zeros — the C4 check fires before RunStreamingPhases.
- (void)testRejectsCodeLimitOverlappingCsBlob {
  constexpr uint32_t kTotal = 64u * 1024;
  constexpr uint32_t kDataoff = 16u * 1024;
  constexpr uint32_t kDatasize = 16u * 1024;
  constexpr uint32_t kCodeLimit = 32u * 1024;  // > kDataoff: extends into CS blob
  constexpr uint32_t kPageSize = 4096;
  constexpr uint32_t kPageCount = (kCodeLimit + kPageSize - 1) / kPageSize;  // 8

  std::vector<uint8_t> data(kTotal, 0);

  struct mach_header_64 mh{};
  mh.magic = MH_MAGIC_64;
  mh.cputype = CPU_TYPE_X86_64;
  mh.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 1;
  mh.sizeofcmds = sizeof(struct linkedit_data_command);
  std::memcpy(data.data(), &mh, sizeof(mh));

  struct linkedit_data_command lc{};
  lc.cmd = LC_CODE_SIGNATURE;
  lc.cmdsize = sizeof(lc);
  lc.dataoff = kDataoff;
  lc.datasize = kDatasize;
  std::memcpy(data.data() + sizeof(mh), &lc, sizeof(lc));

  uint8_t* sb_base = data.data() + kDataoff;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + kPageCount * 32;
  const size_t total_cs_size = cd_off + cd_sz;
  XCTAssertLessThanOrEqual(total_cs_size, static_cast<size_t>(kDatasize));

  auto* sb = reinterpret_cast<CS_SuperBlob*>(sb_base);
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total_cs_size));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(sb_base + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(sb_base + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(kPageCount);
  cd->hashSize = 32;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;  // 4 KiB

  MemoryFileReader reader(data);
  ArchSelector want{CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
  VerifyingHasherCore v(reader, want);
  auto s = v.Run();
  XCTAssertEqual(s, VerifyingHasherCore::Status::kMalformedSignature);
  XCTAssertTrue(std::string(v.LastError()).find("overlaps") != std::string::npos);

  // Spec: post-parse kMalformedSignature paths leave cdhash populated.
  // The CD itself parsed cleanly; only the surrounding Mach-O state failed
  // a structural check (codeLimit overlapping the CS blob). The cdhash is
  // a property of the parsed CD and remains the correct identifier.
  uint8_t expected_full[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(sb_base + cd_off, static_cast<CC_LONG>(cd_sz), expected_full);
  if (v.CDHash().size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"CDHash size = %zu; expected %d", v.CDHash().size(), CS_CDHASH_LEN);
    return;
  }
  XCTAssertEqual(0, std::memcmp(v.CDHash().data(), expected_full, CS_CDHASH_LEN));
}

- (void)testCdHashMatchesIndependentReference {
  auto bytes = Slurp("/usr/bin/yes");
  if (bytes.empty()) {
    XCTFail(@"Slurp returned empty");
    return;
  }
  auto cs_blob = ExtractCsBlobBytes(bytes, kHostArch.cputype);
  if (cs_blob.empty()) {
    XCTFail(@"ExtractCsBlobBytes returned empty");
    return;
  }
  auto expected = ReferenceCdHash(cs_blob);
  if (expected.size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"ReferenceCdHash returned size %zu; expected %d", expected.size(), CS_CDHASH_LEN);
    return;
  }

  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  XCTAssertEqual(v.Run(), VerifyingHasherCore::Status::kOk, @"Run: %s",
                 std::string(v.LastError()).c_str());
  auto got = v.CDHash();
  if (got.size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"CDHash size = %zu; expected %d", got.size(), CS_CDHASH_LEN);
    return;
  }
  XCTAssertEqual(0, std::memcmp(got.data(), expected.data(), CS_CDHASH_LEN));
}

- (void)testCdHashEmptyOnMalformedSignature {
  auto bytes = Slurp("/usr/bin/yes");
  if (bytes.size() < 32u * 1024u) {
    XCTFail(@"Slurp returned %zu bytes; need >= %u", bytes.size(), 32u * 1024u);
    return;
  }
  std::memset(bytes.data() + bytes.size() - 32 * 1024, 0, 32 * 1024);

  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, kHostArch);
  auto s = v.Run();
  XCTAssertNotEqual(s, VerifyingHasherCore::Status::kOk);
  XCTAssertNotEqual(s, VerifyingHasherCore::Status::kIoError);
  XCTAssertTrue(v.CDHash().empty(), @"CDHash must be empty when ParseCodeSignature returns false");
}

- (void)testCdHashInvariantAcrossBufferSizes {
  // The CS blob can land in one of three RunCsBlobPhase branches depending
  // on how much of the file phase-1 already preadded. Forcing a small
  // buf_size pushes us off the "full overlap" branch onto partial / no-
  // overlap, where the parser sees the same byte sequence but assembled
  // from different sources. cdhash must be byte-identical across all paths.
  auto bytes = Slurp("/usr/bin/file");  // fat binary, multi-slice
  if (bytes.empty()) {
    XCTFail(@"Slurp returned empty");
    return;
  }

  MemoryFileReader r1(bytes);
  VerifyingHasherCore v1(r1, kHostArch);  // default buf_size = 1 MiB
  XCTAssertEqual(v1.Run(), VerifyingHasherCore::Status::kOk, @"Run(default): %s",
                 std::string(v1.LastError()).c_str());
  auto cdhash_default = v1.CDHash();
  if (cdhash_default.size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"cdhash_default size = %zu; expected %d", cdhash_default.size(), CS_CDHASH_LEN);
    return;
  }

  MemoryFileReader r2(bytes);
  VerifyingHasherCore::Options small;
  small.buf_size = 4096;
  VerifyingHasherCore v2(r2, kHostArch, small);
  XCTAssertEqual(v2.Run(), VerifyingHasherCore::Status::kOk, @"Run(small): %s",
                 std::string(v2.LastError()).c_str());
  auto cdhash_small = v2.CDHash();
  if (cdhash_small.size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"cdhash_small size = %zu; expected %d", cdhash_small.size(), CS_CDHASH_LEN);
    return;
  }

  XCTAssertEqual(0, std::memcmp(cdhash_default.data(), cdhash_small.data(), CS_CDHASH_LEN));
}

// hw_universal — fat32 binary (arm64 + x86_64) where each slice carries
// four CodeDirectories: SHA-1, SHA-256, SHA-256-TRUNCATED, SHA-384. This
// is the only fixture that exercises the strongest-CD picker on a real
// signed binary (the existing /usr/bin/yes fixture has only one SHA-256
// CD per slice).
//
// Tests use ReferenceCdHash for the expected cdhash rather than hard-coded
// hex bytes — Mach-O builds aren't bit-for-bit reproducible (UUID, build
// version, codesign timestamps), so a regenerated hw_universal would have
// different cdhashes. The reference helper computes per-binary so the
// tests survive `Fuzzing/regenerate_corpus.sh` runs.
- (void)checkHwUniversalForArch:(cpu_type_t)cputype subtype:(cpu_subtype_t)cpusubtype {
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  NSString* path = [bundle.resourcePath stringByAppendingPathComponent:@"testdata/hw_universal"];
  auto bytes = Slurp(path.UTF8String);
  if (bytes.empty()) {
    XCTFail(@"hw_universal not bundled at %@", path);
    return;
  }

  auto cs_blob = ExtractCsBlobBytes(bytes, cputype);
  if (cs_blob.empty()) {
    XCTFail(@"ExtractCsBlobBytes returned empty");
    return;
  }
  auto expected = ReferenceCdHash(cs_blob);
  if (expected.size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"ReferenceCdHash returned size %zu; expected %d", expected.size(), CS_CDHASH_LEN);
    return;
  }

  MemoryFileReader r(bytes);
  VerifyingHasherCore v(r, ArchSelector{cputype, cpusubtype});
  XCTAssertEqual(v.Run(), VerifyingHasherCore::Status::kOk, @"Run: %s",
                 std::string(v.LastError()).c_str());
  XCTAssertTrue(v.PagesMatched());
  // Picks the strongest CD: SHA-384 wins over SHA-256, SHA-256-TRUNCATED, SHA-1.
  XCTAssertEqual(v.ParsedCD().hash_type, CS_HASHTYPE_SHA384);

  auto got = v.CDHash();
  if (got.size() != static_cast<size_t>(CS_CDHASH_LEN)) {
    XCTFail(@"CDHash size = %zu; expected %d", got.size(), CS_CDHASH_LEN);
    return;
  }
  XCTAssertEqual(0, std::memcmp(got.data(), expected.data(), CS_CDHASH_LEN));
}

- (void)testHwUniversalArm64 {
  [self checkHwUniversalForArch:CPU_TYPE_ARM64 subtype:CPU_SUBTYPE_ARM64_ALL];
}

- (void)testHwUniversalX86_64 {
  [self checkHwUniversalForArch:CPU_TYPE_X86_64 subtype:CPU_SUBTYPE_X86_64_ALL];
}

@end
