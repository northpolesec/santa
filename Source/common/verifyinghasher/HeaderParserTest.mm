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

#import <XCTest/XCTest.h>

#include <errno.h>
#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "Source/common/ScopedFile.h"
#include "Source/common/verifyinghasher/MemoryFileReader.h"

using santa::ArchSelector;
using santa::HeaderParser;
using santa::MemoryFileReader;

namespace {

#if defined(__arm64__) || defined(__aarch64__)
// macOS system binaries on arm64 are arm64e-only, so prefer arm64e here.
constexpr ArchSelector kHostArch = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E};
#else
constexpr ArchSelector kHostArch = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
#endif

// hw_universal carries arm64 + x86_64 slices (no arm64e). Fat tests
// that drive the parser with the checked-in fixture must pick the
// slice actually present for the running host, not kHostArch.
#if defined(__arm64__) || defined(__aarch64__)
constexpr ArchSelector kHwUniversalArch = {CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL};
#else
constexpr ArchSelector kHwUniversalArch = {CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
#endif

// Read entire file into a vector for synthetic feed. Loops on pread so a
// short read or EINTR doesn't silently truncate to {} and surface as an
// opaque assertion failure later.
std::vector<uint8_t> Slurp(const char* path) {
  santa::ScopedFile sf(::open(path, O_RDONLY | O_CLOEXEC));
  if (sf.UnsafeFD() < 0) return {};
  struct stat st{};
  if (::fstat(sf.UnsafeFD(), &st) != 0) return {};
  std::vector<uint8_t> v(st.st_size);
  size_t off = 0;
  while (off < v.size()) {
    ssize_t n = ::pread(sf.UnsafeFD(), v.data() + off, v.size() - off, off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return {};
    }
    if (n == 0) return {};  // unexpected EOF before fstat-reported size
    off += static_cast<size_t>(n);
  }
  return v;
}

// Feed `data` to a fresh parser using chunks of size `chunk`. Returns
// final status, populates `out_slice` on kReady.
HeaderParser::Status FeedChunked(const std::vector<uint8_t>& data, ArchSelector want, size_t chunk,
                                 santa::SliceInfo* out_slice, std::string* out_err) {
  HeaderParser p(want, data.size());
  size_t off = 0;
  while (off < data.size()) {
    size_t n = std::min(chunk, data.size() - off);
    auto s = p.Update(data.data() + off, n, off);
    if (s != HeaderParser::Status::kNeedMore) {
      if (out_slice && s == HeaderParser::Status::kReady) *out_slice = p.Slice();
      if (out_err) *out_err = std::string(p.LastError());
      return s;
    }
    off += n;
  }
  if (out_err) *out_err = std::string(p.LastError());
  return p.status();
}

// Build a minimal 64-bit thin Mach-O of `total_size` bytes with one
// LC_CODE_SIGNATURE whose dataoff/datasize are caller-supplied. Bytes
// beyond the load-commands region are zero-filled.
std::vector<uint8_t> MakeThin64WithCsBlob(uint32_t cs_dataoff, uint32_t cs_datasize,
                                          uint64_t total_size) {
  constexpr cpu_type_t kCpuType = CPU_TYPE_X86_64;
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_64_ALL;
  struct mach_header_64 mh{};
  mh.magic = MH_MAGIC_64;
  mh.cputype = kCpuType;
  mh.cpusubtype = kCpuSubtype;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 1;
  mh.sizeofcmds = sizeof(struct linkedit_data_command);
  mh.flags = 0;
  mh.reserved = 0;

  struct linkedit_data_command lc{};
  lc.cmd = LC_CODE_SIGNATURE;
  lc.cmdsize = sizeof(lc);
  lc.dataoff = cs_dataoff;
  lc.datasize = cs_datasize;

  std::vector<uint8_t> data(total_size, 0);
  std::memcpy(data.data(), &mh, sizeof(mh));
  std::memcpy(data.data() + sizeof(mh), &lc, sizeof(lc));
  return data;
}

}  // namespace

@interface HeaderParserTest : XCTestCase
@end

@implementation HeaderParserTest

- (NSString*)hwUniversalFixturePath {
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  return [bundle.resourcePath stringByAppendingPathComponent:@"testdata/hw_universal"];
}

- (void)testParsesThinBinary {
  auto data = Slurp("/usr/bin/yes");
  XCTAssertGreaterThanOrEqual(data.size(), 4u);
  santa::SliceInfo slice{};
  std::string err;
  auto s = FeedChunked(data, kHostArch, 1u << 20, &slice, &err);
  XCTAssertEqual(s, HeaderParser::Status::kReady, @"FeedChunked: %s", err.c_str());
  XCTAssertGreaterThan(slice.cs_blob_size, 0u);
  XCTAssertGreaterThanOrEqual(slice.cs_blob_offset, slice.slice_offset);
}

- (void)testParsesFatBinary {
  auto data = Slurp([self hwUniversalFixturePath].UTF8String);
  santa::SliceInfo slice{};
  std::string err;
  auto s = FeedChunked(data, kHwUniversalArch, 1u << 20, &slice, &err);
  XCTAssertEqual(s, HeaderParser::Status::kReady, @"FeedChunked: %s", err.c_str());
  XCTAssertGreaterThan(slice.slice_offset, 0u);  // fat: slice not at offset 0
  XCTAssertGreaterThan(slice.cs_blob_size, 0u);
}

- (void)testChunkSizeInvariance {
  auto data = Slurp([self hwUniversalFixturePath].UTF8String);
  santa::SliceInfo big{}, small{}, byteByByte{};
  std::string err;
  XCTAssertEqual(FeedChunked(data, kHwUniversalArch, 1u << 20, &big, &err),
                 HeaderParser::Status::kReady);
  XCTAssertEqual(FeedChunked(data, kHwUniversalArch, 17, &small, &err),
                 HeaderParser::Status::kReady);
  XCTAssertEqual(FeedChunked(data, kHwUniversalArch, 1, &byteByByte, &err),
                 HeaderParser::Status::kReady);
  XCTAssertEqual(big.cs_blob_offset, small.cs_blob_offset);
  XCTAssertEqual(big.cs_blob_offset, byteByByte.cs_blob_offset);
  XCTAssertEqual(big.cs_blob_size, small.cs_blob_size);
  XCTAssertEqual(big.cs_blob_size, byteByByte.cs_blob_size);
  XCTAssertEqual(big.slice_offset, small.slice_offset);
  XCTAssertEqual(big.slice_offset, byteByByte.slice_offset);
}

- (void)testRejectsNonMachO {
  auto data = Slurp("/etc/hosts");
  std::string err;
  auto s = FeedChunked(data, kHostArch, 1u << 20, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(err.find("not a Mach-O") != std::string::npos);
}

- (void)testRejectsArchMismatch {
  auto data = Slurp("/usr/bin/yes");
  XCTAssertGreaterThanOrEqual(data.size(), 4u);
  // Use an arch that should never match.
  ArchSelector bogus{static_cast<cpu_type_t>(0xDEADBEEFu), 0};
  std::string err;
  auto s = FeedChunked(data, bogus, 1u << 20, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
}

- (void)testRejectsTruncatedInput {
  auto data = Slurp("/usr/bin/yes");
  data.resize(64);  // truncate to before load commands could fit
  std::string err;
  auto s = FeedChunked(data, kHostArch, 1u << 20, nullptr, &err);
  XCTAssertNotEqual(s, HeaderParser::Status::kReady);
}

- (void)testParsesSynthetic32BitThinBinary {
  // Construct a synthetic 32-bit thin Mach-O slice with one
  // LC_CODE_SIGNATURE load command. Verifies the parser correctly
  // handles 32-bit headers (which are 4 bytes shorter than 64-bit).

  constexpr cpu_type_t kCpuType = CPU_TYPE_X86;  // 32-bit x86
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_ALL;

  struct mach_header mh{};
  mh.magic = MH_MAGIC;
  mh.cputype = kCpuType;
  mh.cpusubtype = kCpuSubtype;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 1;
  mh.sizeofcmds = sizeof(struct linkedit_data_command);
  mh.flags = 0;

  struct linkedit_data_command lc{};
  lc.cmd = LC_CODE_SIGNATURE;
  lc.cmdsize = sizeof(lc);
  lc.dataoff = sizeof(mh) + sizeof(lc) + 16;  // some room past load commands
  lc.datasize = 64;

  std::vector<uint8_t> data(lc.dataoff + lc.datasize, 0);
  std::memcpy(data.data(), &mh, sizeof(mh));
  std::memcpy(data.data() + sizeof(mh), &lc, sizeof(lc));

  santa::SliceInfo slice{};
  std::string err;
  ArchSelector want{kCpuType, kCpuSubtype};
  auto s = FeedChunked(data, want, /*chunk=*/17, &slice, &err);
  XCTAssertEqual(s, HeaderParser::Status::kReady, @"32-bit synthetic: %s", err.c_str());
  XCTAssertEqual(slice.cs_blob_offset, lc.dataoff);
  XCTAssertEqual(slice.cs_blob_size, lc.datasize);
}

// C3 regression: dataoff + datasize beyond the slice must be rejected.
- (void)testRejectsCsBlobBeyondSlice {
  constexpr uint64_t kTotal = 0x4000;  // 16 KiB slice
  // dataoff = 0x3000, datasize = 0x2000 → ends at 0x5000 > 0x4000.
  auto data = MakeThin64WithCsBlob(0x3000, 0x2000, kTotal);
  ArchSelector want{CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
  std::string err;
  auto s = FeedChunked(data, want, /*chunk=*/4096, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(err.find("outside slice") != std::string::npos);
}

// C3 regression: dataoff > slice_size must be rejected (subtraction-safe
// bound check).
- (void)testRejectsDataoffPastSlice {
  constexpr uint64_t kTotal = 0x4000;
  auto data = MakeThin64WithCsBlob(/*dataoff=*/0x5000,
                                   /*datasize=*/0, kTotal);
  ArchSelector want{CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL};
  std::string err;
  auto s = FeedChunked(data, want, /*chunk=*/4096, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(err.find("outside slice") != std::string::npos);
}

// C3 regression: implausibly large datasize (within slice bounds) must be
// rejected by the size cap before it can drive a giant cs_blob_buf_ alloc.
// We need a slice large enough that the size check trips, not the slice
// bounds — pick datasize > kMaxCsBlobSize (64 MiB) and slice_size larger.
//
// The parser rejects on the LC_CODE_SIGNATURE entry before reading the
// declared CS region, so we feed only the header + LC prefix and tell
// the parser the logical file size separately via kTotal. Avoids
// allocating a 256 MiB zero-filled buffer per test run.
- (void)testRejectsImplausibleCsBlobSize {
  constexpr uint64_t kTotal = 256ull * 1024 * 1024;  // logical file size
  constexpr size_t kPrefix = sizeof(struct mach_header_64) + sizeof(struct linkedit_data_command);
  // dataoff = 0x1000, datasize = 128 MiB → exceeds the 64 MiB cap.
  auto data = MakeThin64WithCsBlob(/*cs_dataoff=*/0x1000,
                                   /*cs_datasize=*/128u * 1024 * 1024,
                                   /*total_size=*/kPrefix);
  HeaderParser p({CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL}, kTotal);
  auto s = p.Update(data.data(), data.size(), /*chunk_off=*/0);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(std::string(p.LastError()).find("implausibly large") != std::string::npos);
}

// H1 regression: SliceOffsetIfKnown must report nullopt until the parser has
// resolved the slice (post-magic for thin, post-fat-arch-table for fat) and
// then return the same offset that ends up on Slice() at kReady.
- (void)testSliceOffsetIfKnown {
  auto data = Slurp([self hwUniversalFixturePath].UTF8String);  // fat binary
  HeaderParser p(kHwUniversalArch, data.size());
  // Before any bytes: definitely unknown.
  XCTAssertFalse(p.SliceOffsetIfKnown().has_value());

  // Feed bytes one chunk at a time; once SliceOffsetIfKnown becomes
  // populated it must stay populated and match the final slice's offset.
  constexpr size_t kChunk = 17;
  bool seen_known = false;
  uint64_t observed = 0;
  for (size_t off = 0; off < data.size(); off += kChunk) {
    size_t n = std::min(kChunk, data.size() - off);
    auto s = p.Update(data.data() + off, n, off);
    if (auto so = p.SliceOffsetIfKnown()) {
      if (!seen_known) {
        seen_known = true;
        observed = *so;
      } else {
        XCTAssertEqual(*so, observed);  // sticky, never changes
      }
    } else {
      // Once we've seen a value, it shouldn't disappear.
      XCTAssertFalse(seen_known);
    }
    if (s != HeaderParser::Status::kNeedMore) break;
  }
  XCTAssertEqual(p.status(), HeaderParser::Status::kReady);
  XCTAssertTrue(seen_known);
  XCTAssertEqual(observed, p.Slice().slice_offset);
}

// F1 regression: a slice declaring an implausibly large sizeofcmds (within
// slice bounds but exceeding the parser's sanity cap) must be rejected
// before HeaderParser allocates a multi-MiB scratch buffer. Pick
// sizeofcmds > kMaxSizeOfCmds (1 MiB) and slice_size larger so the slice-
// bound check passes and we exercise the size cap specifically.
- (void)testRejectsImplausibleSizeOfCmds {
  constexpr cpu_type_t kCpuType = CPU_TYPE_X86_64;
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_64_ALL;
  constexpr uint64_t kTotal = 4u * 1024 * 1024;    // 4 MiB
  constexpr uint32_t kBadSize = 2u * 1024 * 1024;  // 2 MiB > 1 MiB cap

  struct mach_header_64 mh{};
  mh.magic = MH_MAGIC_64;
  mh.cputype = kCpuType;
  mh.cpusubtype = kCpuSubtype;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 1;
  mh.sizeofcmds = kBadSize;

  std::vector<uint8_t> data(kTotal, 0);
  std::memcpy(data.data(), &mh, sizeof(mh));

  ArchSelector want{kCpuType, kCpuSubtype};
  std::string err;
  auto s = FeedChunked(data, want, /*chunk=*/65536, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(err.find("implausibly large") != std::string::npos);
}

// F2 defensive: a load command with cmdsize near UINT32_MAX must be rejected
// without computing `p + cmdsize` as a pointer (which would land far past
// one-past-the-end of scratch_, undefined behavior). The subtraction-safe
// `cmdsize > end - p` formulation is well-defined for any cmdsize value.
// Both the pre-fix (UB) and post-fix code reject this input — under UBSan
// the pre-fix code would diagnose a pointer overflow here.
- (void)testRejectsHugeCmdsize {
  constexpr cpu_type_t kCpuType = CPU_TYPE_X86_64;
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_64_ALL;
  struct mach_header_64 mh{};
  mh.magic = MH_MAGIC_64;
  mh.cputype = kCpuType;
  mh.cpusubtype = kCpuSubtype;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 1;
  mh.sizeofcmds = sizeof(struct load_command);  // scratch_ holds 8 bytes

  struct load_command lc{};
  lc.cmd = LC_CODE_SIGNATURE;
  lc.cmdsize = 0xFFFFFFFFu;  // ~4 GiB — way past scratch_'s 8 bytes

  constexpr size_t kTotal = 0x4000;
  std::vector<uint8_t> data(kTotal, 0);
  std::memcpy(data.data(), &mh, sizeof(mh));
  std::memcpy(data.data() + sizeof(mh), &lc, sizeof(lc));

  ArchSelector want{kCpuType, kCpuSubtype};
  std::string err;
  auto s = FeedChunked(data, want, /*chunk=*/4096, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(err.find("malformed load command size") != std::string::npos);
}

// M3 (post-re-audit): xnu silently uses the first LC_CODE_SIGNATURE via its
// per-vnode CS blob cache (load_code_signature in mach_loader.c:3765 hits the
// cache after the first add and never re-reads the dataoff/datasize of
// duplicates). We match that behavior — subsequent LC_CODE_SIGNATURE entries
// are silently skipped rather than rejected. Exercising with lc2's dataoff
// deliberately different from lc1's confirms "first wins": the resulting
// SliceInfo must reflect lc1's blob region, not lc2's.
- (void)testUsesFirstLcCodeSignature {
  constexpr cpu_type_t kCpuType = CPU_TYPE_X86_64;
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_64_ALL;
  struct mach_header_64 mh{};
  mh.magic = MH_MAGIC_64;
  mh.cputype = kCpuType;
  mh.cpusubtype = kCpuSubtype;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 2;
  mh.sizeofcmds = 2 * sizeof(struct linkedit_data_command);

  struct linkedit_data_command lc1{}, lc2{};
  lc1.cmd = LC_CODE_SIGNATURE;
  lc1.cmdsize = sizeof(lc1);
  lc1.dataoff = 0x1000;
  lc1.datasize = 0x200;
  lc2 = lc1;
  lc2.dataoff = 0x2000;  // different from lc1, must be ignored
  lc2.datasize = 0x100;

  constexpr size_t kTotal = 0x4000;
  std::vector<uint8_t> data(kTotal, 0);
  std::memcpy(data.data(), &mh, sizeof(mh));
  std::memcpy(data.data() + sizeof(mh), &lc1, sizeof(lc1));
  std::memcpy(data.data() + sizeof(mh) + sizeof(lc1), &lc2, sizeof(lc2));

  santa::SliceInfo slice{};
  std::string err;
  ArchSelector want{kCpuType, kCpuSubtype};
  auto s = FeedChunked(data, want, /*chunk=*/4096, &slice, &err);
  XCTAssertEqual(s, HeaderParser::Status::kReady);
  XCTAssertEqual(slice.cs_blob_offset, lc1.dataoff);
  XCTAssertEqual(slice.cs_blob_size, lc1.datasize);
}

// LC_CODE_SIGNATURE cmdsize parity: xnu's load_code_signature rejects
// any cmdsize != sizeof(linkedit_data_command) (i.e., != 16). Match that.
// Construct a thin Mach-O with one LC_CODE_SIGNATURE whose cmdsize is 24
// (bigger than 16, but the LC region is still well-formed by general
// load-command rules). Pre-fix code accepted this; post-fix rejects.
- (void)testRejectsWrongLcCodeSignatureCmdsize {
  constexpr cpu_type_t kCpuType = CPU_TYPE_X86_64;
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_64_ALL;
  constexpr uint32_t kBadCmdsize = 24;  // != sizeof(linkedit_data_command)=16

  struct mach_header_64 mh{};
  mh.magic = MH_MAGIC_64;
  mh.cputype = kCpuType;
  mh.cpusubtype = kCpuSubtype;
  mh.filetype = MH_EXECUTE;
  mh.ncmds = 1;
  mh.sizeofcmds = kBadCmdsize;

  // Lay out 24 bytes: 16 bytes of linkedit_data_command + 8 bytes of
  // padding. Matches sizeofcmds so the general LC bound check passes
  // and we exercise specifically the LC_CODE_SIGNATURE-strict check.
  std::vector<uint8_t> lc_buf(kBadCmdsize, 0);
  struct linkedit_data_command lc{};
  lc.cmd = LC_CODE_SIGNATURE;
  lc.cmdsize = kBadCmdsize;
  lc.dataoff = sizeof(mh) + kBadCmdsize + 16;  // some valid spot
  lc.datasize = 64;
  std::memcpy(lc_buf.data(), &lc, sizeof(lc));

  constexpr size_t kTotal = 0x4000;
  std::vector<uint8_t> data(kTotal, 0);
  std::memcpy(data.data(), &mh, sizeof(mh));
  std::memcpy(data.data() + sizeof(mh), lc_buf.data(), lc_buf.size());

  ArchSelector want{kCpuType, kCpuSubtype};
  std::string err;
  auto s = FeedChunked(data, want, /*chunk=*/4096, nullptr, &err);
  XCTAssertEqual(s, HeaderParser::Status::kError);
  XCTAssertTrue(err.find("wrong cmdsize") != std::string::npos);
}

// L1 regression: synthetic fat64 binary (FAT_MAGIC_64) wrapping a 64-bit
// thin Mach-O slice. xnu's exec path doesn't handle fat64 (mach_loader.c
// only dispatches MH_MAGIC{,_64} and FAT_MAGIC), but dyld supports it for
// dylibs/bundles. Fat64 is essentially unused on shipped macOS — no system
// binary in /usr/bin /usr/sbin /bin /sbin /usr/lib uses it — so this test
// exists to protect against bit-rot in the fat64 parsing path. A refactor
// that mis-dispatched fat64 as fat32 would read offset/size at the wrong
// byte positions in fat_arch_64 and fail the assertions below.
- (void)testParsesSyntheticFat64Binary {
  constexpr cpu_type_t kCpuType = CPU_TYPE_X86_64;
  constexpr cpu_subtype_t kCpuSubtype = CPU_SUBTYPE_X86_64_ALL;
  constexpr uint64_t kSliceOff = 0x1000;
  constexpr uint64_t kSliceSize = 0x3000;
  constexpr uint32_t kCsDataoff = 0x800;
  constexpr uint32_t kCsDatasize = 0x100;

  // Inner thin Mach-O slice with one LC_CODE_SIGNATURE.
  auto slice = MakeThin64WithCsBlob(kCsDataoff, kCsDatasize, kSliceSize);

  // Fat header + single fat_arch_64 entry, all big-endian on disk.
  struct fat_header fh{};
  fh.magic = OSSwapHostToBigInt32(FAT_MAGIC_64);
  fh.nfat_arch = OSSwapHostToBigInt32(1);
  struct fat_arch_64 fa{};
  fa.cputype = OSSwapHostToBigInt32(kCpuType);
  fa.cpusubtype = OSSwapHostToBigInt32(kCpuSubtype);
  fa.offset = OSSwapHostToBigInt64(kSliceOff);
  fa.size = OSSwapHostToBigInt64(kSliceSize);
  fa.align = OSSwapHostToBigInt32(12);  // 4 KiB
  fa.reserved = 0;

  std::vector<uint8_t> data(kSliceOff + kSliceSize, 0);
  std::memcpy(data.data(), &fh, sizeof(fh));
  std::memcpy(data.data() + sizeof(fh), &fa, sizeof(fa));
  std::memcpy(data.data() + kSliceOff, slice.data(), slice.size());

  santa::SliceInfo info{};
  std::string err;
  ArchSelector want{kCpuType, kCpuSubtype};
  auto s = FeedChunked(data, want, /*chunk=*/4096, &info, &err);
  XCTAssertEqual(s, HeaderParser::Status::kReady, @"fat64 synthetic: %s", err.c_str());
  XCTAssertEqual(info.slice_offset, kSliceOff);
  XCTAssertEqual(info.slice_size, kSliceSize);
  XCTAssertEqual(info.cs_blob_offset, kSliceOff + kCsDataoff);
  XCTAssertEqual(info.cs_blob_size, kCsDatasize);
  XCTAssertEqual(info.arch_name, "x86_64");
}

// LE-on-disk fat headers — magic bytes serialized in little-endian
// order such that an LE host reads them back as FAT_MAGIC /
// FAT_MAGIC_64 — must be rejected at the magic dispatch. Apple's
// tools and dyld produce only BE-on-disk fat (FAT_CIGAM /
// FAT_CIGAM_64 in host order on LE macOS), and xnu rejects anything
// else via OSSwapBigToHostInt32(magic) == FAT_MAGIC. ProcessFatHeader
// and ProcessFatArchTable both assume BE-on-disk and unconditionally
// OSSwap-from-BE, so accepting an LE form here would silently corrupt
// every field downstream.
- (void)testRejectsLittleEndianFatMagic {
  for (uint32_t magic : {FAT_MAGIC, FAT_MAGIC_64}) {
    std::vector<uint8_t> data(1024, 0);
    std::memcpy(data.data(), &magic, sizeof(magic));
    std::string err;
    auto s = FeedChunked(data, kHostArch, /*chunk=*/4096, nullptr, &err);
    XCTAssertEqual(s, HeaderParser::Status::kError);
    XCTAssertTrue(err.find("not a Mach-O") != std::string::npos,
                  @"LE-on-disk fat magic=0x%08x expected 'not a Mach-O', got: %s", magic,
                  err.c_str());
  }
}

@end
