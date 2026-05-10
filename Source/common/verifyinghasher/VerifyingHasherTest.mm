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

// DO NOT regenerate `hw_universal` without also updating `kHwUniversalSigningID`
// in this file. The signing_id is derived from the binary hash and changes when
// the fixture is rebuilt.

#include "Source/common/verifyinghasher/VerifyingHasher.h"

#include <CommonCrypto/CommonDigest.h>

__BEGIN_DECLS
#include <Kernel/kern/cs_blobs.h>
__END_DECLS

#import <XCTest/XCTest.h>

#include <fcntl.h>
#include <libkern/OSByteOrder.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

using santa::VerifyingHasher;

namespace {

// hw_universal facts (verified via `codesign -dv`):
//   Identifier: hw_universal-555549443efe62e1f0ec3533a308190c01724b5f
//   TeamIdentifier: not set (adhoc-signed)
//   Format: Mach-O universal (x86_64 arm64) — plain arm64, NOT arm64e
//   CPU type for arm64 slice: CPU_TYPE_ARM64 + CPU_SUBTYPE_ARM64_ALL
const char* kHwUniversalSigningID = "hw_universal-555549443efe62e1f0ec3533a308190c01724b5f";
const char* kHwUniversalTeamID = "";  // adhoc: no team id

// hw_team_signed facts (verified via `codesign -dv`):
//   Identifier: hw_team_signed (default; matches binary basename)
//   TeamIdentifier: ZMCG7MLDV9
//   Format: Mach-O universal (x86_64 arm64)
// Re-sign procedure documented in the BUILD's hw_team_signed_fixture comment.
// Update both constants below if the fixture is regenerated with a
// different signing identity.
const char* kHwTeamSignedSigningID = "hw_team_signed";
const char* kHwTeamSignedTeamID = "ZMCG7MLDV9";

// ---- Reference helpers (mirrored from VerifyingHasherCoreTest) --

// Walks a CS SuperBlob, finds the picked CodeDirectory (highest hashRank),
// and returns its 20-byte cdhash. Independent of CodeSignatureParser.
// Returns empty vector on any structural problem.
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

// Locates the CS blob bytes inside `bytes` for the requested cpu_type slice.
// Returns empty on any structural problem.
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

// Slurp a file into a vector. Returns empty on error.
std::vector<uint8_t> Slurp(const char* path) {
  int fd = ::open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return {};
  struct stat st{};
  if (::fstat(fd, &st) != 0) {
    ::close(fd);
    return {};
  }
  std::vector<uint8_t> v(static_cast<size_t>(st.st_size));
  ssize_t n = ::pread(fd, v.data(), v.size(), 0);
  ::close(fd);
  if (n != static_cast<ssize_t>(v.size())) return {};
  return v;
}

}  // namespace

@interface VerifyingHasherTest : XCTestCase
@end

@implementation VerifyingHasherTest

- (NSString*)fixturePath {
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  return [bundle.resourcePath stringByAppendingPathComponent:@"testdata/hw_universal"];
}

// Helper: open hw_universal, return the fd.
// Caller takes ownership of the fd (must close it).
- (int)openHwUniversalFd {
  NSString* path = [self fixturePath];
  int fd = ::open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0, @"Failed to open hw_universal at %@", path);
  return fd;
}

- (std::vector<uint8_t>)hwUniversalArm64CdHash {
  NSString* path = [self fixturePath];
  auto bytes = Slurp(path.UTF8String);
  XCTAssertFalse(bytes.empty(), @"Failed to slurp hw_universal at %@", path);
  auto cs_blob = ExtractCsBlobBytes(bytes, CPU_TYPE_ARM64);
  XCTAssertFalse(cs_blob.empty(), @"Failed to extract CS blob for arm64");
  auto cdhash = ReferenceCdHash(cs_blob);
  XCTAssertEqual(cdhash.size(), static_cast<size_t>(CS_CDHASH_LEN),
                 @"ReferenceCdHash returned unexpected size");
  return cdhash;
}

- (NSString*)teamSignedFixturePath {
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  return [bundle.resourcePath stringByAppendingPathComponent:@"testdata/hw_team_signed"];
}

- (int)openHwTeamSignedFd {
  NSString* path = [self teamSignedFixturePath];
  int fd = ::open(path.UTF8String, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0, @"Failed to open hw_team_signed at %@", path);
  return fd;
}

// ---- Test 1: exact cdhash match -> kMatchCDHash -------------------------

- (void)testMatchCDHashOnExactExpected {
  auto cdhash = [self hwUniversalArm64CdHash];
  int fd = [self openHwUniversalFd];

  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(cdhash.data(), cdhash.size()),
      .signing_id = kHwUniversalSigningID,
      .team_id = kHwUniversalTeamID,
  };

  auto r = VerifyingHasher::Run(fd, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);
  ::close(fd);

  XCTAssertEqual(r.status, VerifyingHasher::Status::kMatchCDHash, @"Expected kMatchCDHash");

  // sha256 must be engaged (populated on successful read).
  XCTAssertTrue(r.sha256.has_value(), @"sha256 must be engaged on kMatchCDHash");
}

// ---- Test 2: ad-hoc binary falls through to kNoMatch on cdhash mismatch

// Drift detection requires a non-empty team_id in Expected. Ad-hoc
// binaries (empty team_id) are not eligible for the (signing_id,
// team_id) drift fallback and fall through to kNoMatch on cdhash
// mismatch. The positive drift case is exercised on the team-signed
// fixture in testMatchSidTidDriftOnTeamSignedBinary.

- (void)testAdHocBinaryFallsThroughToNoMatch {
  // Wrong cdhash (all 0xFF), correct signing_id, correct (empty) team_id.
  // hw_universal is ad-hoc-signed, so kHwUniversalTeamID is "".
  // Expected: kNoMatch (drift guard rejects empty team_id).
  std::vector<uint8_t> wrong_cdhash(CS_CDHASH_LEN, 0xFF);
  int fd = [self openHwUniversalFd];

  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(wrong_cdhash.data(), wrong_cdhash.size()),
      .signing_id = kHwUniversalSigningID,
      .team_id = kHwUniversalTeamID,  // empty (ad-hoc)
  };

  auto r = VerifyingHasher::Run(fd, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);
  ::close(fd);

  XCTAssertEqual(r.status, VerifyingHasher::Status::kNoMatch,
                 @"Drift must not fire for ad-hoc binaries (empty team_id)");
}

// ---- Test 2b: team-signed + wrong cdhash + matching sid+tid -> kMatchSidTidDrift

- (void)testMatchSidTidDriftOnTeamSignedBinary {
  // Wrong cdhash (all 0xFF), correct signing_id, correct (non-empty) team_id.
  // Both Expected fields populated and matching the parsed CD → drift fires.
  std::vector<uint8_t> wrong_cdhash(CS_CDHASH_LEN, 0xFF);
  int fd = [self openHwTeamSignedFd];

  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(wrong_cdhash.data(), wrong_cdhash.size()),
      .signing_id = kHwTeamSignedSigningID,
      .team_id = kHwTeamSignedTeamID,
  };

  auto r = VerifyingHasher::Run(fd, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);
  ::close(fd);

  XCTAssertEqual(r.status, VerifyingHasher::Status::kMatchSidTidDrift,
                 @"Drift must fire on team-signed binary with matching sid+tid");
}

// ---- Test 3: all expected wrong -> kNoMatch ----------------------------

- (void)testNoMatchWhenAllExpectedDiffer {
  std::vector<uint8_t> wrong_cdhash(CS_CDHASH_LEN, 0xAA);
  int fd = [self openHwUniversalFd];

  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(wrong_cdhash.data(), wrong_cdhash.size()),
      .signing_id = "com.wrong.signing.id",
      .team_id = "WRONGTEAM",
  };

  auto r = VerifyingHasher::Run(fd, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);
  ::close(fd);

  XCTAssertEqual(r.status, VerifyingHasher::Status::kNoMatch,
                 @"Expected kNoMatch when all expected values differ");
}

// ---- Test 4: invalid fd -> kError ---------------------------------------

- (void)testErrorOnInvalidFd {
  std::vector<uint8_t> dummy_cdhash(CS_CDHASH_LEN, 0x00);

  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(dummy_cdhash.data(), dummy_cdhash.size()),
      .signing_id = "com.some.app",
      .team_id = "SOMETEAM",
  };

  auto r = VerifyingHasher::Run(-1, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);

  XCTAssertEqual(r.status, VerifyingHasher::Status::kError, @"Expected kError for invalid fd=-1");
  // I/O failure path: digest could not be finalized, so sha256 must be nullopt.
  // Distinguishes this from non-IoError kError paths (e.g., non-Mach-O) where
  // the file was read to EOF and sha256 is engaged.
  XCTAssertFalse(r.sha256.has_value(), @"sha256 must be nullopt on fstat-failure kError");
}

// ---- Test 5: non-Mach-O file -> kError ----------------------------------

- (void)testErrorOnNonMachOFile {
  // Write a tiny non-Mach-O file to NSTemporaryDirectory() (NOT bare /tmp).
  NSString* tmpDir = NSTemporaryDirectory();
  NSString* tmpPath = [tmpDir stringByAppendingPathComponent:@"VerifyingHasherTest_nonmacho.bin"];

  // 16 bytes of garbage (no Mach-O magic).
  const uint8_t garbage[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
  NSData* data = [NSData dataWithBytes:garbage length:sizeof(garbage)];
  BOOL wrote = [data writeToFile:tmpPath atomically:YES];
  XCTAssertTrue(wrote, @"Failed to write non-Mach-O fixture to %@", tmpPath);

  int fd = ::open(tmpPath.UTF8String, O_RDONLY | O_CLOEXEC);
  XCTAssertGreaterThanOrEqual(fd, 0, @"Failed to open non-Mach-O fixture");

  std::vector<uint8_t> dummy_cdhash(CS_CDHASH_LEN, 0x00);
  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(dummy_cdhash.data(), dummy_cdhash.size()),
      .signing_id = "com.some.app",
      .team_id = "SOMETEAM",
  };

  auto r = VerifyingHasher::Run(fd, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);
  ::close(fd);
  ::unlink(tmpPath.UTF8String);

  XCTAssertEqual(r.status, VerifyingHasher::Status::kError, @"Expected kError for non-Mach-O file");
  // Non-Mach-O is a kError path that DID reach EOF — the file was read in
  // full, just rejected as not-a-Mach-O. sha256 must be engaged.
  XCTAssertTrue(r.sha256.has_value(), @"sha256 must be engaged on non-Mach-O kError (read EOF)");
}

// ---- Test 6: sha256 populated on successful read (kNoMatch path) --------
//
// Uses a deliberately wrong cdhash and wrong signing_id/team_id so we get
// kNoMatch — but sha256 must still be populated and non-zero because the
// file was read to EOF successfully.

- (void)testSha256PopulatedOnSuccessfulRead {
  // Use all-zero cdhash (wrong) + wrong signing_id + wrong team_id to force
  // kNoMatch while guaranteeing a successful full-file read.
  std::vector<uint8_t> zero_cdhash(CS_CDHASH_LEN, 0x00);
  int fd = [self openHwUniversalFd];

  VerifyingHasher::Expected exp{
      .cdhash = std::span<const uint8_t>(zero_cdhash.data(), zero_cdhash.size()),
      .signing_id = "com.wrong.id",
      .team_id = "WRONGTEAM",
  };

  auto r = VerifyingHasher::Run(fd, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp);
  ::close(fd);

  // kNoMatch means the file was read successfully; sha256 must be engaged.
  XCTAssertEqual(r.status, VerifyingHasher::Status::kNoMatch,
                 @"Expected kNoMatch (wrong expected values)");
  XCTAssertTrue(r.sha256.has_value(), @"sha256 must be engaged on kNoMatch (file read to EOF)");

  // Cross-check: the same sha256 as the kMatchCDHash path in test 1 — both
  // reads the same file. Run a second call with exact cdhash and assert the
  // sha256 bytes are identical.
  auto cdhash = [self hwUniversalArm64CdHash];
  int fd2 = [self openHwUniversalFd];
  VerifyingHasher::Expected exp2{
      .cdhash = std::span<const uint8_t>(cdhash.data(), cdhash.size()),
      .signing_id = kHwUniversalSigningID,
      .team_id = kHwUniversalTeamID,
  };
  auto r2 = VerifyingHasher::Run(fd2, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL, exp2);
  ::close(fd2);

  XCTAssertTrue(r2.sha256.has_value());
  XCTAssertEqual(*r.sha256, *r2.sha256,
                 @"sha256 must be deterministic across two reads of the same file");
}

@end
