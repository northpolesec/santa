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

#include "Source/common/verifyinghasher/CodeSignatureParser.h"

#include <CommonCrypto/CommonDigest.h>
#include <sys/cdefs.h>

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

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "Source/common/ScopedFile.h"

using santa::ParseCodeSignature;
using santa::ParsedCodeDirectory;

namespace {

// Helper: extract the CS blob bytes from a real Mach-O. Mirrors the
// parsing logic in HeaderParser but is intentionally separate so this
// test doesn't depend on HeaderParser.
std::vector<uint8_t> ExtractCsBlob(const char* path, uint64_t* out_slice_size) {
  santa::ScopedFile sf(::open(path, O_RDONLY | O_CLOEXEC));
  if (sf.UnsafeFD() < 0) return {};
  const int fd = sf.UnsafeFD();
  struct stat st{};
  if (::fstat(fd, &st) != 0) return {};
  uint32_t magic = 0;
  if (::pread(fd, &magic, 4, 0) != 4) return {};

  uint64_t slice_off = 0, slice_size = static_cast<uint64_t>(st.st_size);
  if (magic == FAT_MAGIC || magic == FAT_CIGAM) {
    struct fat_header fh{};
    ::pread(fd, &fh, sizeof(fh), 0);
    uint32_t n = OSSwapBigToHostInt32(fh.nfat_arch);
    std::vector<struct fat_arch> archs(n);
    ::pread(fd, archs.data(), n * sizeof(struct fat_arch), sizeof(fh));
#if defined(__arm64__) || defined(__aarch64__)
    cpu_type_t want = CPU_TYPE_ARM64;
#else
    cpu_type_t want = CPU_TYPE_X86_64;
#endif
    bool matched = false;
    for (auto& a : archs) {
      cpu_type_t ct = static_cast<cpu_type_t>(OSSwapBigToHostInt32(a.cputype));
      if (ct == want) {
        slice_off = OSSwapBigToHostInt32(a.offset);
        slice_size = OSSwapBigToHostInt32(a.size);
        matched = true;
        break;
      }
    }
    // Fast-fail: without this, slice_off stays 0 and the load-command
    // walk below reads the fat header bytes as a mach_header_64 and
    // allocates std::vector<uint8_t> for an arbitrary mh.sizeofcmds.
    if (!matched) return {};
  }
  // Walk the slice's load commands to find LC_CODE_SIGNATURE.
  struct mach_header_64 mh{};
  ::pread(fd, &mh, sizeof(mh), slice_off);
  bool is64 = (mh.magic == MH_MAGIC_64);
  size_t hdr_sz = is64 ? sizeof(mh) : sizeof(struct mach_header);
  std::vector<uint8_t> lc(mh.sizeofcmds);
  ::pread(fd, lc.data(), mh.sizeofcmds, slice_off + hdr_sz);

  uint64_t sig_off = 0, sig_size = 0;
  const uint8_t* p = lc.data();
  for (uint32_t i = 0; i < mh.ncmds; ++i) {
    struct load_command lcmd;
    std::memcpy(&lcmd, p, sizeof(lcmd));
    if (lcmd.cmd == LC_CODE_SIGNATURE) {
      struct linkedit_data_command led;
      std::memcpy(&led, p, sizeof(led));
      sig_off = slice_off + led.dataoff;
      sig_size = led.datasize;
      break;
    }
    p += lcmd.cmdsize;
  }
  if (sig_size == 0) return {};
  std::vector<uint8_t> blob(sig_size);
  ::pread(fd, blob.data(), sig_size, sig_off);
  if (out_slice_size) *out_slice_size = slice_size;
  return blob;
}

}  // namespace

@interface CodeSignatureParserTest : XCTestCase
@end

@implementation CodeSignatureParserTest

- (void)testPicksStrongestCdHashType {
  // SuperBlob containing both a canonical SHA-1 CD and an alternate SHA-256 CD.
  // ParseCodeSignature must pick the SHA-256 one.
  //
  // Layout: SuperBlob | BlobIndex[0] | BlobIndex[1] | CD_SHA1 | CD_SHA256
  const size_t bidx_off = sizeof(CS_SuperBlob);
  const size_t cd1_off = bidx_off + 2 * sizeof(CS_BlobIndex);
  const size_t cd1_sz = sizeof(CS_CodeDirectory) + 20;  // 1 SHA-1 slot
  const size_t cd2_off = cd1_off + cd1_sz;
  const size_t cd2_sz = sizeof(CS_CodeDirectory) + 32;  // 1 SHA-256 slot
  const size_t total = cd2_off + cd2_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(2);

  auto* idxs = reinterpret_cast<CS_BlobIndex*>(blob.data() + bidx_off);
  idxs[0].type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idxs[0].offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd1_off));
  idxs[1].type = OSSwapHostToBigInt32(CSSLOT_ALTERNATE_CODEDIRECTORIES);
  idxs[1].offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd2_off));

  auto setupCd = [](CS_CodeDirectory* cd, size_t cdsz, uint8_t hashType, uint8_t hashSize) {
    cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
    cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cdsz));
    cd->version = 0;
    cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
    cd->codeLimit = OSSwapHostToBigInt32(4096);
    cd->nCodeSlots = OSSwapHostToBigInt32(1);
    cd->hashSize = hashSize;
    cd->hashType = hashType;
    cd->pageSize = 12;  // 4096
  };
  setupCd(reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd1_off), cd1_sz, CS_HASHTYPE_SHA1, 20);
  setupCd(reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd2_off), cd2_sz, CS_HASHTYPE_SHA256,
          32);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/4096, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.hash_type, CS_HASHTYPE_SHA256);
  XCTAssertEqual(parsed.page_count, 1u);

  // The SHA-256 alternate (cd2) was picked over the SHA-1 canonical (cd1).
  // The cdhash must match SHA-256(cd2_bytes) truncated, not SHA-1(cd1_bytes).
  uint8_t expected_full[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(blob.data() + cd2_off, static_cast<CC_LONG>(cd2_sz), expected_full);
  XCTAssertEqual(0, std::memcmp(parsed.cdhash, expected_full, CS_CDHASH_LEN));

  // And conclusively NOT the SHA-1 canonical's cdhash.
  uint8_t sha1_of_cd1[CC_SHA1_DIGEST_LENGTH];
  CC_SHA1(blob.data() + cd1_off, static_cast<CC_LONG>(cd1_sz), sha1_of_cd1);
  XCTAssertNotEqual(0, std::memcmp(parsed.cdhash, sha1_of_cd1, CS_CDHASH_LEN));
}

- (void)testCdHashSha256 {
  // Single-CD SuperBlob with SHA-256. We build it ourselves so the test
  // controls the byte sequence and can recompute the cdhash independently.
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  // Independently compute the expected cdhash: SHA-256 of the CD blob
  // (cd_off..cd_off+cd_sz), truncated to CS_CDHASH_LEN.
  uint8_t expected_full[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(blob.data() + cd_off, static_cast<CC_LONG>(cd_sz), expected_full);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(0, std::memcmp(parsed.cdhash, expected_full, CS_CDHASH_LEN));
}

- (void)testCdHashSha1 {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 20;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA1;
  cd->pageSize = 12;

  uint8_t expected_full[CC_SHA1_DIGEST_LENGTH];
  CC_SHA1(blob.data() + cd_off, static_cast<CC_LONG>(cd_sz), expected_full);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.hash_type, CS_HASHTYPE_SHA1);
  // SHA-1 is exactly CS_CDHASH_LEN long, so cdhash == full digest.
  XCTAssertEqual(0, std::memcmp(parsed.cdhash, expected_full, CS_CDHASH_LEN));
}

- (void)testCdHashSha256Truncated {
  // SHA-256-TRUNCATED computes full SHA-256 over the CD blob; cdhash
  // is the first CS_CDHASH_LEN bytes (same as full SHA-256 truncation).
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 20;  // TRUNCATED stride is 20 on disk.
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256_TRUNCATED;
  cd->pageSize = 12;

  uint8_t expected_full[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(blob.data() + cd_off, static_cast<CC_LONG>(cd_sz), expected_full);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.hash_type, CS_HASHTYPE_SHA256_TRUNCATED);
  XCTAssertEqual(0, std::memcmp(parsed.cdhash, expected_full, CS_CDHASH_LEN));
}

- (void)testCdHashSha384 {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 48;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA384;
  cd->pageSize = 12;

  uint8_t expected_full[CC_SHA384_DIGEST_LENGTH];
  CC_SHA384(blob.data() + cd_off, static_cast<CC_LONG>(cd_sz), expected_full);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.hash_type, CS_HASHTYPE_SHA384);
  XCTAssertEqual(0, std::memcmp(parsed.cdhash, expected_full, CS_CDHASH_LEN));
}

// Performance contract: parsed.slot_hashes is a non-owning view into
// the input blob bytes, not a heap copy. The slot table on a 5 GiB
// Apple Silicon binary is ~10 MiB; on Intel ~40 MiB. Without this
// invariant ParseCodeSignature would memcpy that on every Run().
// Asserts pointer equality between parsed.slot_hashes.data() and the
// expected sub-range of the input blob.
- (void)testSlotHashesIsViewIntoInputBlob {
  // Build a single-CD SuperBlob; compute the expected slot-table location.
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const uint32_t hash_off_in_cd = static_cast<uint32_t>(sizeof(CS_CodeDirectory));
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(hash_off_in_cd);
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertTrue(ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err),
                @"ParseCodeSignature: %s", err.c_str());

  // Slot table should sit at blob.data() + cd_off + hash_off_in_cd.
  const uint8_t* expected = blob.data() + cd_off + hash_off_in_cd;
  XCTAssertEqual(parsed.slot_hashes.data(), expected,
                 @"slot_hashes.data() must point into the input blob, not a copy");
  XCTAssertEqual(parsed.slot_hashes.size(), static_cast<size_t>(kHashSize));
}

// Contract guard: ParseCodeSignature must leave parsed.cdhash zeroed on
// any failure path. The default-initialized {} on the field is the
// in-class guarantee; this test fails loud if anyone moves the
// computation earlier without reverting on later failures.
- (void)testCdHashZeroedOnMalformed {
  std::vector<uint8_t> tiny(4, 0);  // too small to even be a SuperBlob
  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(tiny, /*slice_size=*/0, parsed, err));
  uint8_t zero[CS_CDHASH_LEN] = {};
  XCTAssertEqual(0, std::memcmp(parsed.cdhash, zero, CS_CDHASH_LEN));
}

- (void)testParsesRealCsBlob {
  uint64_t slice_size = 0;
  auto blob = ExtractCsBlob("/usr/bin/yes", &slice_size);
  XCTAssertFalse(blob.empty());
  ParsedCodeDirectory cd;
  std::string err;
  bool ok = ParseCodeSignature(blob, slice_size, cd, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(cd.page_size, 4096u);
  XCTAssertGreaterThan(cd.page_count, 0u);
  XCTAssertEqual(cd.slot_hashes.size(), static_cast<size_t>(cd.page_count) * cd.hash_size);
  XCTAssertTrue(cd.hash_type == CS_HASHTYPE_SHA256 || cd.hash_type == CS_HASHTYPE_SHA384);
}

- (void)testRejectsTooSmallBlob {
  std::vector<uint8_t> tiny(4, 0);
  ParsedCodeDirectory cd;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(tiny, 0, cd, err));
  XCTAssertTrue(err.find("too small") != std::string::npos);
}

- (void)testRejectsBadSuperblobMagic {
  std::vector<uint8_t> blob(sizeof(CS_SuperBlob), 0);
  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(0xdeadbeef);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(blob.size()));
  sb->count = 0;
  ParsedCodeDirectory cd;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, 0, cd, err));
  XCTAssertTrue(err.find("superblob magic") != std::string::npos);
}

- (void)testRejectsCodeLimitExceedingSlice {
  // Construct a minimal SuperBlob with one CD whose codeLimit is huge.
  // Layout: SuperBlob | BlobIndex | CodeDirectory | (32-byte slot)
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 32;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(0xFFFFFFFFu);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = 32;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;  // 4096

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/4096, parsed, err));
  XCTAssertTrue(err.find("codeLimit") != std::string::npos);
}

// Regression for C2: a malicious CD with codeLimit > UINT32_MAX * page_size
// would, before the fix, truncate expected_pages to uint32 and pass the
// nCodeSlots equality check. ParseCodeSignature must instead reject.
//
// Construct: pageSize=12 (4 KiB), codeLimit = 0x10000_00000_0000 (way past
// UINT32_MAX * 4 KiB), nCodeSlots = the truncated value. slice_size is set
// large enough that codeLimit <= slice_size still passes the earlier check,
// so we exercise specifically the page-count narrowing.
- (void)testRejectsPageCountOverflow {
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 32;  // one trailing slot byteslot
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  // version >= CS_SUPPORTSCODELIMIT64 (0x20300) so codeLimit64 is honored.
  cd->version = OSSwapHostToBigInt32(CS_SUPPORTSCODELIMIT64);
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  // codeLimit = 2^48 → expected_pages_u64 = 2^48 / 4096 = 2^36, overflows uint32.
  const uint64_t huge_code_limit = 1ull << 48;
  cd->codeLimit64 = OSSwapHostToBigInt64(huge_code_limit);
  // nCodeSlots = the value the parser would have computed if it had
  // (incorrectly) truncated to uint32: (2^48 / 4096) & 0xFFFFFFFF == 0.
  cd->nCodeSlots = OSSwapHostToBigInt32(0);
  cd->hashSize = 32;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;  // 4 KiB

  ParsedCodeDirectory parsed;
  std::string err;
  // slice_size large enough that codeLimit <= slice_size passes.
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/(1ull << 49), parsed, err));
  XCTAssertTrue(err.find("page count exceeds UINT32_MAX") != std::string::npos);
}

// C2 (post-re-audit): nCodeSlots > expected_pages must be ACCEPTED. xnu's
// cs_validate_codedirectory (bsd/kern/ubc_subr.c:391-394) only checks the
// slot table fits in the CD blob given nCodeSlots; it doesn't require
// nCodeSlots == ceil(codeLimit/pageSize). At runtime, extra slots beyond
// expected_pages are simply never queried. Rejecting "extra slots" would
// be a Santa-only false-positive on binaries xnu happily runs.
- (void)testAcceptsExcessNCodeSlots {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kPageSize = 4096;
  constexpr uint32_t kExpected = (kCodeLimit + kPageSize - 1) / kPageSize;  // 1
  constexpr uint32_t kClaimed = kExpected + 5;                              // overclaim slots
  constexpr uint32_t kHashSize = 32;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + kClaimed * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(kClaimed);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/4096, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  // We use expected_pages, not nCodeSlots — extra slots ignored.
  XCTAssertEqual(parsed.page_count, kExpected);
}

// C2 (post-re-audit): nCodeSlots < expected_pages must still be REJECTED.
// xnu accepts the blob structurally and treats pages beyond nCodeSlots as
// unsigned at runtime (hashes() returns NULL → cs_validate_page sets
// validated=FALSE → VM fault enforcement blocks). For Santa we reject early
// because the alternative is reading past the actual slot table into
// non-slot CD bytes, producing a confusing "kPagesMismatched" diagnostic
// rather than a clear "malformed CD" one. Same effective security outcome
// (binary doesn't run), better diagnostic.
- (void)testRejectsInsufficientNCodeSlots {
  constexpr uint32_t kCodeLimit = 8192;  // 2 pages at 4 KiB
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kClaimed = 1;  // underclaim — 1 slot for a 2-page region
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + kClaimed * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(kClaimed);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/8192, parsed, err));
  XCTAssertTrue(err.find("fewer slot hashes") != std::string::npos);
}

// M2 regression: nCodeSlots claiming a slot table that doesn't fit in the
// CD blob must be rejected, even if the slots we actually read (page_count)
// fit. xnu's cs_validate_codedirectory enforces this on the full claim;
// before the M2 fix the parser bounds-checked only page_count slots, so a
// CD that overstated nCodeSlots beyond what fit slipped through.
//
// Construct: kClaimed slots claimed but only kFits actually fit between
// hashOffset and end-of-blob; expected_pages (1) is small enough that the
// page_count bounds check still passes.
- (void)testRejectsNCodeSlotsOverflowingBlob {
  constexpr uint32_t kCodeLimit = 4096;  // expected_pages = 1
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kSlotsInCd = 8;   // physically present
  constexpr uint32_t kClaimed = 1000;  // overclaim — would need 32 KiB
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + kSlotsInCd * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(kClaimed);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err));
  XCTAssertTrue(err.find("nCodeSlots does not fit") != std::string::npos);
}

// L3 regression: a CD whose `length` field is shorter than the smallest
// header we can read (kMinCdBlobLen = 64 bytes, covering through codeLimit64)
// must be skipped during candidate collection. With only that one (canonical)
// CD in the SuperBlob, the parser reports "no CodeDirectory blobs found"
// because candidates is empty after the skip.
- (void)testRejectsTinyCdBlobLen {
  constexpr uint32_t kCdLen = 60;  // intentionally < kMinCdBlobLen (64)
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t total = cd_off + kCdLen;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(kCdLen);

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/0, parsed, err));
  XCTAssertTrue(err.find("no CodeDirectory blobs found") != std::string::npos);
}

// L3 regression: a CD whose `length` is in [kMinCdBlobLen,
// sizeof(CS_CodeDirectory)) used to be skipped (sizeof grows with each new
// SDK that adds a versioned field — execSeg*, preEncrypt*, linkage*…).
// After the fix, such a CD parses successfully because we only read fields
// up through codeLimit64 (offset 64), which is well within blob_len here.
// This test guards against re-introducing an SDK-fragile threshold.
- (void)testAcceptsCdShorterThanSdkSizeof {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kHashOff = 64;                  // slot table right after header
  constexpr uint32_t kCdLen = kHashOff + kHashSize;  // 96 bytes
  static_assert(kCdLen >= 64, "test must exercise the new minimum threshold");
  static_assert(kCdLen < sizeof(CS_CodeDirectory),
                "test must exercise the previously-rejected band");

  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t total = cd_off + kCdLen;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(kCdLen);
  cd->version = 0;  // pre-scatter, pre-codeLimit64 — no later fields read
  cd->hashOffset = OSSwapHostToBigInt32(kHashOff);
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;
  // Deliberately do NOT touch fields past offset 40 (spare2, scatterOffset,
  // codeLimit64, …) — those bytes are part of the slot table here.

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.page_count, 1u);
  XCTAssertEqual(parsed.hash_type, CS_HASHTYPE_SHA256);
}

// L5 regression: a CD with version >= CS_SUPPORTSSCATTER and a non-zero
// scatterOffset must be rejected explicitly. Apple's codesign emits scatter
// only for the dyld shared cache (DYLDCacheRep in libsecurity_codesigning),
// which Santa never gates as a regular exec, so rejection has no impact on
// legitimate binaries. The reject prevents the parser from silently producing
// kPagesMismatched on a malicious scatter-claiming CD (linear lookup vs xnu's
// scatter-aware hashes() would disagree), which is the right deny but a
// misleading diagnostic.
- (void)testRejectsScatterCd {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = OSSwapHostToBigInt32(CS_SUPPORTSSCATTER);
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;
  cd->scatterOffset = OSSwapHostToBigInt32(0xdeadbeefu);  // any non-zero

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err));
  XCTAssertTrue(err.find("scatter") != std::string::npos);
}

// L5 negative: version >= CS_SUPPORTSSCATTER with scatterOffset == 0 must be
// accepted. Real CDs from any version >= 0x20100 carry the scatterOffset
// field but leave it zero; rejecting those would block essentially every
// modern binary.
- (void)testAcceptsScatterFieldZero {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 1 * kHashSize;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = OSSwapHostToBigInt32(CS_SUPPORTSSCATTER);
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;
  cd->scatterOffset = 0;  // zero on the wire — sentinel for "no scatter"

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
}

- (void)checkRejectsBadPageSize:(uint8_t)bad_page_size {
  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t cd_sz = sizeof(CS_CodeDirectory) + 32;
  const size_t total = cd_off + cd_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_sz));
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
  cd->codeLimit = OSSwapHostToBigInt32(4096);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = 32;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = bad_page_size;

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/4096, parsed, err));
  XCTAssertTrue(err.find("pageSize unsupported") != std::string::npos);
}

// H2/H3 regression: pageSize must be in [12, 18]. Reject 0 (spec "non-paged"
// mode — separate signing path we don't support), 11 (sub-4-KiB pages), and
// 19 (>256 KiB pages — opens a tamper-detection-latency window). Build a
// minimal valid SuperBlob with a single CD whose only invalid field is
// pageSize, so the rejection has to come from the pageSize check.
- (void)testRejectsBadPageSizes {
  [self checkRejectsBadPageSize:0];   // non-paged spec mode
  [self checkRejectsBadPageSize:11];  // sub-4-KiB pages
  [self checkRejectsBadPageSize:19];  // above-256-KiB pages
  [self checkRejectsBadPageSize:31];  // max-uint pageSize
}

// F6 regression: a SuperBlob with two CodeDirectories sharing the same
// hashType must be rejected. xnu's cs_validate_csblob (bsd/kern/ubc_subr.c
// :593-597) calls this "illegal and suspicious" and returns EBADEXEC; we
// match. Two SHA-256 CDs (one canonical, one alternate) is the typical
// shape — covers both "duplicate canonical" and "canonical + alternate
// of same type" since either path through xnu's order-dependent walk
// rejects same-rank duplicates.
- (void)testRejectsDuplicateHashType {
  const size_t bidx_off = sizeof(CS_SuperBlob);
  const size_t cd1_off = bidx_off + 2 * sizeof(CS_BlobIndex);
  const size_t cd1_sz = sizeof(CS_CodeDirectory) + 32;
  const size_t cd2_off = cd1_off + cd1_sz;
  const size_t cd2_sz = sizeof(CS_CodeDirectory) + 32;
  const size_t total = cd2_off + cd2_sz;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(2);

  auto* idxs = reinterpret_cast<CS_BlobIndex*>(blob.data() + bidx_off);
  idxs[0].type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idxs[0].offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd1_off));
  idxs[1].type = OSSwapHostToBigInt32(CSSLOT_ALTERNATE_CODEDIRECTORIES);
  idxs[1].offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd2_off));

  auto setupCd = [](CS_CodeDirectory* cd, size_t cdsz) {
    cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
    cd->length = OSSwapHostToBigInt32(static_cast<uint32_t>(cdsz));
    cd->version = 0;
    cd->hashOffset = OSSwapHostToBigInt32(static_cast<uint32_t>(sizeof(CS_CodeDirectory)));
    cd->codeLimit = OSSwapHostToBigInt32(4096);
    cd->nCodeSlots = OSSwapHostToBigInt32(1);
    cd->hashSize = 32;
    cd->hashType = CS_HASHTYPE_SHA256;  // duplicate hashType
    cd->pageSize = 12;
  };
  setupCd(reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd1_off), cd1_sz);
  setupCd(reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd2_off), cd2_sz);

  ParsedCodeDirectory parsed;
  std::string err;
  XCTAssertFalse(ParseCodeSignature(blob, /*slice_size=*/4096, parsed, err));
  XCTAssertTrue(err.find("same hashType") != std::string::npos);
}

// Task 10, Step 2: identifier field — TDD red step.
// Builds a synthetic CD whose identOffset points at a known string placed
// immediately after the slot table. Expects parsed.identifier to hold it.
- (void)testParsedCDExposesIdentifier {
  // CD layout:
  //   [0, 112)  CS_CodeDirectory header (sizeof = 112)
  //   [112,144) one SHA-256 slot hash (hashOffset = 112)
  //   [144,161) identifier string "com.example.test\0"
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kHashOff = static_cast<uint32_t>(sizeof(CS_CodeDirectory));
  const std::string kIdent = "com.example.test";
  const uint32_t kIdentOff = kHashOff + kHashSize;  // 144
  const uint32_t kCdLen = kIdentOff + static_cast<uint32_t>(kIdent.size()) + 1;

  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t total = cd_off + kCdLen;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(kCdLen);
  cd->version = 0;
  cd->hashOffset = OSSwapHostToBigInt32(kHashOff);
  cd->identOffset = OSSwapHostToBigInt32(kIdentOff);
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  // Write the identifier string at identOffset.
  std::memcpy(blob.data() + cd_off + kIdentOff, kIdent.c_str(), kIdent.size() + 1);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.identifier, kIdent);
}

// Task 10, Step 4: team_id positive case.
// Builds a synthetic CD with version >= CS_SUPPORTSTEAMID, sets teamOffset
// to point at a known string after the slot table. Expects team_id to hold it.
- (void)testParsedCDExposesTeamID {
  // CD layout (version = CS_SUPPORTSTEAMID so teamOffset field is present):
  //   [0, 112)  CS_CodeDirectory header
  //   [112,144) one SHA-256 slot hash (hashOffset = 112)
  //   [144,160) identifier "com.example.app\0"
  //   [160,172) team id "TEAMID1234\0"
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kHashOff = static_cast<uint32_t>(sizeof(CS_CodeDirectory));  // 112
  const std::string kIdent = "com.example.app";
  const std::string kTeam = "TEAMID1234";
  const uint32_t kIdentOff = kHashOff + kHashSize;                                 // 144
  const uint32_t kTeamOff = kIdentOff + static_cast<uint32_t>(kIdent.size()) + 1;  // 160
  const uint32_t kCdLen = kTeamOff + static_cast<uint32_t>(kTeam.size()) + 1;

  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t total = cd_off + kCdLen;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(kCdLen);
  cd->version = OSSwapHostToBigInt32(CS_SUPPORTSTEAMID);
  cd->hashOffset = OSSwapHostToBigInt32(kHashOff);
  cd->identOffset = OSSwapHostToBigInt32(kIdentOff);
  cd->teamOffset = OSSwapHostToBigInt32(kTeamOff);
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  std::memcpy(blob.data() + cd_off + kIdentOff, kIdent.c_str(), kIdent.size() + 1);
  std::memcpy(blob.data() + cd_off + kTeamOff, kTeam.c_str(), kTeam.size() + 1);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertEqual(parsed.team_id, kTeam);
}

// Task 10, Step 4b: team_id empty for adhoc (teamOffset == 0).
// Even with a version >= CS_SUPPORTSTEAMID, if teamOffset is zero the
// parser must leave team_id empty.
- (void)testParsedCDTeamIDEmptyForAdhoc {
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kHashOff = static_cast<uint32_t>(sizeof(CS_CodeDirectory));
  const uint32_t kCdLen = kHashOff + kHashSize;

  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t total = cd_off + kCdLen;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(kCdLen);
  cd->version = OSSwapHostToBigInt32(CS_SUPPORTSTEAMID);
  cd->hashOffset = OSSwapHostToBigInt32(kHashOff);
  cd->identOffset = 0;  // no identifier
  cd->teamOffset = 0;   // adhoc: no team
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertTrue(parsed.team_id.empty(), @"team_id must be empty for adhoc (teamOffset == 0)");
}

// Task 10, Step 4c: team_id empty for old CD version (pre-CS_SUPPORTSTEAMID).
// Even if teamOffset field bytes are non-zero, the parser must not read them
// when the CD version predates CS_SUPPORTSTEAMID (0x20200).
- (void)testParsedCDTeamIDIgnoredForOldCdVersion {
  // Use a version >= CS_SUPPORTSSCATTER so scatterOffset is present and the
  // struct overlaps teamOffset, but version is still < CS_SUPPORTSTEAMID.
  // We deliberately write a non-zero value at the teamOffset field position
  // (offset 48) to confirm the parser ignores it.
  constexpr uint32_t kCodeLimit = 4096;
  constexpr uint32_t kHashSize = 32;
  constexpr uint32_t kHashOff = static_cast<uint32_t>(sizeof(CS_CodeDirectory));
  const std::string kTeamString = "SHOULDNOTAPPEAR";
  const uint32_t kTeamStringOff = kHashOff + kHashSize;
  const uint32_t kCdLen = kTeamStringOff + static_cast<uint32_t>(kTeamString.size()) + 1;

  const size_t cd_off = sizeof(CS_SuperBlob) + sizeof(CS_BlobIndex);
  const size_t total = cd_off + kCdLen;
  std::vector<uint8_t> blob(total, 0);

  auto* sb = reinterpret_cast<CS_SuperBlob*>(blob.data());
  sb->magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  sb->length = OSSwapHostToBigInt32(static_cast<uint32_t>(total));
  sb->count = OSSwapHostToBigInt32(1);

  auto* idx = reinterpret_cast<CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  idx->type = OSSwapHostToBigInt32(CSSLOT_CODEDIRECTORY);
  idx->offset = OSSwapHostToBigInt32(static_cast<uint32_t>(cd_off));

  auto* cd = reinterpret_cast<CS_CodeDirectory*>(blob.data() + cd_off);
  cd->magic = OSSwapHostToBigInt32(CSMAGIC_CODEDIRECTORY);
  cd->length = OSSwapHostToBigInt32(kCdLen);
  // Version is < CS_SUPPORTSTEAMID but >= CS_SUPPORTSSCATTER so scatterOffset
  // field exists. The teamOffset field position holds a non-zero byte value
  // (planted below); the parser must ignore it.
  cd->version = OSSwapHostToBigInt32(CS_SUPPORTSSCATTER);  // 0x20100 < CS_SUPPORTSTEAMID
  cd->hashOffset = OSSwapHostToBigInt32(kHashOff);
  cd->identOffset = 0;
  // Intentionally write a non-zero value into the teamOffset field position
  // by typing through teamOffset directly. The parser must not use it.
  cd->teamOffset = OSSwapHostToBigInt32(kTeamStringOff);  // non-zero, but version too old
  cd->scatterOffset = 0;                                  // zero to pass the scatter check
  cd->codeLimit = OSSwapHostToBigInt32(kCodeLimit);
  cd->nCodeSlots = OSSwapHostToBigInt32(1);
  cd->hashSize = kHashSize;
  cd->hashType = CS_HASHTYPE_SHA256;
  cd->pageSize = 12;

  // Write the "would-be team" string at kTeamStringOff.
  std::memcpy(blob.data() + cd_off + kTeamStringOff, kTeamString.c_str(), kTeamString.size() + 1);

  ParsedCodeDirectory parsed;
  std::string err;
  bool ok = ParseCodeSignature(blob, /*slice_size=*/kCodeLimit, parsed, err);
  XCTAssertTrue(ok, @"ParseCodeSignature: %s", err.c_str());
  XCTAssertTrue(parsed.team_id.empty(),
                @"team_id must be empty for pre-CS_SUPPORTSTEAMID CD version");
}

@end
