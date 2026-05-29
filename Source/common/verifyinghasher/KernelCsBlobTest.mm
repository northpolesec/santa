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

#include "Source/common/verifyinghasher/KernelCsBlob.h"

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
#include <span>
#include <string>
#include <vector>

#include "Source/common/ScopedFile.h"
#include "Source/common/verifyinghasher/CodeSignatureParser.h"

namespace {

// ---- Reference helpers (mirrored from VerifyingHasherTest.mm) ----
// These are file-scope free functions, not in a shared header — the
// duplication is the pragmatic choice for now. A follow-up could extract
// them to a shared test-helper objc_library if it becomes annoying.

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
  santa::ScopedFile sf(::open(path, O_RDONLY | O_CLOEXEC));
  if (sf.UnsafeFD() < 0) return {};
  struct stat st{};
  if (::fstat(sf.UnsafeFD(), &st) != 0) return {};
  std::vector<uint8_t> v(static_cast<size_t>(st.st_size));
  ssize_t n = ::pread(sf.UnsafeFD(), v.data(), v.size(), 0);
  if (n != static_cast<ssize_t>(v.size())) return {};
  return v;
}

// Big-endian u32 append helper.
void AppendBE32(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back(static_cast<uint8_t>((x >> 24) & 0xff));
  v.push_back(static_cast<uint8_t>((x >> 16) & 0xff));
  v.push_back(static_cast<uint8_t>((x >> 8) & 0xff));
  v.push_back(static_cast<uint8_t>(x & 0xff));
}

// Wrapper magic the kernel expects for each well-known slot type. Mirrors
// xnu's per-type checks in cs_validate_csblob (bsd/kern/ubc_subr.c) and the
// magic arg the kernel passes to csblob_find_blob_bytes (lines 3291–3299).
uint32_t DefaultWrapperMagicForSlot(uint32_t slot_type) {
  switch (slot_type) {
    case CSSLOT_ENTITLEMENTS: return CSMAGIC_EMBEDDED_ENTITLEMENTS;
    case CSSLOT_DER_ENTITLEMENTS: return CSMAGIC_EMBEDDED_DER_ENTITLEMENTS;
    case CSSLOT_SIGNATURESLOT: return CSMAGIC_BLOBWRAPPER;
    default: return CSMAGIC_BLOBWRAPPER;
  }
}

// One slot's contribution to a synthetic SuperBlob. `wrapper_magic` is the
// CS_GenericBlob magic written at the slot's payload offset.
struct SlotSpec {
  uint32_t type;
  uint32_t wrapper_magic;
  std::vector<uint8_t> payload;
};

// Common SuperBlob assembly used by MakeSuperBlob and MakeSuperBlobWithMagics.
std::vector<uint8_t> AssembleSuperBlob(const std::vector<SlotSpec>& slots) {
  const uint32_t count = static_cast<uint32_t>(slots.size());
  const uint32_t index_table_end = static_cast<uint32_t>(sizeof(CS_SuperBlob)) +
                                   count * static_cast<uint32_t>(sizeof(CS_BlobIndex));

  std::vector<uint32_t> offsets;
  uint32_t cursor = index_table_end;
  for (const auto& s : slots) {
    offsets.push_back(cursor);
    cursor += 8 + static_cast<uint32_t>(s.payload.size());  // wrapper hdr + payload
  }
  const uint32_t total = cursor;

  std::vector<uint8_t> out;
  out.reserve(total);
  AppendBE32(out, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(out, total);
  AppendBE32(out, count);
  for (size_t i = 0; i < slots.size(); ++i) {
    AppendBE32(out, slots[i].type);
    AppendBE32(out, offsets[i]);
  }
  for (const auto& s : slots) {
    AppendBE32(out, s.wrapper_magic);
    AppendBE32(out, 8 + static_cast<uint32_t>(s.payload.size()));
    out.insert(out.end(), s.payload.begin(), s.payload.end());
  }
  return out;
}

// Build a minimal valid CS SuperBlob (CSMAGIC_EMBEDDED_SIGNATURE) carrying
// the given slots. Each payload is wrapped in an 8-byte CS_GenericBlob
// header whose magic is derived from the slot type via
// DefaultWrapperMagicForSlot — so callers in positive tests don't have to
// repeat the well-known per-slot magic. For tests that need to exercise
// wrong-magic rejection, use MakeSuperBlobWithMagics.
std::vector<uint8_t> MakeSuperBlob(
    const std::vector<std::pair<uint32_t, std::vector<uint8_t>>>& slots) {
  std::vector<SlotSpec> with_magics;
  with_magics.reserve(slots.size());
  for (const auto& [type, payload] : slots) {
    with_magics.push_back({type, DefaultWrapperMagicForSlot(type), payload});
  }
  return AssembleSuperBlob(with_magics);
}

// Same as MakeSuperBlob but caller picks the wrapper magic per slot. Used
// by negative tests that need to construct a slot whose inner magic does
// not match what KCB expects for that slot type.
std::vector<uint8_t> MakeSuperBlobWithMagics(const std::vector<SlotSpec>& slots) {
  return AssembleSuperBlob(slots);
}

// Parse a cs_blob and return a copy of the picked CodeDirectory's bytes.
// Returns empty on parse failure. We only need the CD bytes here (for use
// as CMSDecoder detached content), so pass an effectively-unbounded
// slice_size — the codeLimit<=slice_size check is a DoS guard unrelated to
// CD-bytes extraction, and the real slice size isn't available here.
std::vector<uint8_t> ExtractCdBytes(std::span<const uint8_t> cs_blob) {
  santa::ParsedCodeDirectory parsed;
  std::string err;
  if (!santa::ParseCodeSignature(cs_blob, UINT64_MAX, parsed, err)) {
    return {};
  }
  return std::vector<uint8_t>(parsed.cd_bytes.begin(), parsed.cd_bytes.end());
}

}  // namespace

@interface KernelCsBlobTest : XCTestCase
@end

@implementation KernelCsBlobTest

// Returns the absolute path to a fixture under the test bundle's testdata/.
- (NSString*)fixturePath:(NSString*)name {
  NSBundle* bundle = [NSBundle bundleForClass:[self class]];
  return [bundle.resourcePath
      stringByAppendingPathComponent:[@"testdata" stringByAppendingPathComponent:name]];
}

- (void)testParseBytesEmptyInputFailsParse {
  std::vector<uint8_t> empty;
  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(empty, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kCmsParseFailed);
  XCTAssertFalse(r.last_error.empty());
}

- (void)testParseBytesBadSuperBlobMagicFailsParse {
  // Construct minimum-sized buffer with bogus magic.
  std::vector<uint8_t> bad(sizeof(CS_SuperBlob), 0);
  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(bad, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kCmsParseFailed);
}

- (void)testParseBytesRejectsOversizedInput {
  // Defense-in-depth for the public/fuzz entry point: cs_blob larger than
  // KCB's 16 MiB cap must be rejected up-front, before FindSlotPayload
  // walks an attacker-controlled BlobIndex. Mirrors the cap that Fetch
  // already applies to cs_blob_size_hint and the probe-reported length.
  const size_t kJustOverCap = 16 * 1024 * 1024 + 1;
  std::vector<uint8_t> oversized(kJustOverCap, 0);
  // Even with a valid magic, the size cap rejects up-front.
  uint32_t magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  std::memcpy(oversized.data(), &magic, sizeof(magic));
  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(oversized, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kCmsParseFailed);
  XCTAssertFalse(r.last_error.empty());
}

- (void)testParseBytesUndersizedSuperBlobLengthDoesNotOverread {
  // Valid embedded-signature magic, but sb->length is smaller than the
  // SuperBlob header while sb->count is huge. A missing `sb_len >=
  // sizeof(CS_SuperBlob)` guard underflows the max_entries computation and
  // walks the BlobIndex far past the buffer. Must be rejected, not crash.
  std::vector<uint8_t> blob(64, 0);
  uint32_t magic = OSSwapHostToBigInt32(CSMAGIC_EMBEDDED_SIGNATURE);
  std::memcpy(blob.data(), &magic, sizeof(magic));
  uint32_t len = OSSwapHostToBigInt32(4);  // < sizeof(CS_SuperBlob)
  std::memcpy(blob.data() + 4, &len, sizeof(len));
  uint32_t count = OSSwapHostToBigInt32(0x00ffffff);  // absurdly large
  std::memcpy(blob.data() + 8, &count, sizeof(count));

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);

  // No slot may be reported, and the structurally-bogus blob has no CMS.
  XCTAssertFalse(r.entitlement_der.has_value());
  XCTAssertFalse(r.entitlement_xml.has_value());
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

- (void)testFetchReturnsBlobFetchFailedForZeroToken {
  // A zero audit_token resolves to pid 0; csops_audittoken will refuse.
  audit_token_t token{};
  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::Fetch(token, 0, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kBlobFetchFailed);
  XCTAssertFalse(r.last_error.empty());
}

- (void)testParseBytesExtractsEntitlements {
  auto bytes = Slurp([self fixturePath:@"hw_entitled"].UTF8String);
  XCTAssertFalse(bytes.empty());
  auto cs_blob = ExtractCsBlobBytes(bytes, CPU_TYPE_ARM64);
  XCTAssertFalse(cs_blob.empty());
  auto cd_bytes = ExtractCdBytes(cs_blob);
  XCTAssertFalse(cd_bytes.empty());

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd_bytes);

  // Status will still be kNoCmsSignature or kOk (CMS extraction is the
  // next task). What we care about here is entitlement_der.
  XCTAssertTrue(r.entitlement_der.has_value());
  XCTAssertFalse(r.entitlement_der->empty());

  // entitlement_xml is also expected to be populated for the hw_entitled
  // fixture since codesign produces both slots when given --entitlements.
  XCTAssertTrue(r.entitlement_xml.has_value());
  XCTAssertFalse(r.entitlement_xml->empty());

  // The bytes returned should be the inner payload, not including the
  // CS_GenericBlob magic/length header. Just assert the first byte isn't
  // the BlobCore magic high byte.
  XCTAssertNotEqual((*r.entitlement_xml)[0], 0xFA);
}

- (void)testParseBytesAdHocHasNoEntitlements {
  auto bytes = Slurp([self fixturePath:@"hw_universal"].UTF8String);
  XCTAssertFalse(bytes.empty());
  auto cs_blob = ExtractCsBlobBytes(bytes, CPU_TYPE_ARM64);
  XCTAssertFalse(cs_blob.empty());
  auto cd_bytes = ExtractCdBytes(cs_blob);

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd_bytes);

  XCTAssertFalse(r.entitlement_der.has_value());
  XCTAssertFalse(r.entitlement_xml.has_value());
}

- (void)testParseBytesExtractsSigningTimeFromCmsSignedBinary {
  auto bytes = Slurp([self fixturePath:@"hw_team_signed"].UTF8String);
  XCTAssertFalse(bytes.empty());
  auto cs_blob = ExtractCsBlobBytes(bytes, CPU_TYPE_ARM64);
  XCTAssertFalse(cs_blob.empty());
  auto cd_bytes = ExtractCdBytes(cs_blob);
  XCTAssertFalse(cd_bytes.empty());

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd_bytes);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kOk);
  XCTAssertTrue(r.signing_time.has_value(), @"expected signing_time on team-signed fixture");
  // CFAbsoluteTime epoch is 2001-01-01. Anything sensible should be > 0.
  XCTAssertGreaterThan(*r.signing_time, 0.0);
}

- (void)testParseBytesMismatchedCdBytesStillExtractsSigningTime {
  // Contract pin: KCB performs NO signer verification. CMSDecoderFinalizeMessage
  // only COMPUTES the detached-content (cd_bytes) digest; it never compares it
  // to the signed messageDigest (that comparison lives in
  // CMSDecoderCopySignerStatus, which KCB never calls). So a well-formed but
  // WRONG cd_bytes must not change the outcome — the developer-controlled
  // signingTime is read straight from the CMS signed attributes regardless.
  // (Correct-cd_bytes case: testParseBytesExtractsSigningTimeFromCmsSignedBinary.)
  // In production this can't happen — BinaryAttestation gates KCB on
  // VH.cdhash == ES.cdhash — but pinning it here documents that `kOk` /
  // `signing_time` carry no signature guarantee on their own.
  auto bytes = Slurp([self fixturePath:@"hw_team_signed"].UTF8String);
  XCTAssertFalse(bytes.empty());
  auto cs_blob = ExtractCsBlobBytes(bytes, CPU_TYPE_ARM64);
  XCTAssertFalse(cs_blob.empty());
  auto cd_bytes = ExtractCdBytes(cs_blob);
  XCTAssertFalse(cd_bytes.empty());

  // Corrupt the CD bytes so they no longer hash to the signed messageDigest,
  // while remaining a well-formed, non-empty detached-content buffer.
  std::vector<uint8_t> wrong_cd = cd_bytes;
  wrong_cd[0] ^= 0xFF;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, wrong_cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kOk);
  XCTAssertTrue(r.signing_time.has_value());
  XCTAssertGreaterThan(*r.signing_time, 0.0);
}

- (void)testParseBytesAdHocReturnsNoCmsSignature {
  // hw_universal is multi-CD ad-hoc-signed; has no CMS slot.
  auto bytes = Slurp([self fixturePath:@"hw_universal"].UTF8String);
  XCTAssertFalse(bytes.empty());
  auto cs_blob = ExtractCsBlobBytes(bytes, CPU_TYPE_ARM64);
  XCTAssertFalse(cs_blob.empty());
  auto cd_bytes = ExtractCdBytes(cs_blob);

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd_bytes);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
  XCTAssertFalse(r.signing_time.has_value());
  XCTAssertFalse(r.secure_signing_time.has_value());
}

- (void)testParseBytesExtractsSecureSigningTimeFromNotarizedBinary {
  // santactl_2026.4.csblob is a real Developer-ID-signed, TSA-timestamped
  // SuperBlob captured from a released NPS Santa binary. The fixture
  // file IS the cs_blob (no Mach-O wrapper), so we Slurp it directly.
  auto cs_blob = Slurp([self fixturePath:@"santactl_2026.4.csblob"].UTF8String);
  XCTAssertFalse(cs_blob.empty());
  auto cd_bytes = ExtractCdBytes(cs_blob);
  XCTAssertFalse(cd_bytes.empty());

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd_bytes);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kOk);
  // Developer-controlled signingTime present.
  XCTAssertTrue(r.signing_time.has_value());
  XCTAssertGreaterThan(*r.signing_time, 0.0);
  // RFC-3161 TSA timestamp present (the point of this fixture).
  XCTAssertTrue(r.secure_signing_time.has_value(), @"expected TSA timestamp on notarized fixture");
  XCTAssertGreaterThan(*r.secure_signing_time, 0.0);
}

- (void)testParseBytesGarbageCmsReturnsCmsParseFailed {
  // Synthetic SuperBlob with a CMS slot whose payload is non-DER bytes.
  // FindSlotPayload locates the slot (non-empty), so we reach the
  // CMSDecoder pipeline; CMSDecoderUpdateMessage or Finalize must reject
  // the garbage and surface kCmsParseFailed with a populated last_error.
  std::vector<uint8_t> garbage(128, 0xAB);
  auto cs_blob = MakeSuperBlob({{static_cast<uint32_t>(CSSLOT_SIGNATURESLOT), garbage}});
  std::vector<uint8_t> cd(32, 0x11);  // any non-empty bytes; CFData must construct

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kCmsParseFailed);
  XCTAssertFalse(r.last_error.empty());
  XCTAssertFalse(r.signing_time.has_value());
  XCTAssertFalse(r.secure_signing_time.has_value());
}

- (void)testParseBytesCmsFailureStillExtractsEntitlements {
  // Cross-cutting (spec §Testing Strategy / Entitlement coverage): a
  // kCmsParseFailed result must NOT void independent slot data.
  // Synthetic SuperBlob with a valid-looking entitlement XML slot and a
  // garbage CMS slot — entitlements must still come through.
  std::vector<uint8_t> xml = {'<', 'p', 'l', 'i', 's', 't', '>'};
  std::vector<uint8_t> garbage(128, 0xAB);
  auto cs_blob = MakeSuperBlob({
      {static_cast<uint32_t>(CSSLOT_ENTITLEMENTS), xml},
      {static_cast<uint32_t>(CSSLOT_SIGNATURESLOT), garbage},
  });
  std::vector<uint8_t> cd(32, 0x11);

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kCmsParseFailed);
  XCTAssertTrue(r.entitlement_xml.has_value());
  XCTAssertEqual(r.entitlement_xml->size(), xml.size());
  XCTAssertEqual(0, std::memcmp(r.entitlement_xml->data(), xml.data(), xml.size()));
}

// ---- Tier 1: FindSlotPayload bounds-check coverage ----
// Each test exercises one specific bounds guard via a hand-crafted
// malformed SuperBlob. ParseBytes' magic check still passes (we write a
// valid magic); the rejection happens inside FindSlotPayload for the
// signature/entitlement slot lookups, so the externally-visible result
// is kNoCmsSignature with no entitlements populated.

- (void)testParseBytesSuperBlobLengthOverrunsBuffer {
  // sb->length = 128, but the buffer is only sizeof(CS_SuperBlob)=12.
  // FindSlotPayload's `sb_len > cs_blob.size()` guard must reject.
  std::vector<uint8_t> blob;
  AppendBE32(blob, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(blob, 128);  // sb_len claims 128 bytes
  AppendBE32(blob, 0);    // sb_count

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
  XCTAssertFalse(r.entitlement_der.has_value());
  XCTAssertFalse(r.entitlement_xml.has_value());
}

- (void)testParseBytesSlotCountOverrunsIndexTable {
  // sb_len leaves zero room for BlobIndex entries (sb_len == sizeof header),
  // but sb_count claims 10 entries. FindSlotPayload's `sb_count > max_entries`
  // guard must reject.
  std::vector<uint8_t> blob;
  AppendBE32(blob, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(blob, static_cast<uint32_t>(sizeof(CS_SuperBlob)));  // sb_len = 12
  AppendBE32(blob, 10);                                           // sb_count, but max_entries = 0

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

- (void)testParseBytesSlotOffsetOverrunsSuperBlob {
  // One slot whose offset+8 lies past sb_len. FindSlotPayload's
  // `blob_off + 8 > sb_len` guard must reject.
  std::vector<uint8_t> blob;
  AppendBE32(blob, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(blob, 20);  // sb_len = 12 header + 8 one BlobIndex entry
  AppendBE32(blob, 1);
  AppendBE32(blob, static_cast<uint32_t>(CSSLOT_SIGNATURESLOT));
  AppendBE32(blob, 15);  // offset 15 → +8 = 23 > sb_len=20

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

- (void)testParseBytesSlotLengthOverrunsSuperBlob {
  // Slot points to a blob whose declared length extends past sb_len.
  // FindSlotPayload's `blob_off + blob_len > sb_len` guard must reject.
  std::vector<uint8_t> blob;
  AppendBE32(blob, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(blob, 28);  // sb_len = 12 header + 8 index + 8 wrapper hdr
  AppendBE32(blob, 1);
  AppendBE32(blob, static_cast<uint32_t>(CSSLOT_SIGNATURESLOT));
  AppendBE32(blob, 20);          // offset 20
  AppendBE32(blob, 0xfade0b01);  // wrapper magic at offset 20
  AppendBE32(blob, 100);         // wrapper length = 100; 20+100=120 > sb_len=28

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

- (void)testParseBytesSlotLengthLessThan8 {
  // Wrapper length < 8 leaves no room for the BlobCore header itself.
  // FindSlotPayload's `blob_len < 8` guard must reject.
  std::vector<uint8_t> blob;
  AppendBE32(blob, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(blob, 28);
  AppendBE32(blob, 1);
  AppendBE32(blob, static_cast<uint32_t>(CSSLOT_SIGNATURESLOT));
  AppendBE32(blob, 20);
  AppendBE32(blob, 0xfade0b01);
  AppendBE32(blob, 4);  // length 4 < 8

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

// ---- Tier 2: spec contract tests ----

- (void)testParseBytesEmptyCmsSlotReturnsNoCmsSignature {
  // Spec §Error Handling: "Empty vs absent SignatureSlot: both produce
  // kNoCmsSignature in KCB." The absent case is covered by hw_universal;
  // this covers the empty case (slot present, payload length 0).
  auto cs_blob =
      MakeSuperBlob({{static_cast<uint32_t>(CSSLOT_SIGNATURESLOT), std::vector<uint8_t>{}}});
  std::vector<uint8_t> empty_cd;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, empty_cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
  XCTAssertFalse(r.signing_time.has_value());
  XCTAssertFalse(r.secure_signing_time.has_value());
}

- (void)testParseBytesDerOnlyEntitlements {
  // DER slot present, XML slot absent — slot extraction is independent.
  std::vector<uint8_t> der_payload = {0x30, 0x82, 0x00, 0x05, 'D', 'E', 'R', '!'};
  auto cs_blob = MakeSuperBlob({{static_cast<uint32_t>(CSSLOT_DER_ENTITLEMENTS), der_payload}});
  std::vector<uint8_t> empty_cd;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, empty_cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
  XCTAssertTrue(r.entitlement_der.has_value());
  XCTAssertEqual(r.entitlement_der->size(), der_payload.size());
  XCTAssertEqual(0, std::memcmp(r.entitlement_der->data(), der_payload.data(), der_payload.size()));
  XCTAssertFalse(r.entitlement_xml.has_value());
}

- (void)testParseBytesXmlOnlyEntitlements {
  // XML slot present, DER slot absent — symmetric to the DER-only case.
  std::vector<uint8_t> xml_payload = {'<', 'p', 'l', 'i', 's', 't', '/', '>'};
  auto cs_blob = MakeSuperBlob({{static_cast<uint32_t>(CSSLOT_ENTITLEMENTS), xml_payload}});
  std::vector<uint8_t> empty_cd;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, empty_cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
  XCTAssertTrue(r.entitlement_xml.has_value());
  XCTAssertEqual(r.entitlement_xml->size(), xml_payload.size());
  XCTAssertEqual(0, std::memcmp(r.entitlement_xml->data(), xml_payload.data(), xml_payload.size()));
  XCTAssertFalse(r.entitlement_der.has_value());
}

- (void)testParseBytesDuplicateSlotTypeFirstWins {
  // Two entries with the same slot type. KCB matches xnu's
  // csblob_find_blob_bytes semantics: the first BlobIndex entry of the
  // requested type wins. Pinning this prevents an accidental "last wins"
  // refactor from diverging from kernel behavior.
  std::vector<uint8_t> first = {'f', 'i', 'r', 's', 't'};
  std::vector<uint8_t> second = {'s', 'e', 'c', 'o', 'n', 'd', '!', '!'};
  auto cs_blob = MakeSuperBlob({
      {static_cast<uint32_t>(CSSLOT_ENTITLEMENTS), first},
      {static_cast<uint32_t>(CSSLOT_ENTITLEMENTS), second},
  });
  std::vector<uint8_t> empty_cd;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, empty_cd);

  XCTAssertTrue(r.entitlement_xml.has_value());
  XCTAssertEqual(r.entitlement_xml->size(), first.size());
  XCTAssertEqual(0, std::memcmp(r.entitlement_xml->data(), first.data(), first.size()));
}

// ---- Tier 3: kernel/Apple-parity rejections ----

- (void)testParseBytesEntitlementSlotWrongMagicSkipped {
  // xnu's cs_validate_csblob rejects a CSSLOT_ENTITLEMENTS blob whose
  // inner magic is not CSMAGIC_EMBEDDED_ENTITLEMENTS (ubc_subr.c:599);
  // its csblob_find_blob_bytes (line 717) `continue`s past slots whose
  // inner magic differs from what the caller asked for. KCB must mirror
  // that: a wrong-magic entitlement slot is NOT surfaced as an
  // entitlement, even though the kernel would have rejected the entire
  // cs_blob upstream so we won't see this in production.
  std::vector<uint8_t> payload = {'b', 'o', 'g', 'u', 's'};
  auto cs_blob = MakeSuperBlobWithMagics({
      {static_cast<uint32_t>(CSSLOT_ENTITLEMENTS), 0xdeadbeef, payload},
  });
  std::vector<uint8_t> empty_cd;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, empty_cd);

  XCTAssertFalse(r.entitlement_xml.has_value());
  XCTAssertFalse(r.entitlement_der.has_value());
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

- (void)testParseBytesCmsSlotWrongMagicSkipped {
  // Kernel parity: a slot of type CSSLOT_SIGNATURESLOT with inner magic
  // != CSMAGIC_BLOBWRAPPER must be ignored. We never reach CMSDecoder,
  // and the lookup returns "absent" rather than feeding garbage in.
  std::vector<uint8_t> garbage(64, 0xCC);
  auto cs_blob = MakeSuperBlobWithMagics({
      {static_cast<uint32_t>(CSSLOT_SIGNATURESLOT), 0xdeadbeef, garbage},
  });
  std::vector<uint8_t> empty_cd;

  auto r = santa::KernelCsBlob::ParseBytes(cs_blob, empty_cd);

  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
  XCTAssertFalse(r.signing_time.has_value());
  XCTAssertFalse(r.secure_signing_time.has_value());
}

- (void)testParseBytesSlotOffsetIntoHeaderRejected {
  // Apple's SuperBlobCore::validateBlob
  // (libsecurity_utilities/lib/superblob.h:75) rejects any non-zero slot
  // offset that points into the SuperBlob header or BlobIndex region.
  // For a single-slot SuperBlob, ix_limit = sizeof(CS_SuperBlob) +
  // sizeof(CS_BlobIndex) = 20. Offset 16 lies inside that region.
  std::vector<uint8_t> blob;
  AppendBE32(blob, CSMAGIC_EMBEDDED_SIGNATURE);
  AppendBE32(blob, 28);  // sb_len = 12 header + 8 index + 8 wrapper hdr
  AppendBE32(blob, 1);
  AppendBE32(blob, static_cast<uint32_t>(CSSLOT_SIGNATURESLOT));
  AppendBE32(blob, 16);  // offset 16 < ix_limit (20) — inside index table
  AppendBE32(blob, CSMAGIC_BLOBWRAPPER);
  AppendBE32(blob, 8);

  std::vector<uint8_t> empty_cd;
  auto r = santa::KernelCsBlob::ParseBytes(blob, empty_cd);
  XCTAssertEqual(r.status, santa::KernelCsBlob::Status::kNoCmsSignature);
}

@end
