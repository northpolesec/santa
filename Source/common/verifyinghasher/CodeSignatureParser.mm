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

#include <libkern/OSByteOrder.h>
#include <os/overflow.h>

#include <cstddef>
#include <cstdio>
#include <cstring>

#include "Source/common/verifyinghasher/HashTraits.h"

namespace santa {

namespace {

struct CDCandidate {
  const CS_CodeDirectory* cd;
  size_t blob_len;
  const uint8_t* blob_base;
};

// Minimum CD blob length we'll accept as a candidate.
//
// We only ever read fields up through `codeLimit64` (offset 56–63 in
// CS_CodeDirectory) — see the field-by-field map in the parser body.
// Hardcoding 64 instead of `sizeof(CS_CodeDirectory)` decouples this gate
// from SDK churn: each new CD version (v0x20400 execSeg*, v0x20500
// preEncrypt*, v0x20600 linkage*, …) inflates the struct in the SDK
// header. A CD that parsed fine yesterday could be silently skipped
// tomorrow after an SDK bump, even though the on-disk bytes haven't
// changed and we never touch the new fields. The static_assert below
// catches the case where the SDK *removes* codeLimit64 (so 64 stops
// covering our reads); add a new field-specific guard if that ever
// happens.
constexpr size_t kMinCdBlobLen = 64;
static_assert(offsetof(CS_CodeDirectory, codeLimit64) + sizeof(uint64_t) <= kMinCdBlobLen,
              "kMinCdBlobLen must cover the bytes we read");

// Hash-type rank, mirroring xnu's hashPriorities order:
//   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/bsd/kern/ubc_subr.c#L226-L231
// Returns 1..4 for supported types (higher = stronger), 0 for unsupported.
// Used by the CD picker to (a) select the strongest candidate and
// (b) detect duplicate hashTypes (xnu rejects same-rank duplicates as
// "illegal and suspicious"; cs_validate_csblob):
//   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/bsd/kern/ubc_subr.c#L593-L597
unsigned int HashRank(uint8_t hash_type) {
  switch (hash_type) {
    case CS_HASHTYPE_SHA1: return 1;
    case CS_HASHTYPE_SHA256_TRUNCATED: return 2;
    case CS_HASHTYPE_SHA256: return 3;
    case CS_HASHTYPE_SHA384: return 4;
    default: return 0;
  }
}

uint8_t HashSizeFor(uint8_t hash_type) {
  switch (hash_type) {
    case CS_HASHTYPE_SHA384: return CC_SHA384_DIGEST_LENGTH;
    case CS_HASHTYPE_SHA256: return CS_SHA256_LEN;
    case CS_HASHTYPE_SHA256_TRUNCATED: return CS_SHA256_TRUNCATED_LEN;
    case CS_HASHTYPE_SHA1: return CS_SHA1_LEN;
    default: return 0;
  }
}

}  // namespace

bool ParseCodeSignature(std::span<const uint8_t> blob, uint64_t slice_size,
                        ParsedCodeDirectory& out, std::string& err) {
  // Reset output up front so callers reusing a ParsedCodeDirectory across
  // parses don't leak stale strings/spans/hashes from a prior successful
  // call through the conditionally-overwritten fields (identifier,
  // team_id) on the next parse, and so every early-return path leaves
  // a clean output.
  out = ParsedCodeDirectory{};
  err.clear();

  if (blob.size() < sizeof(CS_SuperBlob)) {
    err = "code signature blob too small for SuperBlob";
    return false;
  }
  const CS_SuperBlob* sb = reinterpret_cast<const CS_SuperBlob*>(blob.data());
  const uint32_t sb_magic = OSSwapBigToHostInt32(sb->magic);
  if (sb_magic != CSMAGIC_EMBEDDED_SIGNATURE) {
    err = "malformed code signature (bad superblob magic)";
    return false;
  }
  const uint32_t sb_len = OSSwapBigToHostInt32(sb->length);
  const uint32_t sb_count = OSSwapBigToHostInt32(sb->count);
  if (sb_len < sizeof(CS_SuperBlob) || sb_len > blob.size()) {
    err = "malformed code signature (bad superblob length)";
    return false;
  }
  const size_t max_entries = (sb_len - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex);
  if (sb_count > max_entries) {
    err = "malformed code signature (superblob count exceeds available space)";
    return false;
  }

  std::vector<CDCandidate> candidates;
  bool saw_canonical = false;
  const CS_BlobIndex* indices =
      reinterpret_cast<const CS_BlobIndex*>(blob.data() + sizeof(CS_SuperBlob));
  for (uint32_t i = 0; i < sb_count; ++i) {
    const uint32_t slot_type = OSSwapBigToHostInt32(indices[i].type);
    const uint32_t blob_off = OSSwapBigToHostInt32(indices[i].offset);
    // Bound the magic+length header (8 bytes) inside the SuperBlob.
    // Strict `>` (not `>=`) is intentional: blob_off + 8 == sb_len
    // places the header at the SuperBlob's exact tail, with no payload
    // — the next check rejects that via `blob_off + blob_len > sb_len`
    // for any nonzero blob_len.
    if (static_cast<uint64_t>(blob_off) + 8 > sb_len) {
      err = "malformed code signature (blob offset out of range)";
      return false;
    }

    const bool is_canonical = (slot_type == CSSLOT_CODEDIRECTORY);
    const bool is_alternate = (slot_type >= CSSLOT_ALTERNATE_CODEDIRECTORIES &&
                               slot_type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT);
    if (!is_canonical && !is_alternate) continue;

    // Structural floor enforced on every CD candidate, canonical and
    // alternate alike. Matches the preamble of xnu's
    // cs_validate_codedirectory (length >= sizeof(*cd), magic ==
    // CSMAGIC_CODEDIRECTORY) — xnu rejects the whole superblob on any
    // CD failing this, and so do we. Silently skipping a malformed
    // alternate (the prior shape of this loop) lets an attacker steer
    // the picker to a weaker valid CD by malforming higher-rank
    // entries, which can swap the (cdhash, identifier, team_id)
    // triple Santa publishes downstream. The flag and push_back are
    // deferred until after validation passes so saw_canonical only
    // flips on a structurally-valid slot-0 entry — mirrors xnu's
    // primary_cd_exists semantics.
    const uint8_t* p = blob.data() + blob_off;
    uint32_t raw_magic = 0, raw_len = 0;
    std::memcpy(&raw_magic, p, sizeof(raw_magic));
    std::memcpy(&raw_len, p + 4, sizeof(raw_len));
    const uint32_t blob_magic = OSSwapBigToHostInt32(raw_magic);
    const uint32_t blob_len = OSSwapBigToHostInt32(raw_len);

    if (blob_magic != CSMAGIC_CODEDIRECTORY) {
      err = "malformed code signature (CD blob has wrong magic)";
      return false;
    }
    if (static_cast<uint64_t>(blob_off) + blob_len > sb_len) {
      err = "malformed code signature (CD blob length out of range)";
      return false;
    }
    if (blob_len < kMinCdBlobLen) {
      err = "malformed code signature (CD blob too small)";
      return false;
    }

    if (is_canonical) saw_canonical = true;
    candidates.push_back({reinterpret_cast<const CS_CodeDirectory*>(p), blob_len, p});
  }

  if (candidates.empty()) {
    err = "no CodeDirectory blobs found";
    return false;
  }
  if (!saw_canonical) {
    // Apple's CS spec requires slot 0 (CSSLOT_CODEDIRECTORY) to be
    // present. A blob with only alternate CDs is malformed.
    err = "no canonical CodeDirectory (slot 0) in superblob";
    return false;
  }

  // Walk candidates in BlobIndex order and pick highest rank, mirroring
  // xnu's cs_validate_csblob:
  //   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/bsd/kern/ubc_subr.c#L585-L597
  // xnu rejects same-rank duplicates ("illegal and suspicious"); we match
  // that behavior exactly, including its order-dependent quirk where a
  // lower-rank duplicate after a higher-rank candidate is silently
  // ignored (the higher-rank one is already the chosen best).
  const CDCandidate* picked = nullptr;
  unsigned int best_rank = 0;
  for (const auto& c : candidates) {
    unsigned int r = HashRank(c.cd->hashType);
    if (r == 0) continue;  // unsupported hashType, skip
    if (picked == nullptr || r > best_rank) {
      picked = &c;
      best_rank = r;
    } else if (r == best_rank) {
      err = "multiple CodeDirectories with same hashType";
      return false;
    }
  }
  if (!picked) {
    std::string seen;
    for (const auto& c : candidates) {
      char b[8];
      std::snprintf(b, sizeof(b), "%u ", c.cd->hashType);
      seen += b;
    }
    err = "no supported CodeDirectory hashType (found: " + seen + ")";
    return false;
  }

  // The picked CD gets full structural validation below (page count,
  // hashOffset bounds, codeLimit, etc.). Non-picked candidates only
  // get the magic + length floor enforced during candidate collection
  // — the same preamble xnu's cs_validate_codedirectory applies
  // before its deeper checks. Skipping the deeper checks on non-picked
  // candidates is benign: they can't affect the picker (the floor
  // gates entry into the candidates vector) and we only hash the
  // picked CD's bytes.

  const CS_CodeDirectory* cd = picked->cd;
  out.hash_type = cd->hashType;
  out.hash_size = HashSizeFor(cd->hashType);
  if (out.hash_size == 0) {
    err = "CodeDirectory unsupported hashType slipped through";
    return false;
  }
  if (cd->hashSize != out.hash_size) {
    err = "CodeDirectory hashSize mismatch";
    return false;
  }
  // pageSize is log2(page_size_in_bytes). Apple has only ever shipped two
  // values: 12 (4 KiB, macOS) and 16 (64 KiB, iOS). xnu accepts the full
  // 0..31 range, but for a security gate we restrict to [12, 18]:
  //   < 12 (== 4 KiB):  rejects pageSize=0 (the spec's "non-paged
  //                     single-block" mode we don't support) and 1..11
  //                     (sub-4-KiB pages — not used in practice; tiny
  //                     pages + large codeLimits are a CPU/memory DoS
  //                     vector even with the page-count overflow check).
  //   > 18 (== 256 KiB): caps the maximum page size at 256 KiB. Allowing
  //                     larger pages lets an attacker delay tamper
  //                     detection by an entire page worth of I/O before
  //                     PageVerifier finalizes a slot — at pageSize=31
  //                     that's 2 GiB of streaming before we can fail.
  //                     256 KiB is comfortably above today's 64 KiB iOS
  //                     value, leaves headroom for a future Apple bump
  //                     (e.g., 128 KiB / 256 KiB), and keeps detection
  //                     latency trivial on modern storage.
  if (cd->pageSize < 12 || cd->pageSize > 18) {
    err = "CodeDirectory pageSize unsupported (must be 12..18)";
    return false;
  }
  out.page_size = 1u << cd->pageSize;

  const uint32_t version = OSSwapBigToHostInt32(cd->version);

  // Reject scatter-using CDs. Apple's codesign produces a scatter vector
  // only for the dyld shared cache (DYLDCacheRep::Writer::addDiscretionary
  // in libsecurity_codesigning); MachORep / BundleDiskRep / DiskImageRep
  // and friends never set scatterOffset. Santa never sees the shared cache
  // as a regular exec target, so rejecting scatter has zero impact on
  // legitimate verification. Without this reject, a malicious CD that sets
  // scatterOffset would silently produce kPagesMismatched (our linear slot
  // lookup disagrees with xnu's scatter-aware hashes()), which is the
  // right deny-verdict but a misleading diagnostic. Reject explicitly so
  // the assumption "we don't speak scatter" is encoded in the parser, not
  // implicit in the lookup. (scatterOffset is uint32_t big-endian; zero is
  // endian-invariant so a raw-byte compare against 0 is fine.)
  if (version >= CS_SUPPORTSSCATTER && cd->scatterOffset != 0) {
    err = "CodeDirectory uses scatter (unsupported)";
    return false;
  }

  const uint32_t cl32 = OSSwapBigToHostInt32(cd->codeLimit);
  if (version >= CS_SUPPORTSCODELIMIT64 && cd->codeLimit64 != 0) {
    out.code_limit = OSSwapBigToHostInt64(cd->codeLimit64);
  } else {
    out.code_limit = cl32;
  }
  if (out.code_limit > slice_size) {
    err = "CodeDirectory codeLimit exceeds slice size";
    return false;
  }
  // Note: codeLimit == 0 is intentionally accepted. xnu's
  // cs_validate_codedirectory doesn't reject it:
  //   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/bsd/kern/ubc_subr.c#L359
  // Pages outside [0, codeLimit) are treated as "no hash to validate"
  // at runtime in cs_validate_hash:
  //   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/bsd/kern/ubc_subr.c#L5922-L5928
  // and xnu's VM fault handler refuses to map them executable when
  // cs_enforcement_enabled is set (default for most processes):
  //   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/osfmk/vm/vm_fault.c#L2911-L2921
  // Rejecting codeLimit==0 here would be a Santa-only false-positive
  // vs xnu's blob-validation behavior.

  const uint32_t n_code_slots = OSSwapBigToHostInt32(cd->nCodeSlots);
  const uint32_t hash_offset = OSSwapBigToHostInt32(cd->hashOffset);
  // Compute expected page count = ceil(code_limit / page_size) in uint64.
  // Without the explicit overflow + narrow-fit checks, a pathological CD
  // (large codeLimit, small page_size) lets nCodeSlots match a truncated
  // value and PageVerifier walks past the slot table at runtime.
  uint64_t numerator;
  if (os_add_overflow(out.code_limit, static_cast<uint64_t>(out.page_size) - 1, &numerator)) {
    err = "CodeDirectory codeLimit + page_size overflows";
    return false;
  }
  const uint64_t expected_pages_u64 = numerator / out.page_size;
  if (expected_pages_u64 > UINT32_MAX) {
    err = "CodeDirectory page count exceeds UINT32_MAX";
    return false;
  }
  const uint32_t expected_pages = static_cast<uint32_t>(expected_pages_u64);
  // xnu's cs_validate_codedirectory requires the CD's full claimed slot
  // table — nCodeSlots * hash_size bytes starting at hashOffset — to fit
  // in the blob. We later only access expected_pages slots, but enforce
  // the xnu invariant on the full claim so a CD that overstates nCodeSlots
  // beyond what fits gets rejected with the same verdict xnu would give.
  if (hash_offset > picked->blob_len ||
      (picked->blob_len - hash_offset) / out.hash_size < n_code_slots) {
    err = "CodeDirectory nCodeSlots does not fit in blob";
    return false;
  }
  // Asymmetric: accept nCodeSlots > expected_pages, reject nCodeSlots <
  // expected_pages. Rationale:
  //
  // (a) "Extra slots" direction (n_code_slots > expected_pages): xnu's
  //     cs_validate_codedirectory only checks the slot table fits in the
  //     CD blob given nCodeSlots; it doesn't require equality. At runtime,
  //     hashes(cd, page_index) is only called for page_index <
  //     expected_pages (codeLimit bounds it), so extra slots are never
  //     queried — binary runs. Rejecting here would be a Santa-only
  //     false-positive.
  //
  // (b) "Missing slots" direction (n_code_slots < expected_pages): xnu
  //     accepts the blob structurally; at runtime hashes() returns NULL
  //     for page_index >= nCodeSlots → cs_validate_page sets
  //     validated=FALSE → VM fault enforcement blocks the page. The
  //     binary effectively can't execute. We reject early because the
  //     alternative is reading past the actual slot table into other
  //     CD fields (identOffset string, padding, etc.) and reporting
  //     kPagesMismatched on cryptographic non-match — same security
  //     outcome as xnu's runtime block, but a worse diagnostic.
  if (expected_pages > n_code_slots) {
    err = "CodeDirectory has fewer slot hashes than codeLimit/pageSize requires";
    return false;
  }
  out.page_count = expected_pages;

  const size_t slots_bytes = static_cast<size_t>(out.page_count) * out.hash_size;
  // Note: hashOffset < sizeof(CS_CodeDirectory) is intentionally accepted.
  // xnu's cs_validate_codedirectory only checks `length < hashOffset`,
  // not against the CD header size:
  //   https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.101.15/bsd/kern/ubc_subr.c#L382
  // A CD with hashOffset=0 (slot table overlapping the CD header) is
  // structurally weird but xnu's runtime page validator and our
  // PageVerifier both correctly fail it via slot-hash mismatch — the
  // "slot 0" bytes would be CD header fields, never matching a real
  // page hash. Rejecting here would be a Santa-only false-positive vs
  // xnu's blob-validation behavior. The upper bound is enforced below.
  if (hash_offset + slots_bytes > picked->blob_len) {
    err = "CodeDirectory slot hashes out of bounds";
    return false;
  }
  out.slot_hashes = std::span<const uint8_t>(picked->blob_base + hash_offset, slots_bytes);

  // Compute the cdhash of the picked CD: H_picked(cd_blob[0, blob_len)),
  // truncated to CS_CDHASH_LEN. Matches xnu's cs_cd_hash.
  {
    uint8_t full[CC_SHA384_DIGEST_LENGTH];  // largest supported
    switch (out.hash_type) {
      case CS_HASHTYPE_SHA1: {
        Sha1Traits::Ctx c;
        Sha1Traits::Init(&c);
        Sha1Traits::Update(&c, picked->blob_base, picked->blob_len);
        Sha1Traits::Final(full, &c);
        break;
      }
      case CS_HASHTYPE_SHA256:
      case CS_HASHTYPE_SHA256_TRUNCATED: {
        Sha256Traits::Ctx c;
        Sha256Traits::Init(&c);
        Sha256Traits::Update(&c, picked->blob_base, picked->blob_len);
        Sha256Traits::Final(full, &c);
        break;
      }
      case CS_HASHTYPE_SHA384: {
        Sha384Traits::Ctx c;
        Sha384Traits::Init(&c);
        Sha384Traits::Update(&c, picked->blob_base, picked->blob_len);
        Sha384Traits::Final(full, &c);
        break;
      }
      default:
        // Unreachable: HashRank()==0 candidates were rejected at the
        // candidate-selection stage. Defensive abort here would mask
        // a real bug; treat as malformed.
        err = "cdhash: unsupported hashType slipped through";
        return false;
    }
    static_assert(CS_CDHASH_LEN <= CC_SHA1_DIGEST_LENGTH,
                  "all supported hash digests must be at least CS_CDHASH_LEN");
    std::memcpy(out.cdhash, full, CS_CDHASH_LEN);
  }

  // Read the null-terminated identifier string at cd_blob_base + identOffset.
  // Bounded by blob_len to avoid reads past the CodeDirectory blob end.
  {
    uint32_t ident_off = OSSwapBigToHostInt32(cd->identOffset);
    if (ident_off != 0 && ident_off < picked->blob_len) {
      const uint8_t* p = picked->blob_base + ident_off;
      size_t max_len = picked->blob_len - ident_off;
      size_t actual_len = strnlen(reinterpret_cast<const char*>(p), max_len);
      out.identifier.assign(reinterpret_cast<const char*>(p), actual_len);
    }
  }

  // teamOffset is only valid in CodeDirectory version >= CS_SUPPORTSTEAMID.
  // If the CD version predates that, or teamOffset is zero, leave team_id empty.
  {
    const uint32_t team_off = OSSwapBigToHostInt32(cd->teamOffset);
    if (version >= CS_SUPPORTSTEAMID && team_off != 0 && team_off < picked->blob_len) {
      const uint8_t* p = picked->blob_base + team_off;
      size_t max_len = picked->blob_len - team_off;
      size_t actual_len = strnlen(reinterpret_cast<const char*>(p), max_len);
      out.team_id.assign(reinterpret_cast<const char*>(p), actual_len);
    }
  }

  return true;
}

}  // namespace santa
