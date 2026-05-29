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

#include <Security/CMSDecoder.h>
#include <Security/SecPolicy.h>
#include <bsm/libbsm.h>  // audit_token_to_pid
#include <errno.h>
#include <sys/cdefs.h>

__BEGIN_DECLS
#include <Kernel/kern/cs_blobs.h>

// csops_audittoken is not declared in any shipped user-mode header — only
// the syscall number SYS_csops_audittoken exists in <sys/syscall.h>.
// Santa's Source/common/CSOpsHelper.h declares plain csops the same way.
int csops_audittoken(pid_t pid, unsigned int ops, void* useraddr, size_t usersize,
                     audit_token_t* uaudittoken);
__END_DECLS

#include <libkern/OSByteOrder.h>

#include <cstring>
#include <string>

#include "Source/common/ScopedCFTypeRef.h"

namespace santa {

namespace {

// CS_OPS_BLOB op code (xnu bsd/sys/codesign.h). Not exported in user-mode
// headers; defined locally. Matches the convention in CSOpsHelper.h
// (kCsopStatus=0, kCsopCDHash=5, kCsopIdentity=11, kCsopTeamID=14).
// NB: the value is 10, NOT 7 — op 7 is CS_OPS_ENTITLEMENTS_BLOB. Using 7
// would silently fetch the entitlements blob instead of the cs_blob and
// fail the SuperBlob magic check. Verified empirically 2026-05-27.
constexpr unsigned int kCsopBlob = 10;

// Upper bound on any cs_blob we'll trust or allocate for. Mirrors the
// posture in HeaderParser's LC_CODE_SIGNATURE datasize check; keeps a
// bogus or hostile size hint from triggering a huge allocation here.
constexpr size_t kMaxCsBlobSize = 16 * 1024 * 1024;  // 16 MiB

// Looks up a slot of type `slot_type` whose inner CS_GenericBlob has magic
// `expected_magic`, and returns the payload (everything after the 8-byte
// BlobCore magic+length header) on success. Returns an empty span if no
// matching slot exists or any per-slot bounds/magic check fails.
//
// Parity notes (xnu + Apple's libsecurity_utilities):
//
//  * Inner-magic filtering: xnu's csblob_find_blob_bytes
//    (bsd/kern/ubc_subr.c:694) takes `magic` and `continue`s past slots
//    whose inner blob magic doesn't match. xnu's cs_validate_csblob
//    additionally rejects the whole cs_blob if a known-typed slot has
//    wrong magic (e.g. CSSLOT_ENTITLEMENTS without
//    CSMAGIC_EMBEDDED_ENTITLEMENTS — ubc_subr.c:599). Apple's
//    libsecurity SuperBlobCore::find returns the raw blob, but callers
//    re-validate via Blob<T>::specific() which checks magic. We mirror
//    the kernel: enforce per-slot magic right here.
//
//  * ix_limit guard: Apple's SuperBlobCore::validateBlob
//    (libsecurity_utilities/lib/superblob.h:75) rejects any non-zero
//    slot offset that falls inside the SuperBlob header or BlobIndex
//    table. We mirror this by computing the index-table end and skipping
//    slots that point into it (which also covers the offset==0 case
//    Apple's find treats as "no blob").
//
//  * Per-slot failures use `continue`, matching xnu's behavior on magic
//    mismatch (line 717) and length overflow (line 721). Looking
//    further in the same BlobIndex is the more robust choice; in
//    production we never see malformed slots anyway because
//    cs_validate_csblob rejected them before csops returned the buffer.
std::span<const uint8_t> FindSlotPayload(std::span<const uint8_t> cs_blob, uint32_t slot_type,
                                         uint32_t expected_magic) {
  if (cs_blob.size() < sizeof(CS_SuperBlob)) return {};
  const CS_SuperBlob* sb = reinterpret_cast<const CS_SuperBlob*>(cs_blob.data());
  const uint32_t sb_len = OSSwapBigToHostInt32(sb->length);
  const uint32_t sb_count = OSSwapBigToHostInt32(sb->count);
  // sb_len < sizeof(CS_SuperBlob) must be rejected before the subtraction
  // below, or it underflows and max_entries becomes enormous, letting the
  // BlobIndex walk run off the end of cs_blob. Mirrors the guard in
  // CodeSignatureParser::ParseCodeSignature.
  if (sb_len < sizeof(CS_SuperBlob) || sb_len > cs_blob.size()) return {};
  const size_t max_entries = (sb_len - sizeof(CS_SuperBlob)) / sizeof(CS_BlobIndex);
  if (sb_count > max_entries) return {};
  // End of the BlobIndex table; per Apple's SuperBlobCore::validateBlob,
  // no slot payload may begin inside the header/index region.
  const size_t ix_limit = sizeof(CS_SuperBlob) + sb_count * sizeof(CS_BlobIndex);

  const CS_BlobIndex* indices =
      reinterpret_cast<const CS_BlobIndex*>(cs_blob.data() + sizeof(CS_SuperBlob));

  for (uint32_t i = 0; i < sb_count; ++i) {
    if (OSSwapBigToHostInt32(indices[i].type) != slot_type) continue;
    const uint32_t blob_off = OSSwapBigToHostInt32(indices[i].offset);
    // Offset must lie strictly after the index table (Apple parity).
    // Also rejects offset==0 implicitly.
    if (blob_off < ix_limit) continue;
    if (static_cast<uint64_t>(blob_off) + 8 > sb_len) continue;
    uint32_t raw_magic;
    std::memcpy(&raw_magic, cs_blob.data() + blob_off, sizeof(raw_magic));
    if (OSSwapBigToHostInt32(raw_magic) != expected_magic) continue;
    uint32_t raw_len;
    std::memcpy(&raw_len, cs_blob.data() + blob_off + 4, sizeof(raw_len));
    const uint32_t blob_len = OSSwapBigToHostInt32(raw_len);
    if (blob_len < 8) continue;  // need at least magic+length
    if (static_cast<uint64_t>(blob_off) + blob_len > sb_len) continue;
    // Skip the 8-byte BlobCore (magic + length) header, return the payload.
    return std::span<const uint8_t>(cs_blob.data() + blob_off + 8, blob_len - 8);
  }
  return {};
}

}  // namespace

KernelCsBlob::Result KernelCsBlob::ParseBytes(std::span<const uint8_t> kernel_cs_blob,
                                              std::span<const uint8_t> cd_bytes) {
  Result r;

  // Defense-in-depth for the public/fuzz entry point. Fetch() already
  // caps cs_blob_size_hint and the probe-reported blob length, but
  // ParseBytes accepts arbitrary spans — without a cap here, a hostile
  // input could drive FindSlotPayload's BlobIndex walk for an arbitrary
  // amount of work, and slot payloads (CMS / entitlements) could be
  // arbitrarily large. Reject up-front.
  if (kernel_cs_blob.size() > kMaxCsBlobSize) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "kernel cs_blob exceeds size cap";
    return r;
  }
  if (kernel_cs_blob.size() < sizeof(CS_SuperBlob)) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "kernel cs_blob too small for SuperBlob";
    return r;
  }
  const CS_SuperBlob* sb = reinterpret_cast<const CS_SuperBlob*>(kernel_cs_blob.data());
  if (OSSwapBigToHostInt32(sb->magic) != CSMAGIC_EMBEDDED_SIGNATURE) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "kernel cs_blob has wrong SuperBlob magic";
    return r;
  }

  // Extract entitlement slot payloads (CSSLOT_ENTITLEMENTS = 5,
  // CSSLOT_DER_ENTITLEMENTS = 7). Independent of CMS state — present
  // even on ad-hoc binaries if the original codesign included them.
  // Per-slot expected magics match xnu (bsd/kern/ubc_subr.c:3291-3299).
  if (auto xml =
          FindSlotPayload(kernel_cs_blob, CSSLOT_ENTITLEMENTS, CSMAGIC_EMBEDDED_ENTITLEMENTS);
      !xml.empty()) {
    r.entitlement_xml = std::vector<uint8_t>(xml.begin(), xml.end());
  }
  if (auto der = FindSlotPayload(kernel_cs_blob, CSSLOT_DER_ENTITLEMENTS,
                                 CSMAGIC_EMBEDDED_DER_ENTITLEMENTS);
      !der.empty()) {
    r.entitlement_der = std::vector<uint8_t>(der.begin(), der.end());
  }

  // Locate the CMS signature slot.
  auto cms = FindSlotPayload(kernel_cs_blob, CSSLOT_SIGNATURESLOT, CSMAGIC_BLOBWRAPPER);
  if (cms.empty()) {
    r.status = Status::kNoCmsSignature;
    return r;
  }

  // CMSDecoder pipeline. FindSlotPayload already skipped the 8-byte
  // BlobCore header, so `cms` is the raw CMS message bytes.
  ScopedCFTypeRef<CMSDecoderRef> cms_decoder;
  if (CMSDecoderCreate(cms_decoder.InitializeInto()) != errSecSuccess) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "CMSDecoderCreate failed";
    return r;
  }

  if (CMSDecoderUpdateMessage(cms_decoder.Unsafe(), cms.data(), cms.size()) != errSecSuccess) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "CMSDecoderUpdateMessage failed";
    return r;
  }

  // SetDetachedContent gets the CD bytes whose hash matches the
  // messageDigest signed-attribute.
  auto cd_data = ScopedCFTypeRef<CFDataRef>::Assume(
      CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, cd_bytes.data(),
                                  static_cast<CFIndex>(cd_bytes.size()), kCFAllocatorNull));
  if (!cd_data) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "CFDataCreateWithBytesNoCopy(cd_bytes) failed";
    return r;
  }

  if (CMSDecoderSetDetachedContent(cms_decoder.Unsafe(), cd_data.Unsafe()) != errSecSuccess) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "CMSDecoderSetDetachedContent failed";
    return r;
  }

  if (CMSDecoderFinalizeMessage(cms_decoder.Unsafe()) != errSecSuccess) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "CMSDecoderFinalizeMessage failed";
    return r;
  }

  // Developer-controlled signingTime. errSecSigningTimeMissing is a
  // soft-absent signal — leave signing_time as nullopt.
  CFAbsoluteTime t = 0;
  OSStatus sig_st = CMSDecoderCopySignerSigningTime(cms_decoder.Unsafe(), 0, &t);
  if (sig_st == errSecSuccess && t > 0.0) {
    r.signing_time = t;
  } else if (sig_st != errSecSuccess && sig_st != errSecSigningTimeMissing) {
    r.status = Status::kCmsParseFailed;
    r.last_error = "CMSDecoderCopySignerSigningTime failed";
    return r;
  }

  // TSA timestamp. errSecTimestampMissing is the absent-token signal.
  //
  // Build an explicit policy array [AppleTimeStamping, Revocation(no-net)]
  // and pass it instead of nullptr. Passing nullptr causes
  // CMSDecoderCopySignerTimestampWithPolicy to fall back to bare
  // SecPolicyCreateWithOID(kSecPolicyAppleTimeStamping) (see
  // tsaSupport.c verifySigners) — that's fine for revocation (no policy
  // attached, no OCSP/CRL), but it provides no explicit no-network
  // guarantee, and a future SDK that flips the default would silently
  // start fetching. Adding SecPolicyCreateRevocation with
  // kSecRevocationNetworkAccessDisabled annihilates any revocation
  // policy that might appear later. Mirrors what
  // SecStaticCode::createTimeStampingAndRevocationPolicies() builds when
  // kSecCSNoNetworkAccess is in effect (StaticCode.cpp). The residual
  // AIA chain-building fetch path (kSecCAIssuerSource, queried only when
  // the chain can't be completed from the in-message + local-anchor
  // sources) is shared with SecStaticCode and is unreachable for
  // Apple-TSA-signed binaries whose chain is inline.
  // SecPolicyCreateWithOID is deprecated (since 10.9) but is the only *public*
  // API for the Apple timestamping policy — SecPolicyCreateAppleTimeStamping()
  // is SPI (SecPolicyPriv.h), unavailable to out-of-framework code, and is also
  // exactly what Apple's own tsaSupport.c falls back to for a NULL policy. Keep
  // this call; silence the deprecation locally rather than switching APIs.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  auto ts_policy =
      ScopedCFTypeRef<SecPolicyRef>::Assume(SecPolicyCreateWithOID(kSecPolicyAppleTimeStamping));
#pragma clang diagnostic pop
  auto no_revoc = ScopedCFTypeRef<SecPolicyRef>::Assume(
      SecPolicyCreateRevocation(kSecRevocationNetworkAccessDisabled));
  ScopedCFTypeRef<CFArrayRef> ts_policies;
  if (ts_policy && no_revoc) {
    const void* p[] = {ts_policy.Unsafe(), no_revoc.Unsafe()};
    ts_policies = ScopedCFTypeRef<CFArrayRef>::Assume(
        CFArrayCreate(kCFAllocatorDefault, p, 2, &kCFTypeArrayCallBacks));
  }
  // If policy construction failed (extremely unlikely for these stable
  // APIs), fall back to nullptr — same behavior as before this change.
  t = 0;
  OSStatus ts_st = CMSDecoderCopySignerTimestampWithPolicy(
      cms_decoder.Unsafe(), ts_policies ? ts_policies.Unsafe() : nullptr,
      /*signerIndex=*/0, &t);
  if (ts_st == errSecSuccess && t > 0.0) {
    r.secure_signing_time = t;
  } else if (ts_st != errSecSuccess && ts_st != errSecTimestampMissing) {
    // TSA validation failure is not catastrophic for our use case —
    // demote to "secure time absent" but don't fail the whole extraction.
    // (Same posture Apple's StaticCode takes: tolerate missing/invalid
    // TSA, succeed with secure_signing_time = nullopt.)
  }

  r.status = Status::kOk;
  return r;
}

KernelCsBlob::Result KernelCsBlob::Fetch(const audit_token_t& token, size_t cs_blob_size_hint,
                                         std::span<const uint8_t> cd_bytes) {
  Result r;
  audit_token_t mutable_token = token;
  pid_t pid = audit_token_to_pid(mutable_token);

  // Try the one-syscall path: allocate cs_blob_size_hint bytes and ask
  // the kernel. If the hint is right (common case), one syscall serves.
  // If the hint is 0, too large, or too small, fall back to the
  // header-probe pattern. Capping at kMaxCsBlobSize keeps a bogus hint
  // from forcing a huge allocation here — the probe path independently
  // re-applies the same cap to the kernel-reported length.
  std::vector<uint8_t> buf;
  if (cs_blob_size_hint > 0 && cs_blob_size_hint <= kMaxCsBlobSize) {
    buf.resize(cs_blob_size_hint);
    int rc = csops_audittoken(pid, kCsopBlob, buf.data(), buf.size(), &mutable_token);
    if (rc == 0) {
      // Success. Read BlobCore (8 bytes: magic + length, both big-endian)
      // at offset 0 to learn actual blob length.
      if (buf.size() < 8) {
        r.status = Status::kBlobFetchFailed;
        r.last_error = "csops returned undersized buffer";
        return r;
      }
      uint32_t actual_len_be;
      std::memcpy(&actual_len_be, buf.data() + 4, sizeof(actual_len_be));
      uint32_t actual_len = OSSwapBigToHostInt32(actual_len_be);
      if (actual_len > buf.size()) actual_len = static_cast<uint32_t>(buf.size());
      buf.resize(actual_len);
      return ParseBytes(buf, cd_bytes);
    }
    if (errno != ERANGE) {
      r.status = Status::kBlobFetchFailed;
      r.last_error = std::string("csops_audittoken errno=") + std::to_string(errno);
      return r;
    }
    // fall through to header-probe path
  }

  // Header-probe path: ask for just the BlobCore (8 bytes); on ERANGE,
  // the kernel writes the header (which carries length) anyway.
  uint8_t header[8];
  int rc = csops_audittoken(pid, kCsopBlob, header, sizeof(header), &mutable_token);
  if (rc == 0) {
    r.status = Status::kBlobFetchFailed;
    r.last_error = "csops_audittoken unexpectedly returned success on small buf";
    return r;
  }
  if (errno != ERANGE) {
    r.status = Status::kBlobFetchFailed;
    r.last_error = std::string("csops_audittoken header errno=") + std::to_string(errno);
    return r;
  }

  uint32_t blob_len_be;
  std::memcpy(&blob_len_be, header + 4, sizeof(blob_len_be));
  uint32_t blob_len = OSSwapBigToHostInt32(blob_len_be);
  if (blob_len < 8 || blob_len > kMaxCsBlobSize) {
    r.status = Status::kBlobFetchFailed;
    r.last_error = "csops_audittoken reported implausible blob length";
    return r;
  }

  buf.assign(blob_len, 0);
  rc = csops_audittoken(pid, kCsopBlob, buf.data(), buf.size(), &mutable_token);
  if (rc != 0) {
    r.status = Status::kBlobFetchFailed;
    r.last_error = std::string("csops_audittoken full-fetch errno=") + std::to_string(errno);
    return r;
  }

  return ParseBytes(buf, cd_bytes);
}

}  // namespace santa
