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

#ifndef SANTA_COMMON_VERIFYINGHASHER_KERNELCSBLOB_H
#define SANTA_COMMON_VERIFYINGHASHER_KERNELCSBLOB_H

#include <CoreFoundation/CoreFoundation.h>
#include <bsm/libbsm.h>  // audit_token_t

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace santa {

// Extracts signing times (developer-controlled + RFC-3161 TSA) and
// entitlement blob bytes from a kernel-resident code-signing SuperBlob.
//
// TRUST CONTRACT — read before consuming Result:
// KernelCsBlob does NOT cryptographically verify the CMS signer. It parses
// the SuperBlob and reads CMS signed attributes; it never calls
// CMSDecoderCopySignerStatus, and CMSDecoderFinalizeMessage does not compare
// the detached-content (cd_bytes) digest against the signed messageDigest
// (that comparison lives in the verify path KCB deliberately skips). So
// `kOk` means "the SuperBlob/CMS parsed and the requested fields were
// present" — NOT "the signature is valid." `signing_time` in particular is
// an unverified, developer-controlled attribute, surfaced verbatim even if
// cd_bytes does not match the messageDigest.
//
// Trust in these fields comes from the CALLER's anchoring, not from KCB:
//   - Fetch() obtains bytes via csops(CS_OPS_BLOB), which the kernel only
//     serves for a CS_VALID/CS_DEBUGGED process, so the blob's CMS was
//     already amfid-validated at load; and
//   - the intended consumer (BinaryAttestation) additionally gates on
//     CS_VALID and a VH.cdhash == ES.cdhash cross-check before trusting any
//     field here.
// `secure_signing_time` is the exception: the TSA token IS trust-evaluated
// (via CMSDecoderCopySignerTimestampWithPolicy) before it is surfaced.
//
// ParseBytes() is a TEST/FUZZ entry point and performs none of the above
// anchoring — do not feed it attacker-influenced bytes in a trust context.
class KernelCsBlob {
 public:
  enum class Status {
    kOk,
    kNoCmsSignature,
    kBlobFetchFailed,
    kCmsParseFailed,
  };

  struct Result {
    Status status = Status::kBlobFetchFailed;
    std::optional<CFAbsoluteTime> signing_time;
    std::optional<CFAbsoluteTime> secure_signing_time;
    std::optional<std::vector<uint8_t>> entitlement_der;
    std::optional<std::vector<uint8_t>> entitlement_xml;
    std::string last_error;
  };

  // Production entry point. Performs csops_audittoken(CS_OPS_BLOB) and
  // hands the bytes to ParseBytes. `cd_bytes` must point at the
  // CodeDirectory blob bytes (typically VH's parsed_cd.cd_bytes); used as
  // detached content for CMSDecoder. `cs_blob_size_hint` should be VH's
  // slice_.cs_blob_size for the one-syscall path; pass 0 to force the
  // header-probe path.
  static Result Fetch(const audit_token_t& token, size_t cs_blob_size_hint,
                      std::span<const uint8_t> cd_bytes);

  // Test entry point. Parses kernel-style cs_blob bytes directly.
  static Result ParseBytes(std::span<const uint8_t> kernel_cs_blob,
                           std::span<const uint8_t> cd_bytes);
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_KERNELCSBLOB_H
