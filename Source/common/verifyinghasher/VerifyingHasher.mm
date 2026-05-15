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

#include "Source/common/verifyinghasher/VerifyingHasher.h"

#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>

#include <algorithm>
#include <cstring>

#include "Source/common/verifyinghasher/CodeSignatureParser.h"
#include "Source/common/verifyinghasher/FileReader.h"
#include "Source/common/verifyinghasher/VerifyingHasherCore.h"

namespace santa {

namespace {

// True iff a == b byte-for-byte. Empty-vs-empty returns false (we never
// claim a "match" against an absent expected cdhash).
bool BytesEqual(std::span<const uint8_t> a, std::span<const uint8_t> b) {
  if (a.empty() || b.empty()) return false;
  if (a.size() != b.size()) return false;
  return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

bool StatMatches(const struct stat& st, const VerifyingHasher::StatTuple& exp) {
  return st.st_dev == exp.dev && st.st_ino == exp.ino && st.st_size == exp.size &&
         st.st_mtimespec.tv_sec == exp.mtime.tv_sec && st.st_mtimespec.tv_nsec == exp.mtime.tv_nsec;
}

}  // namespace

VerifyingHasher::Result VerifyingHasher::Run(int fd, cpu_type_t cputype, cpu_subtype_t cpusubtype,
                                             const Expected& exp, const RunOptions& opts) {
  Result r{};

  // Unsigned path: fstat and verify the stat tuple matches ES's capture
  // before reading anything. A mismatch means the file has been replaced
  // or modified between AUTH EXEC and now — return kError immediately,
  // leaving sha256 nullopt. No point computing a digest of the wrong file.
  if (!exp.signed_check.has_value()) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !StatMatches(st, exp.stat)) {
      r.status = Status::kError;
      return r;
    }
  }

  FdFileReader reader(fd, exp.stat.size);
  ArchSelector want{cputype, cpusubtype};
  VerifyingHasherCore::Options core_opts;
  core_opts.skip_page_hash = opts.skip_page_hash;
  VerifyingHasherCore core(reader, want, core_opts);

  auto core_status = core.Run();

  if (auto d = core.FullFileDigest(); d.size() == CC_SHA256_DIGEST_LENGTH) {
    std::array<uint8_t, CC_SHA256_DIGEST_LENGTH> buf;
    std::copy(d.begin(), d.end(), buf.begin());
    r.sha256 = buf;
  }

  // Unsigned path. The stat tuple was already verified at facade entry;
  // here we additionally require Core to confirm the slice has no embedded
  // code signature. Both conditions are independently load-bearing; do
  // not drop the kNoSignature check on the assumption that "stat already
  // verified the file."
  if (!exp.signed_check.has_value()) {
    if (core_status == VerifyingHasherCore::Status::kNoSignature) {
      r.status = Status::kMatchUnsigned;
    } else {
      r.status = Status::kError;
    }
    return r;
  }

  // Signed path.
  const auto& sig = *exp.signed_check;
  if (core_status != VerifyingHasherCore::Status::kOk) {
    // Includes kPagesMismatched, kNoSignature, kIoError, kMalformedSignature,
    // kSliceNotFound, kNotMachO — all collapse to kError on the Signed path.
    r.status = Status::kError;
    return r;
  }

  auto computed_cdhash = core.CDHash();
  const auto& parsed = core.ParsedCD();

  if (BytesEqual(computed_cdhash, sig.cdhash)) {
    r.status = Status::kMatchCDHash;
  } else if (!sig.signing_id.empty() && !sig.team_id.empty() &&
             parsed.identifier == sig.signing_id && parsed.team_id == sig.team_id) {
    // Drift detection requires a non-empty signed_check->team_id; ad-hoc
    // binaries (empty team_id) carry weaker identity than the team-signed
    // model the drift fallback assumes and fall through to kNoMatch on
    // any cdhash mismatch.
    r.status = Status::kMatchSidTidDrift;
  } else {
    r.status = Status::kNoMatch;
  }
  return r;
}

}  // namespace santa
