/// Copyright 2025 North Pole Security, Inc.
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

#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"

// Terminal value that will never match a valid cert hash.
NSString *const kBadCertHash = @"BAD_CERT_HASH";

namespace santa {

FAAPolicyProcessor::FAAPolicyProcessor(SNTDecisionCache *decision_cache)
    : decision_cache_(decision_cache) {}

NSString *FAAPolicyProcessor::GetCertificateHash(const es_file_t *es_file) {
  // First see if we've already cached this value
  NSLog(@"GetCertificateHash ENTER");
  SantaVnode vnodeID = SantaVnode::VnodeForFile(es_file);
  NSString *result = cert_hash_cache_.get(vnodeID);
  if (!result) {
    // If this wasn't already cached, try finding a cached SNTCachedDecision
    SNTCachedDecision *cd = [decision_cache_ cachedDecisionForFile:es_file->stat];
    if (cd) {
      // There was an existing cached decision, use its cert hash
      result = cd.certSHA256;
    } else {
      // If the cached decision didn't exist, try a manual lookup
      NSError *e;
      MOLCodesignChecker *csInfo =
          [[MOLCodesignChecker alloc] initWithBinaryPath:@(es_file->path.data) error:&e];
      if (!e) {
        result = csInfo.leafCertificate.SHA256;
      }
    }

    if (!result.length) {
      // If result is still nil, there isn't much recourse... We will
      // assume that this error isn't transient and set a terminal value
      // in the cache to prevent continous attempts to lookup cert hash.
      result = kBadCertHash;
    }

    // Finally, add the result to the cache to prevent future lookups
    cert_hash_cache_.set(vnodeID, result);
  }

  return result;
}

/// An An `es_process_t` must match all criteria within the given
/// WatchItemProcess to be considered a match.
bool FAAPolicyProcessor::PolicyMatchesProcess(const WatchItemProcess &policy_proc,
                                              const es_process_t *es_proc) {
  // Note: Intentionally not checking `CS_VALID` here - this check must happen
  // outside of this method. This method is used to individually check each
  // configured process exception while the check for a valid code signature
  // is more broad and applies whether or not process exceptions exist.
  if (es_proc->codesigning_flags & CS_SIGNED) {
    // Check whether or not the process is a platform binary if specified by the policy.
    if (policy_proc.platform_binary.has_value() &&
        policy_proc.platform_binary.value() != es_proc->is_platform_binary) {
      return false;
    }

    // If the policy contains a team ID, check that the instigating process
    // also has a team ID and matches the policy.
    if (!policy_proc.team_id.empty() &&
        (!es_proc->team_id.data || (policy_proc.team_id != es_proc->team_id.data))) {
      // We expected a team ID to match against, but the process didn't have one.
      return false;
    }

    // If the policy contains a signing ID, check that the instigating process
    // also has a signing ID and matches the policy.
    if (!policy_proc.signing_id.empty() &&
        (!es_proc->signing_id.data || (policy_proc.signing_id != es_proc->signing_id.data))) {
      return false;
    }

    // Check if the instigating process has an allowed CDHash
    if (policy_proc.cdhash.size() == CS_CDHASH_LEN &&
        std::memcmp(policy_proc.cdhash.data(), es_proc->cdhash, CS_CDHASH_LEN) != 0) {
      return false;
    }

    // Check if the instigating process has an allowed certificate hash
    if (!policy_proc.certificate_sha256.empty()) {
      NSString *result = GetCertificateHash(es_proc->executable);
      if (!result || policy_proc.certificate_sha256 != [result UTF8String]) {
        return false;
      }
    }
  } else {
    // If the process isn't signed, ensure the policy doesn't contain any
    // attributes that require a signature
    if (!policy_proc.team_id.empty() || !policy_proc.signing_id.empty() ||
        policy_proc.cdhash.size() == CS_CDHASH_LEN || !policy_proc.certificate_sha256.empty()) {
      return false;
    }
  }

  // Check if the instigating process path opening the file is allowed
  if (policy_proc.binary_path.length() > 0 &&
      policy_proc.binary_path != es_proc->executable->path.data) {
    return false;
  }

  return true;
}

SNTCachedDecision *FAAPolicyProcessor::GetCachedDecision(const struct stat &stat_buf) {
  return [decision_cache_ cachedDecisionForFile:stat_buf];
}

}  // namespace santa
