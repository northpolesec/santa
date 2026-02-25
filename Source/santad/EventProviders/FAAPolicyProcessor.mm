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

#include <bsm/libbsm.h>
#include <pwd.h>

#include "Source/common/AuditUtilities.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTBlockMessage.h"
#include "Source/common/SNTStoredFileAccessEvent.h"
#include "Source/common/String.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

// Terminal value that will never match a valid cert hash.
NSString *const kBadCertHash = @"BAD_CERT_HASH";

namespace santa {

// Semi-arbitrary values for the reads_cache_ and tty_message SantaSetCache
// objects. The number of processes should be large enough to have room for
// simultaneously running processes that might match FAA rules. The
// per-process capacity should be large enough to help speed up consecutive
// reads or deduplicate TTY messages.
static constexpr size_t kNumProcesses = 2048;
static constexpr size_t kPerProcessSetCapacity = 128;

static constexpr uint32_t kOpenFlagsIndicatingWrite = FWRITE | O_APPEND | O_TRUNC;

bool IsBlockDecision(FileAccessPolicyDecision decision) {
  return decision == FileAccessPolicyDecision::kDenied ||
         decision == FileAccessPolicyDecision::kDeniedInvalidSignature;
}

FileAccessPolicyDecision ApplyOverrideToDecision(FileAccessPolicyDecision decision,
                                                 SNTOverrideFileAccessAction overrideAction) {
  switch (overrideAction) {
    // When no override should be applied, return the decision unmodified
    case SNTOverrideFileAccessActionNone: return decision;

    // When the decision should be overridden to be audit only, only change the
    // decision if it was going to deny the operation.
    case SNTOverrideFileAccessActionAuditOnly:
      if (IsBlockDecision(decision)) {
        return FileAccessPolicyDecision::kAllowedAuditOnly;
      } else {
        return decision;
      }

    // If the override action is to disable policy, return a decision that will
    // be treated as if no policy applied to the operation.
    case SNTOverrideFileAccessActionDiable: return FileAccessPolicyDecision::kNoPolicy;

    default:
      // This is a programming error. Bail.
      [NSException
           raise:@"Invalid SNTOverrideFileAccessAction"
          format:@"Invalid SNTOverrideFileAccessAction: %d", static_cast<int>(overrideAction)];
  }
}

bool ShouldLogDecision(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kDenied: return true;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return true;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return true;
    default: return false;
  }
}

static inline bool ShouldShowUIForPolicy(const std::shared_ptr<WatchItemPolicyBase> &policy) {
  return !policy->silent;
}

static inline bool ShouldMessageTTYForPolicy(const std::shared_ptr<WatchItemPolicyBase> &policy,
                                             const Message &msg) {
  if (policy->silent_tty || !TTYWriter::CanWrite(msg->process)) {
    return false;
  }
  return true;
}

es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kNoPolicy: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kDenied: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return ES_AUTH_RESULT_DENY;
    case FileAccessPolicyDecision::kAllowed: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kAllowedReadAccess: return ES_AUTH_RESULT_ALLOW;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return ES_AUTH_RESULT_ALLOW;
    default:
      // This is a programming error. Bail.
      [NSException raise:@"Invalid FileAccessPolicyDecision"
                  format:@"Invalid FileAccessPolicyDecision: %d", static_cast<int>(decision)];
  }
}

/// Combine two AUTH results such that the most strict policy wins - that is, if
/// either policy denied the operation, the operation is denied
es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2) {
  // If either policy denied the operation, the operation is denied
  return ((result1 == ES_AUTH_RESULT_DENY || result2 == ES_AUTH_RESULT_DENY)
              ? ES_AUTH_RESULT_DENY
              : ES_AUTH_RESULT_ALLOW);
}

FAAPolicyProcessor::FAAPolicyProcessor(
    SNTDecisionCache *decision_cache, std::shared_ptr<Enricher> enricher,
    std::shared_ptr<Logger> logger, std::shared_ptr<TTYWriter> tty_writer,
    std::shared_ptr<Metrics> metrics, uint32_t rate_limit_logs_per_sec,
    uint32_t rate_limit_window_size_sec,
    GenerateEventDetailLinkBlock generate_event_detail_link_block,
    StoreAccessEventBlock store_access_event_block)
    : decision_cache_(decision_cache),
      enricher_(std::move(enricher)),
      logger_(std::move(logger)),
      tty_writer_(std::move(tty_writer)),
      metrics_(std::move(metrics)),
      generate_event_detail_link_block_(generate_event_detail_link_block),
      store_access_event_block_(store_access_event_block),
      reads_cache_(kNumProcesses, kPerProcessSetCapacity),
      tty_message_cache_(kNumProcesses, kPerProcessSetCapacity),
      rate_limiter_(
          RateLimiter::Create(metrics_, rate_limit_logs_per_sec, rate_limit_window_size_sec)) {
  configurator_ = [SNTConfigurator configurator];
  queue_ = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
}

void FAAPolicyProcessor::ModifyRateLimiterSettings(uint32_t logs_per_sec,
                                                   uint32_t window_size_sec) {
  rate_limiter_.ModifySettings(logs_per_sec, window_size_sec);
}

NSString *FAAPolicyProcessor::GetCertificateHash(const es_file_t *es_file) {
  // First see if we've already cached this value
  SantaVnode vnodeID = SantaVnode::VnodeForFile(es_file);
  NSString *result = cert_hash_cache_.get(vnodeID);
  if (result) {
    return result;
  }

  // If this wasn't already cached, try finding a cached SNTCachedDecision
  SNTCachedDecision *cd = [decision_cache_ cachedDecisionForFile:es_file->stat];
  if (cd) {
    // There was an existing cached decision, use its cert hash
    result = cd.certSHA256;
  } else {
    // If the cached decision didn't exist, try a manual lookup
    MOLCodesignChecker *csInfo =
        [[MOLCodesignChecker alloc] initWithBinaryPath:@(es_file->path.data)];
    result = csInfo.leafCertificate.SHA256;
  }
  if (!result.length) {
    // If result is still nil, there isn't much recourse... We will
    // assume that this error isn't transient and set a terminal value
    // in the cache to prevent continuous attempts to lookup cert hash.
    result = kBadCertHash;
  }
  // Finally, add the result to the cache to prevent future lookups
  cert_hash_cache_.set(vnodeID, result);

  return result;
}

/// An `es_process_t` must match all criteria within the given
/// WatchItemProcess to be considered a match.
bool FAAPolicyProcessor::PolicyMatchesProcess(const WatchItemProcess &policy_proc,
                                              const es_process_t *es_proc) {
  // Note: Intentionally not checking `CS_VALID` here - this check must happen
  // outside of this method. This method is used to individually check each
  // configured process exception while the check for a valid code signature
  // is more broad and applies whether or not process exceptions exist.
  if (es_proc->codesigning_flags & CS_SIGNED) {
    // Check whether or not the process is a platform binary if specified by the policy.
    if (policy_proc.platform_binary && !es_proc->is_platform_binary) {
      return false;
    }

    // If the policy contains a team ID, check that the instigating process
    // also has a team ID and matches the policy.
    if (!policy_proc.team_id.empty() &&
        (!es_proc->team_id.data || (policy_proc.team_id != es_proc->team_id.data))) {
      // We expected a team ID to match against, but the process didn't have one.
      return false;
    }

    // SigningID checks
    if (!policy_proc.signing_id.empty()) {
      if (!es_proc->signing_id.data) {
        // Policy has SID set, but process has no SID
        return false;
      }

      if (policy_proc.signing_id_wildcard_pos != std::string::npos) {
        if (!policy_proc.platform_binary && policy_proc.team_id.empty()) {
          // Policy SID is a prefix but neither Platform Binary nor Team ID were set
          // Note: Config parsing should have ensured this isn't possible, but the runtime check
          // here is meant as a fallback.
          return false;
        }

        std::string_view sid_view = std::string_view(policy_proc.signing_id);
        std::string_view prefix = sid_view.substr(0, policy_proc.signing_id_wildcard_pos);
        std::string_view suffix = sid_view.substr(policy_proc.signing_id_wildcard_pos + 1);

        // Skip comparison if the proc SID isn't long enough
        if (es_proc->signing_id.length < (prefix.length() + suffix.length())) {
          return false;
        }

        // Check the proc SID matches the policy SID prefix/suffix parts
        if (strncmp(es_proc->signing_id.data, prefix.data(), prefix.length()) != 0 ||
            strncmp(es_proc->signing_id.data + (es_proc->signing_id.length - suffix.length()),
                    suffix.data(), suffix.length()) != 0) {
          return false;
        }
      } else if (policy_proc.signing_id != es_proc->signing_id.data) {
        // Policy SID didn't match process
        return false;
      }
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

bool FAAPolicyProcessor::PolicyAllowsReadsForTarget(
    const Message &msg, const Message::PathTarget &target,
    const std::shared_ptr<WatchItemPolicyBase> policy) {
  // All special cases currently require the option "allow_read_access" is set
  if (!policy->allow_read_access) {
    return false;
  }

  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN:
      // If the policy is write-only, but the operation isn't a write action, it's allowed
      if (!(msg->event.open.fflag & kOpenFlagsIndicatingWrite)) {
        return true;
      }
      break;

    case ES_EVENT_TYPE_AUTH_CLONE:
      // If policy is write-only, readable targets are allowed (e.g. source file)
      if (target.is_readable) {
        return true;
      }
      break;

    case ES_EVENT_TYPE_AUTH_COPYFILE:
      // Note: Flags for the copyfile event represent the kernel view, not the usersapce
      // copyfile(3) implementation. This means if a `copyfile(3)` flag like `COPYFILE_MOVE`
      // is specified, it will come as a separate `unlink(2)` event, not a flag here.
      if (target.is_readable) {
        return true;
      }
      break;

    default:
      // No other event types have special cases
      break;
  }

  return false;
}

FileAccessPolicyDecision FAAPolicyProcessor::ApplyPolicy(
    const Message &msg, const Message::PathTarget &target,
    const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
    CheckIfPolicyMatchesBlock check_if_policy_matches_block) {
  if (!optional_policy.has_value()) {
    return FileAccessPolicyDecision::kNoPolicy;
  }

  // If the process is signed but has an invalid signature, it is denied
  if (((msg->process->codesigning_flags & (CS_SIGNED | CS_VALID)) == CS_SIGNED) &&
      [configurator_ enableBadSignatureProtection]) {
    // TODO(mlw): Think about how to make stronger guarantees here to handle
    // programs becoming invalid after first being granted access. Maybe we
    // should only allow things that have hardened runtime flags set?
    return FileAccessPolicyDecision::kDeniedInvalidSignature;
  }

  std::shared_ptr<WatchItemPolicyBase> policy = *optional_policy;

  // If the policy allows read access and the target is readable, produce
  // an immediate result.
  // TODO(mlw): It might be beneficial to evaluate the full policy since the
  // kAllowedReadAccess result means that we cannot utilize the ES cache
  // layer. If the policy would generally allow access to the resource,
  // producing the full kAllow result would potentially result in better
  // system performance.
  if (PolicyAllowsReadsForTarget(msg, target, policy)) {
    return FileAccessPolicyDecision::kAllowedReadAccess;
  }

  FileAccessPolicyDecision decision = check_if_policy_matches_block(*policy, target, msg)
                                          ? FileAccessPolicyDecision::kAllowed
                                          : FileAccessPolicyDecision::kDenied;

  // If the RuleType option was configured to contain a list of denied
  // processes or denied paths, the decision should be inverted from allowed
  // to denied or vice versa. Note that this inversion must be made prior to
  // checking the policy's audit-only flag.
  if (policy->rule_type == WatchItemRuleType::kPathsWithDeniedProcesses ||
      policy->rule_type == WatchItemRuleType::kProcessesWithDeniedPaths) {
    if (decision == FileAccessPolicyDecision::kAllowed) {
      decision = FileAccessPolicyDecision::kDenied;
    } else {
      decision = FileAccessPolicyDecision::kAllowed;
    }
  }

  if (decision == FileAccessPolicyDecision::kDenied && policy->audit_only) {
    decision = FileAccessPolicyDecision::kAllowedAuditOnly;
  }

  return decision;
}

void FAAPolicyProcessor::LogTelemetry(const WatchItemPolicyBase &policy, const Message &msg,
                                      size_t target_index, FileAccessPolicyDecision decision) {
  RateLimiter::Decision rate_limit_decision = rate_limiter_.Decide(msg->mach_time);
  metrics_->SetFileAccessEventMetrics(policy.version, policy.name,
                                      (rate_limit_decision == RateLimiter::Decision::kAllowed)
                                          ? FileAccessMetricStatus::kOK
                                          : FileAccessMetricStatus::kBlockedUser,
                                      msg->event_type, decision);

  if (rate_limit_decision != RateLimiter::Decision::kAllowed) {
    return;
  }

  // Ensure copies of necessary components are made before going async so
  // they have proper lifetimes.
  std::string policy_name_copy = policy.name;
  std::string policy_version_copy = policy.version;
  __block Message msg_copy(msg);

  dispatch_async(queue_, ^{
    Message moved_in_msg = std::move(msg_copy);
    const Message::PathTarget &target = moved_in_msg.PathTargetAtIndex(target_index);
    EnrichedProcess enriched_proc =
        enricher_->Enrich(*moved_in_msg->process, EnrichOptions::kLocalOnly);
    std::optional<santa::EnrichedFile> enriched_event_target =
        enricher_->Enrich(target.unsafe_file, EnrichOptions::kLocalOnly);
    logger_->LogFileAccess(policy_version_copy, policy_name_copy, std::move(moved_in_msg),
                           enriched_proc, target_index, std::move(enriched_event_target), decision);
  });
}

bool FAAPolicyProcessor::HaveMessagedTTYForPolicy(const WatchItemPolicyBase &policy,
                                                  const Message &msg) {
  return !tty_message_cache_.Set(PidPidversion(msg->process->audit_token),
                                 {policy.version, policy.name});
}

void FAAPolicyProcessor::LogTTY(SNTStoredFileAccessEvent *event, URLTextPair link_info,
                                const Message &msg, const WatchItemPolicyBase &policy) {
  if (HaveMessagedTTYForPolicy(policy, msg)) {
    return;
  }

  NSAttributedString *attrStr = [SNTBlockMessage
      attributedBlockMessageForFileAccessEvent:event
                                 customMessage:OptionalStringToNSString(policy.custom_message)];

  NSMutableString *blockMsg = [NSMutableString stringWithCapacity:1024];
  // Escape sequences `\033[1m` and `\033[0m` begin/end bold lettering
  [blockMsg appendFormat:@"\n\033[1mSanta\033[0m\n\n%@\n\n", attrStr.string];
  [blockMsg appendFormat:@"\033[1mAccessed Path:\033[0m %@\n"
                         @"\033[1mRule Version: \033[0m %@\n"
                         @"\033[1mRule Name:    \033[0m %@\n"
                         @"\n"
                         @"\033[1mProcess Path: \033[0m %@\n"
                         @"\033[1mIdentifier:   \033[0m %@\n"
                         @"\033[1mParent:       \033[0m %@\n\n",
                         event.accessedPath, event.ruleVersion, event.ruleName,
                         event.process.filePath, event.process.fileSHA256,
                         StringToNSString(msg.ParentProcessName())];

  NSURL *detailURL =
      [SNTBlockMessage eventDetailURLForFileAccessEvent:event
                                         eventDetailURL:link_info.first
                                                            ?: [[SNTConfigurator configurator]
                                                                   fileAccessEventDetailURL]];
  if (detailURL) {
    [blockMsg appendFormat:@"More info:\n%@\n", detailURL.absoluteString];
  }

  tty_writer_->WriteWithoutSignal(msg->process, blockMsg);
}

FileAccessPolicyDecision FAAPolicyProcessor::ProcessTargetAndPolicy(
    const Message &msg, const TargetPolicyPair &target_policy_pair,
    CheckIfPolicyMatchesBlock check_if_policy_matches_block,
    SNTFileAccessDeniedBlock file_access_denied_block,
    SNTOverrideFileAccessAction override_action) {
  const Message::PathTarget &target = msg.PathTargetAtIndex(target_policy_pair.first);
  const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy =
      target_policy_pair.second;
  FileAccessPolicyDecision decision = ApplyOverrideToDecision(
      ApplyPolicy(msg, target, optional_policy, check_if_policy_matches_block), override_action);

  // Note: If ShouldLogDecision, it shouldn't be possible for optionalPolicy
  // to not have a value. Performing the check just in case to prevent a crash.
  if (ShouldLogDecision(decision) && optional_policy.has_value()) {
    std::shared_ptr<WatchItemPolicyBase> policy = *optional_policy;

    LogTelemetry(*policy, msg, target_policy_pair.first, decision);

    SNTCachedDecision *cd = GetCachedDecision(msg->process->executable->stat);
    SNTStoredFileAccessEvent *event = [[SNTStoredFileAccessEvent alloc] init];

    event.accessedPath = StringToNSString(target.path);
    event.ruleVersion = StringToNSString(policy->version);
    event.ruleName = StringToNSString(policy->name);
    event.decision = decision;
    event.process.fileSHA256 = cd.sha256 ?: @"<unknown sha>";
    event.process.filePath = StringToNSString(msg->process->executable->path.data);
    event.process.teamID = cd.teamID ?: @"<unknown team id>";
    event.process.signingID = cd.signingID ?: @"<unknown signing id>";
    event.process.cdhash = cd.cdhash ?: @"<unknown CDHash>";
    event.process.pid = @(audit_token_to_pid(msg->process->audit_token));
    event.process.signingChain = cd.certChain;
    struct passwd *user = getpwuid(audit_token_to_ruid(msg->process->audit_token));
    if (user) event.process.executingUser = @(user->pw_name);
    event.process.parent = [[SNTStoredFileAccessProcess alloc] init];
    event.process.parent.pid = @(audit_token_to_pid(msg->process->parent_audit_token));
    event.process.parent.filePath = StringToNSString(msg.ParentProcessPath());

    URLTextPair link_info;
    if (generate_event_detail_link_block_) {
      link_info = generate_event_detail_link_block_(policy);
    }

    if (store_access_event_block_) {
      store_access_event_block_(event, IsBlockDecision(decision));
    }

    if (IsBlockDecision(decision)) {
      if (ShouldShowUIForPolicy(policy)) {
        file_access_denied_block(event, OptionalStringToNSString(policy->custom_message),
                                 link_info.first, link_info.second);
      }

      if (ShouldMessageTTYForPolicy(policy, msg)) {
        LogTTY(event, link_info, msg, *policy);
      }
    }
  }

  return decision;
}

static inline FAAPolicyProcessor::ReadsCacheKey MakeReadsCacheKey(const audit_token_t &tok,
                                                                  FAAClientType client_type) {
  return {Pid(tok), Pidversion(tok), client_type};
}

FAAPolicyProcessor::ESResult FAAPolicyProcessor::ProcessMessage(
    const Message &msg, std::vector<TargetPolicyPair> target_policy_pairs,
    CheckIfPolicyMatchesBlock check_if_policy_matches_block,
    SNTFileAccessDeniedBlock file_access_denied_block, SNTOverrideFileAccessAction overrideAction,
    FAAClientType client_type) {
  es_auth_result_t policy_result = ES_AUTH_RESULT_ALLOW;
  bool cacheable = true;

  for (const TargetPolicyPair &target_policy_pair : target_policy_pairs) {
    const Message::PathTarget &path_target = msg.PathTargetAtIndex(target_policy_pair.first);
    FileAccessPolicyDecision decision =
        ProcessTargetAndPolicy(msg, target_policy_pair, check_if_policy_matches_block,
                               file_access_denied_block, overrideAction);
    // Populate the reads_cache_ if:
    //   1. The policy applied
    //   2. The process wasn't invalid
    //   3. A devno/ino pair existed for the target
    //   4. The policy allowed read access
    // Note: As long as a policy allows read access, the caller's read cache can be updated
    // regardless of the RuleType of the policy.
    if (decision != FileAccessPolicyDecision::kNoPolicy &&
        decision != FileAccessPolicyDecision::kDeniedInvalidSignature && path_target.is_readable &&
        path_target.unsafe_file && target_policy_pair.second.has_value() &&
        (*target_policy_pair.second)->allow_read_access) {
      reads_cache_.Set(MakeReadsCacheKey(msg->process->audit_token, client_type),
                       std::pair<dev_t, ino_t>({path_target.unsafe_file->stat.st_dev,
                                                path_target.unsafe_file->stat.st_ino}));
    }

    policy_result =
        CombinePolicyResults(policy_result, FileAccessPolicyDecisionToESAuthResult(decision));

    // Only if all decisions are explicitly allowed should a decision be
    // cacheable. If something was denied or audit-only or allowed only
    // because of read access then future executions should also be evaluated
    // so they may also emit additional telemetry.
    if (decision != FileAccessPolicyDecision::kAllowed) {
      cacheable = false;
    }
  }

  return {policy_result, cacheable};
}

std::optional<FAAPolicyProcessor::ESResult> FAAPolicyProcessor::ImmediateResponse(
    const Message &msg, FAAClientType client_type) {
  // Note: Some other events have readable targets, but only events where all
  // targets can be determined to be readable can be considered. E.g., for
  // clone, the destination must still be evaluated so the reads_cache_ is not
  // consulted.
  if (msg->event_type == ES_EVENT_TYPE_AUTH_OPEN &&
      !(msg->event.open.fflag & kOpenFlagsIndicatingWrite) &&
      reads_cache_.Contains(MakeReadsCacheKey(msg->process->audit_token, client_type),
                            std::pair<dev_t, ino_t>{msg->event.open.file->stat.st_dev,
                                                    msg->event.open.file->stat.st_ino})) {
    return std::make_optional<FAAPolicyProcessor::ESResult>({ES_AUTH_RESULT_ALLOW, false});
  }
  return std::nullopt;
}

void FAAPolicyProcessor::NotifyExit(const audit_token_t &tok, FAAClientType client_type) {
  reads_cache_.Remove(MakeReadsCacheKey(tok, client_type));
  tty_message_cache_.Remove(PidPidversion(tok));
}

}  // namespace santa
