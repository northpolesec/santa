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
#include "Source/common/String.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"

// Terminal value that will never match a valid cert hash.
NSString *const kBadCertHash = @"BAD_CERT_HASH";

namespace santa {

constexpr uint32_t kOpenFlagsIndicatingWrite = FWRITE | O_APPEND | O_TRUNC;

static inline std::string Path(const es_file_t *esFile) {
  return std::string(esFile->path.data, esFile->path.length);
}

static inline std::string Path(const es_string_token_t &tok) {
  return std::string(tok.data, tok.length);
}

static inline void PushBackIfNotTruncated(std::vector<FAAPolicyProcessor::PathTarget> &vec,
                                          const es_file_t *esFile, bool isReadable = false) {
  if (!esFile->path_truncated) {
    vec.push_back({Path(esFile), isReadable,
                   isReadable ? std::make_optional<std::pair<dev_t, ino_t>>(
                                    {esFile->stat.st_dev, esFile->stat.st_ino})
                              : std::nullopt});
  }
}

// Note: This variant of PushBackIfNotTruncated can never be marked "is_readable"
static inline void PushBackIfNotTruncated(std::vector<FAAPolicyProcessor::PathTarget> &vec,
                                          const es_file_t *dir, const es_string_token_t &name) {
  if (!dir->path_truncated) {
    vec.push_back({Path(dir) + "/" + Path(name), false, std::nullopt});
  }
}

inline bool IsBlockDecision(FileAccessPolicyDecision decision) {
  return decision == FileAccessPolicyDecision::kDenied ||
         decision == FileAccessPolicyDecision::kDeniedInvalidSignature;
}

inline FileAccessPolicyDecision ApplyOverrideToDecision(
    FileAccessPolicyDecision decision, SNTOverrideFileAccessAction overrideAction) {
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

inline bool ShouldLogDecision(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kDenied: return true;
    case FileAccessPolicyDecision::kDeniedInvalidSignature: return true;
    case FileAccessPolicyDecision::kAllowedAuditOnly: return true;
    default: return false;
  }
}

/// The user should be notified whenever the policy will be logged (as long as it's not audit only)
inline bool ShouldNotifyUserDecision(FileAccessPolicyDecision decision) {
  return IsBlockDecision(decision);
}

static bool ShouldShowUI(const std::shared_ptr<WatchItemPolicyBase> &policy) {
  return !policy->silent;
}

static bool ShouldMessageTTY(const std::shared_ptr<WatchItemPolicyBase> &policy,
                             const Message &msg) {
  if (policy->silent_tty || !TTYWriter::CanWrite(msg->process)) {
    return false;
  }
  return true;
}

inline es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision) {
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
inline es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2) {
  // If either policy denied the operation, the operation is denied
  return ((result1 == ES_AUTH_RESULT_DENY || result2 == ES_AUTH_RESULT_DENY)
              ? ES_AUTH_RESULT_DENY
              : ES_AUTH_RESULT_ALLOW);
}

FAAPolicyProcessor::FAAPolicyProcessor(
    SNTDecisionCache *decision_cache, std::shared_ptr<Enricher> enricher,
    std::shared_ptr<Logger> logger, std::shared_ptr<TTYWriter> tty_writer,
    GenerateEventDetailLinkBlock generate_event_detail_link_block)
    : decision_cache_(decision_cache),
      enricher_(std::move(enricher)),
      logger_(std::move(logger)),
      tty_writer_(std::move(tty_writer)),
      generate_event_detail_link_block_(generate_event_detail_link_block),
      reads_cache_(1024, 8192) {
  configurator_ = [SNTConfigurator configurator];
  queue_ = dispatch_get_global_queue(QOS_CLASS_UTILITY, 0);
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

bool FAAPolicyProcessor::PolicyAllowsReadsForTarget(
    const Message &msg, const PathTarget &target,
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
    const Message &msg, const PathTarget &target,
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

void FAAPolicyProcessor::LogTelemetry(const WatchItemPolicyBase &policy, const PathTarget &target,
                                      const Message &msg, FileAccessPolicyDecision decision) {
  // Ensure copies of necessary components are made before going async so
  // they have proper lifetimes.
  std::string policy_name_copy = policy.name;
  std::string policy_version_copy = policy.version;
  std::string target_path_copy = target.path;
  __block Message msg_copy(msg);

  dispatch_async(queue_, ^{
    EnrichedProcess enriched_proc = enricher_->Enrich(*msg_copy->process);
    logger_->LogFileAccess(policy_version_copy, policy_name_copy, std::move(msg_copy),
                           std::move(enriched_proc), target_path_copy, decision);
  });
}

void FAAPolicyProcessor::LogTTY(SNTFileAccessEvent *event, URLTextPair link_info,
                                const Message &msg, const WatchItemPolicyBase &policy) {
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
                         event.accessedPath, event.ruleVersion, event.ruleName, event.filePath,
                         event.fileSHA256, event.parentName];

  NSURL *detailURL = [SNTBlockMessage eventDetailURLForFileAccessEvent:event
                                                             customURL:link_info.first];
  if (detailURL) {
    [blockMsg appendFormat:@"More info:\n%@\n\n", detailURL.absoluteString];
  }

  tty_writer_->Write(msg->process, blockMsg);
}

FileAccessPolicyDecision FAAPolicyProcessor::ProcessTargetAndPolicy(
    const Message &msg, const PathTarget &target,
    const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
    CheckIfPolicyMatchesBlock check_if_policy_matches_block,
    SNTFileAccessDeniedBlock file_access_denied_block,
    SNTOverrideFileAccessAction override_action) {
  FileAccessPolicyDecision decision = ApplyOverrideToDecision(
      ApplyPolicy(msg, target, optional_policy, check_if_policy_matches_block), override_action);

  // Note: If ShouldLogDecision, it shouldn't be possible for optionalPolicy
  // to not have a value. Performing the check just in case to prevent a crash.
  if (ShouldLogDecision(decision) && optional_policy.has_value()) {
    std::shared_ptr<WatchItemPolicyBase> policy = *optional_policy;

    // TODO: Rate limiting
    LogTelemetry(*policy, target, msg, decision);

    if (ShouldNotifyUserDecision(decision) &&
        (ShouldShowUI(policy) || ShouldMessageTTY(policy, msg))) {
      SNTCachedDecision *cd = GetCachedDecision(msg->process->executable->stat);
      SNTFileAccessEvent *event = [[SNTFileAccessEvent alloc] init];

      event.accessedPath = StringToNSString(target.path);
      event.ruleVersion = StringToNSString(policy->version);
      event.ruleName = StringToNSString(policy->name);
      event.fileSHA256 = cd.sha256 ?: @"<unknown sha>";
      event.filePath = StringToNSString(msg->process->executable->path.data);
      event.teamID = cd.teamID ?: @"<unknown team id>";
      event.signingID = cd.signingID ?: @"<unknown signing id>";
      event.cdhash = cd.cdhash ?: @"<unknown CDHash>";
      event.pid = @(audit_token_to_pid(msg->process->audit_token));
      event.ppid = @(audit_token_to_pid(msg->process->parent_audit_token));
      event.parentName = StringToNSString(msg.ParentProcessName());
      event.signingChain = cd.certChain;

      struct passwd *user = getpwuid(audit_token_to_ruid(msg->process->audit_token));
      if (user) event.executingUser = @(user->pw_name);

      URLTextPair link_info;
      if (generate_event_detail_link_block_) {
        link_info = generate_event_detail_link_block_(policy);
      }

      if (ShouldShowUI(policy)) {
        file_access_denied_block(event, OptionalStringToNSString(policy->custom_message),
                                 link_info.first, link_info.second);
      }

      // TODO: TTY message cache
      if (ShouldMessageTTY(policy, msg)) {
        LogTTY(event, link_info, msg, *policy);
      }
    }
  }

  return decision;
}

static inline FAAPolicyProcessor::ReadsCacheKey MakeReadsCacheKey(const Message &msg,
                                                                  FAAClientType client_type) {
  return {Pid(msg->process->audit_token), Pidversion(msg->process->audit_token), client_type};
}

FAAPolicyProcessor::ESResult FAAPolicyProcessor::ProcessMessage(
    const Message &msg, std::vector<TargetPolicyPair> target_policy_pairs,
    ReadsCacheUpdateBlock reads_cache_update_block,
    CheckIfPolicyMatchesBlock check_if_policy_matches_block,
    SNTFileAccessDeniedBlock file_access_denied_block, SNTOverrideFileAccessAction overrideAction,
    FAAClientType client_type) {
  es_auth_result_t policy_result = ES_AUTH_RESULT_ALLOW;
  bool cacheable = true;

  for (const TargetPolicyPair &target_policy_pair : target_policy_pairs) {
    FileAccessPolicyDecision decision = ProcessTargetAndPolicy(
        msg, target_policy_pair.first, target_policy_pair.second, check_if_policy_matches_block,
        file_access_denied_block, overrideAction);
    // Trigger the caller's ReadsCacheUpdateBlock if:
    //   1. The policy applied
    //   2. The process wasn't invalid
    //   3. A devno/ino pair existed for the target
    //   4. The policy allowed read access
    // Note: As long as a policy allows read access, the caller's read cache can be updated
    // regardless of the RuleType of the policy.
    if (decision != FileAccessPolicyDecision::kNoPolicy &&
        decision != FileAccessPolicyDecision::kDeniedInvalidSignature &&
        target_policy_pair.first.devno_ino.has_value() && target_policy_pair.second.has_value() &&
        (*target_policy_pair.second)->allow_read_access) {
      reads_cache_.Set(MakeReadsCacheKey(msg, client_type), *target_policy_pair.first.devno_ino);
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
      reads_cache_.Contains(MakeReadsCacheKey(msg, client_type),
                            std::pair<dev_t, ino_t>{msg->event.open.file->stat.st_dev,
                                                    msg->event.open.file->stat.st_ino})) {
    return std::make_optional<FAAPolicyProcessor::ESResult>({ES_AUTH_RESULT_ALLOW, false});
  }
  return std::nullopt;
}

void FAAPolicyProcessor::NotifyExit(const Message &msg, FAAClientType client_type) {
  reads_cache_.Remove(MakeReadsCacheKey(msg, client_type));
}

std::vector<FAAPolicyProcessor::PathTarget> FAAPolicyProcessor::PathTargets(const Message &msg) {
  std::vector<FAAPolicyProcessor::PathTarget> targets;
  targets.reserve(2);

  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE:
      PushBackIfNotTruncated(targets, msg->event.clone.source, true);
      PushBackIfNotTruncated(targets, msg->event.clone.target_dir, msg->event.clone.target_name);
      break;

    case ES_EVENT_TYPE_AUTH_CREATE:
      // AUTH CREATE events should always be ES_DESTINATION_TYPE_NEW_PATH
      if (msg->event.create.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackIfNotTruncated(targets, msg->event.create.destination.new_path.dir,
                               msg->event.create.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for create event: %d. Ignoring target.",
             msg->event.create.destination_type);
      }
      break;

    case ES_EVENT_TYPE_AUTH_COPYFILE:
      PushBackIfNotTruncated(targets, msg->event.copyfile.source, true);
      if (msg->event.copyfile.target_file) {
        PushBackIfNotTruncated(targets, msg->event.copyfile.target_file);
      } else {
        PushBackIfNotTruncated(targets, msg->event.copyfile.target_dir,
                               msg->event.copyfile.target_name);
      }
      break;

    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
      PushBackIfNotTruncated(targets, msg->event.exchangedata.file1);
      PushBackIfNotTruncated(targets, msg->event.exchangedata.file2);
      break;

    case ES_EVENT_TYPE_AUTH_LINK:
      PushBackIfNotTruncated(targets, msg->event.link.source);
      PushBackIfNotTruncated(targets, msg->event.link.target_dir, msg->event.link.target_filename);
      break;

    case ES_EVENT_TYPE_AUTH_OPEN:
      PushBackIfNotTruncated(targets, msg->event.open.file, true);
      break;

    case ES_EVENT_TYPE_AUTH_RENAME:
      PushBackIfNotTruncated(targets, msg->event.rename.source);
      if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        PushBackIfNotTruncated(targets, msg->event.rename.destination.existing_file);
      } else if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_NEW_PATH) {
        PushBackIfNotTruncated(targets, msg->event.rename.destination.new_path.dir,
                               msg->event.rename.destination.new_path.filename);
      } else {
        LOGW(@"Unexpected destination type for rename event: %d. Ignoring destination.",
             msg->event.rename.destination_type);
      }
      break;

    case ES_EVENT_TYPE_AUTH_TRUNCATE:
      PushBackIfNotTruncated(targets, msg->event.truncate.target);
      break;

    case ES_EVENT_TYPE_AUTH_UNLINK:
      PushBackIfNotTruncated(targets, msg->event.unlink.target);
      break;

    default:
      [NSException
           raise:@"Unexpected event type"
          format:@"File Access Authorizer client does not handle event: %d", msg->event_type];
      exit(EXIT_FAILURE);
  }

  return targets;
}

}  // namespace santa
