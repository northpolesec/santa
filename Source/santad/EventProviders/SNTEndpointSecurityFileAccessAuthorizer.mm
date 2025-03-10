/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/santad/EventProviders/SNTEndpointSecurityFileAccessAuthorizer.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>
#include <pwd.h>
#include <sys/fcntl.h>
#include <sys/types.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

#include "Source/common/AuditUtilities.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#include "Source/common/Platform.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#include "Source/common/SNTFileAccessEvent.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTStrengthify.h"
#include "Source/common/SantaSetCache.h"
#include "Source/common/String.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/DataLayer/WatchItems.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/RateLimiter.h"

using santa::DataWatchItemPolicy;
using santa::EndpointSecurityAPI;
using santa::Enricher;
using santa::EnrichOptions;
using santa::EventDisposition;
using santa::FAAPolicyProcessor;
using santa::FileAccessMetricStatus;
using santa::Logger;
using santa::Message;
using santa::Metrics;
using santa::OptionalStringToNSString;
using santa::PidPidversion;
using santa::RateLimiter;
using santa::StringToNSString;
using santa::TTYWriter;
using santa::WatchItemProcess;
using santa::WatchItems;

static constexpr uint32_t kOpenFlagsIndicatingWrite = FWRITE | O_APPEND | O_TRUNC;
static constexpr uint16_t kDefaultRateLimitQPS = 50;
static constexpr size_t kMaxCacheSize = 512;
static constexpr size_t kMaxCacheEntrySize = 8192;

// Helper type alias for tracking process-related information
template <typename ValueT>
using ProcessSetCache = santa::SantaSetCache<std::pair<pid_t, pid_t>, ValueT>;

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
      LOGE(@"Invalid file access decision encountered: %d", static_cast<int>(decision));
      [NSException raise:@"Invalid FileAccessPolicyDecision"
                  format:@"Invalid FileAccessPolicyDecision: %d", static_cast<int>(decision)];
  }
}

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
      LOGE(@"Invalid override file access action encountered: %d",
           static_cast<int>(overrideAction));
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

bool ShouldNotifyUserDecision(FileAccessPolicyDecision decision) {
  return ShouldLogDecision(decision) && decision != FileAccessPolicyDecision::kAllowedAuditOnly;
}

es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2) {
  // If either policy denied the operation, the operation is denied
  return ((result1 == ES_AUTH_RESULT_DENY || result2 == ES_AUTH_RESULT_DENY)
              ? ES_AUTH_RESULT_DENY
              : ES_AUTH_RESULT_ALLOW);
}

bool ShouldMessageTTY(const std::shared_ptr<DataWatchItemPolicy> &policy, const Message &msg,
                      ProcessSetCache<std::pair<std::string, std::string>> *ttyMessageCache) {
  if (policy->silent_tty || !TTYWriter::CanWrite(msg->process)) {
    return false;
  }

  // If `Set` returns `true`, it means this is the first time the item is
  // being added to the cache and we should message the TTY in this case.
  return ttyMessageCache->Set(PidPidversion(msg->process->audit_token),
                              {policy->version, policy->name});
}

@interface SNTEndpointSecurityFileAccessAuthorizer ()
@property SNTConfigurator *configurator;
@property bool isSubscribed;
@end

@implementation SNTEndpointSecurityFileAccessAuthorizer {
  std::shared_ptr<Logger> _logger;
  std::shared_ptr<WatchItems> _watchItems;
  std::shared_ptr<Enricher> _enricher;
  std::shared_ptr<RateLimiter> _rateLimiter;
  std::shared_ptr<TTYWriter> _ttyWriter;
  std::unique_ptr<ProcessSetCache<std::pair<dev_t, ino_t>>> _readsCache;
  std::unique_ptr<ProcessSetCache<std::pair<std::string, std::string>>> _ttyMessageCache;
  std::shared_ptr<Metrics> _metrics;
  std::shared_ptr<santa::FAAPolicyProcessor> _faaPolicyProcessor;
}

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<Metrics>)metrics
                       logger:(std::shared_ptr<santa::Logger>)logger
                   watchItems:(std::shared_ptr<WatchItems>)watchItems
                     enricher:(std::shared_ptr<santa::Enricher>)enricher
           faaPolicyProcessor:(std::shared_ptr<santa::FAAPolicyProcessor>)faaPolicyProcessor
                    ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:metrics
                    processor:santa::Processor::kFileAccessAuthorizer];
  if (self) {
    _watchItems = std::move(watchItems);
    _logger = std::move(logger);
    _enricher = std::move(enricher);
    _faaPolicyProcessor = std::move(faaPolicyProcessor);
    _ttyWriter = std::move(ttyWriter);
    _metrics = std::move(metrics);

    _readsCache =
        ProcessSetCache<std::pair<dev_t, ino_t>>::Create(kMaxCacheSize, kMaxCacheEntrySize);
    _ttyMessageCache = ProcessSetCache<std::pair<std::string, std::string>>::Create(
        kMaxCacheSize, kMaxCacheEntrySize);

    _configurator = [SNTConfigurator configurator];

    _rateLimiter = RateLimiter::Create(_metrics, santa::Processor::kFileAccessAuthorizer,
                                       kDefaultRateLimitQPS);

    SNTMetricBooleanGauge *famEnabled = [[SNTMetricSet sharedInstance]
        booleanGaugeWithName:@"/santa/fam_enabled"
                  fieldNames:@[]
                    helpText:@"Whether or not the FAM client is enabled"];

    WEAKIFY(self);
    [[SNTMetricSet sharedInstance] registerCallback:^{
      STRONGIFY(self);
      [famEnabled set:self.isSubscribed forFieldValues:@[]];
    }];

    [self establishClientOrDie];

    [super enableTargetPathWatching];
  }
  return self;
}

- (NSString *)description {
  return @"FileAccessAuthorizer";
}

- (FileAccessPolicyDecision)specialCaseForPolicy:(std::shared_ptr<DataWatchItemPolicy>)policy
                                          target:(const FAAPolicyProcessor::PathTarget &)target
                                         message:(const Message &)msg {
  switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_OPEN:
      // If the policy is write-only, but the operation isn't a write action, it's allowed
      if (policy->allow_read_access && !(msg->event.open.fflag & kOpenFlagsIndicatingWrite)) {
        return FileAccessPolicyDecision::kAllowedReadAccess;
      }
      break;

    case ES_EVENT_TYPE_AUTH_CLONE:
      // If policy is write-only, readable targets are allowed (e.g. source file)
      if (policy->allow_read_access && target.is_readable) {
        return FileAccessPolicyDecision::kAllowedReadAccess;
      }
      break;

    case ES_EVENT_TYPE_AUTH_COPYFILE:
      // Note: Flags for the copyfile event represent the kernel view, not the usersapce
      // copyfile(3) implementation. This means if a `copyfile(3)` flag like `COPYFILE_MOVE`
      // is specified, it will come as a separate `unlink(2)` event, not a flag here.
      if (policy->allow_read_access && target.is_readable) {
        return FileAccessPolicyDecision::kAllowedReadAccess;
      }
      break;

    case ES_EVENT_TYPE_AUTH_CREATE:
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA:
    case ES_EVENT_TYPE_AUTH_LINK:
    case ES_EVENT_TYPE_AUTH_RENAME:
    case ES_EVENT_TYPE_AUTH_TRUNCATE:
    case ES_EVENT_TYPE_AUTH_UNLINK:
      // These event types have no special case
      break;

    default:
      [NSException raise:@"Unexpected event type"
                  format:@"Received unexpected event type in the file access authorizer: %d",
                         msg->event_type];
      exit(EXIT_FAILURE);
  }

  return FileAccessPolicyDecision::kNoPolicy;
}

// The operation is allowed when:
//   - No policy exists
//   - The policy is write-only, but the operation is read-only
//   - The operation was instigated by an allowed process
//   - If the instigating process is signed, the codesignature is valid
// Otherwise the operation is denied.
- (FileAccessPolicyDecision)applyPolicy:
                                (std::optional<std::shared_ptr<DataWatchItemPolicy>>)optionalPolicy
                              forTarget:(const FAAPolicyProcessor::PathTarget &)target
                              toMessage:(const Message &)msg {
  // If no policy exists, everything is allowed
  if (!optionalPolicy.has_value()) {
    return FileAccessPolicyDecision::kNoPolicy;
  }

  // If the process is signed but has an invalid signature, it is denied
  if (((msg->process->codesigning_flags & (CS_SIGNED | CS_VALID)) == CS_SIGNED) &&
      [self.configurator enableBadSignatureProtection]) {
    // TODO(mlw): Think about how to make stronger guarantees here to handle
    // programs becoming invalid after first being granted access. Maybe we
    // should only allow things that have hardened runtime flags set?
    return FileAccessPolicyDecision::kDeniedInvalidSignature;
  }

  std::shared_ptr<DataWatchItemPolicy> policy = optionalPolicy.value();

  // If policy allows reading, add target to the cache
  if (policy->allow_read_access && target.devno_ino.has_value()) {
    _readsCache->Set(PidPidversion(msg->process->audit_token), *target.devno_ino);
  }

  // Check if this action contains any special case that would produce
  // an immediate result.
  FileAccessPolicyDecision specialCase = [self specialCaseForPolicy:policy
                                                             target:target
                                                            message:msg];
  if (specialCase != FileAccessPolicyDecision::kNoPolicy) {
    return specialCase;
  }

  FileAccessPolicyDecision decision = FileAccessPolicyDecision::kDenied;

  for (const WatchItemProcess &process : policy->processes) {
    if (_faaPolicyProcessor->PolicyMatchesProcess(process, msg->process)) {
      decision = FileAccessPolicyDecision::kAllowed;
      break;
    }
  }

  // If the RuleType option was configured to contain a list of denied processes,
  // the decision should be inverted from allowed to denied or vice versa.
  // Note that this inversion must be made prior to checking the policy's
  // audit-only flag.
  if (policy->rule_type == santa::WatchItemRuleType::kPathsWithDeniedProcesses) {
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

- (FileAccessPolicyDecision)
     handleMessage:(const Message &)msg
            target:(const FAAPolicyProcessor::PathTarget &)target
            policy:(std::optional<std::shared_ptr<DataWatchItemPolicy>>)optionalPolicy
     policyVersion:(const std::string &)policyVersion
    overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  FileAccessPolicyDecision policyDecision = ApplyOverrideToDecision(
      [self applyPolicy:optionalPolicy forTarget:target toMessage:msg], overrideAction);

  // Note: If ShouldLogDecision, it shouldn't be possible for optionalPolicy
  // to not have a value. Performing the check just in case to prevent a crash.
  if (ShouldLogDecision(policyDecision) && optionalPolicy.has_value()) {
    std::shared_ptr<DataWatchItemPolicy> policy = optionalPolicy.value();
    RateLimiter::Decision decision = _rateLimiter->Decide(msg->mach_time);

    self->_metrics->SetFileAccessEventMetrics(policyVersion, policy->name,
                                              (decision == RateLimiter::Decision::kAllowed)
                                                  ? FileAccessMetricStatus::kOK
                                                  : FileAccessMetricStatus::kBlockedUser,
                                              msg->event_type, policyDecision);

    if (decision == RateLimiter::Decision::kAllowed) {
      std::string policyNameCopy = policy->name;
      std::string policyVersionCopy = policyVersion;
      std::string targetPathCopy = target.path;

      [self asynchronouslyProcess:msg
                          handler:^(Message &&esMsg) {
                            self->_logger->LogFileAccess(
                                policyVersionCopy, policyNameCopy, esMsg,
                                self->_enricher->Enrich(*esMsg->process, EnrichOptions::kLocalOnly),
                                targetPathCopy, policyDecision);
                          }];
    }

    // Notify users on block decisions
    if (ShouldNotifyUserDecision(policyDecision) &&
        (!policy->silent || (!policy->silent_tty && TTYWriter::CanWrite(msg->process)))) {
      SNTCachedDecision *cd =
          _faaPolicyProcessor->GetCachedDecision(msg->process->executable->stat);

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

      std::pair<NSString *, NSString *> linkInfo = self->_watchItems->EventDetailLinkInfo(policy);

      if (!policy->silent && self.fileAccessDeniedBlock) {
        self.fileAccessDeniedBlock(event, OptionalStringToNSString(policy->custom_message),
                                   linkInfo.first, linkInfo.second);
      }

      if (ShouldMessageTTY(policy, msg, _ttyMessageCache.get())) {
        NSAttributedString *attrStr =
            [SNTBlockMessage attributedBlockMessageForFileAccessEvent:event
                                                        customMessage:OptionalStringToNSString(
                                                                          policy->custom_message)];

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
                               event.filePath, event.fileSHA256, event.parentName];

        NSURL *detailURL = [SNTBlockMessage eventDetailURLForFileAccessEvent:event
                                                                   customURL:linkInfo.first];
        if (detailURL) {
          [blockMsg appendFormat:@"More info:\n%@\n\n", detailURL.absoluteString];
        }

        self->_ttyWriter->Write(msg->process, blockMsg);
      }
    }
  }

  return policyDecision;
}

- (void)processMessage:(Message)msg overrideAction:(SNTOverrideFileAccessAction)overrideAction {
  std::vector<FAAPolicyProcessor::PathTarget> targets = _faaPolicyProcessor->PathTargets(msg);

  // Extract the paths from the vector of PathTargets in order to lookup policies
  // Note: There should only ever be 1 or 2 items in the vector
  std::vector<std::string_view> paths;
  paths.reserve(2);
  for (const FAAPolicyProcessor::PathTarget &target : targets) {
    paths.push_back(std::string_view(target.path));
  }

  WatchItems::VersionAndPolicies versionAndPolicies = self->_watchItems->FindPolciesForPaths(paths);

  es_auth_result_t policyResult = ES_AUTH_RESULT_ALLOW;
  bool cacheable = true;

  for (size_t i = 0; i < targets.size(); i++) {
    FileAccessPolicyDecision curDecision = [self handleMessage:msg
                                                        target:targets[i]
                                                        policy:versionAndPolicies.second[i]
                                                 policyVersion:versionAndPolicies.first
                                                overrideAction:overrideAction];

    policyResult =
        CombinePolicyResults(policyResult, FileAccessPolicyDecisionToESAuthResult(curDecision));

    // Only if all decisions are explicitly allowed should a decision be
    // cacheable. If something was denied or audit-only or allowed only
    // because of read access then future executions should also be evaluated
    // so they may also emit additional telemetry.
    if (curDecision != FileAccessPolicyDecision::kAllowed) {
      cacheable = false;
    }
  }

  [self respondToMessage:msg withAuthResult:policyResult cacheable:cacheable];
}

- (void)handleMessage:(santa::Message &&)esMsg
    recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  SNTOverrideFileAccessAction overrideAction = [self.configurator overrideFileAccessAction];

  // If the override action is set to Disable, return immediately.
  if (overrideAction == SNTOverrideFileAccessActionDiable) {
    if (esMsg->action_type == ES_ACTION_TYPE_AUTH) {
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
    }
    return;
  }

  if (esMsg->event_type == ES_EVENT_TYPE_AUTH_OPEN &&
      !(esMsg->event.open.fflag & kOpenFlagsIndicatingWrite)) {
    if (_readsCache->Contains(PidPidversion(esMsg->process->audit_token),
                              std::pair<dev_t, ino_t>{esMsg->event.open.file->stat.st_dev,
                                                      esMsg->event.open.file->stat.st_ino})) {
      [self respondToMessage:esMsg withAuthResult:ES_AUTH_RESULT_ALLOW cacheable:false];
      return;
    }
  } else if (esMsg->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
    // On process exit, remove the cache entry
    _readsCache->Remove(PidPidversion(esMsg->process->audit_token));
    _ttyMessageCache->Remove(PidPidversion(esMsg->process->audit_token));
    return;
  }

  [self processMessage:std::move(esMsg)
               handler:^(Message msg) {
                 [self processMessage:std::move(msg) overrideAction:overrideAction];
                 recordEventMetrics(EventDisposition::kProcessed);
               }];
}

- (void)enable {
  std::set<es_event_type_t> events = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  if (!self.isSubscribed) {
    if ([super subscribe:events]) {
      self.isSubscribed = true;
    }
  }

  // Always clear cache to ensure operations that were previously allowed are re-evaluated.
  [super clearCache];
}

- (void)disable {
  if (self.isSubscribed) {
    if ([super unsubscribeAll]) {
      self.isSubscribed = false;
    }
    [super unmuteAllTargetPaths];
  }
}

- (void)watchItemsCount:(size_t)count
               newPaths:(const santa::SetPairPathAndType &)newPaths
           removedPaths:(const santa::SetPairPathAndType &)removedPaths {
  if (count == 0) {
    [self disable];
  } else {
    // Stop watching removed paths
    [super unmuteTargetPaths:removedPaths];

    // Begin watching the added paths
    [super muteTargetPaths:newPaths];

    // begin receiving events (if not already)
    [self enable];
  }

  _readsCache->Clear();
}

@end
