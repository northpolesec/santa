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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_FAAPOLICYPROCESSOR_H
#define SANTA__SANTAD__EVENTPROVIDERS_FAAPOLICYPROCESSOR_H

#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <sys/stat.h>

#include <memory>
#include <optional>
#include <tuple>
#include <vector>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaSetCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/EventProviders/RateLimiter.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTDecisionCache.h"
#include "Source/santad/TTYWriter.h"

extern NSString *const kBadCertHash;

// NB: Unfortunately, googletest macros don't play nice with Objective-C types
// and when using macros like MOCK_METHOD, the compiler generates errors about
// "NSString *" and "NSString *__strong" being different types. In order to
// facilitate testing, these unnecessary qualifiers are added in this class
// and we ignore clang complaining about them.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wignored-qualifiers"

namespace santa {

enum class FAAClientType {
  kData,
  kProcess,
};

class FAAPolicyProcessor {
 public:
  struct ESResult {
    es_auth_result_t auth_result;
    bool cacheable;
  };

  using TargetPolicyPair = std::pair<size_t, std::optional<std::shared_ptr<WatchItemPolicyBase>>>;

  /// When this block is called, the policy enforcement client must determine
  /// whether or not the given policy applies to the given ES message.
  using CheckIfPolicyMatchesBlock = bool (^)(const santa::WatchItemPolicyBase &base_policy,
                                             const Message::PathTarget &target, const Message &msg);
  using URLTextPair = std::pair<NSString *, NSString *>;
  /// A block that generates custom URL and Text pairs from a given policy.
  using GenerateEventDetailLinkBlock =
      URLTextPair (^)(const std::shared_ptr<WatchItemPolicyBase> &watch_item);

  using ReadsCacheKey = std::tuple<pid_t, int, FAAClientType>;
  using StoreAccessEventBlock = void (^)(SNTStoredFileAccessEvent *, bool);

  // Friend classes that can call private methods requiring FAAClientType parameters
  friend class DataFAAPolicyProcessorProxy;
  friend class ProcessFAAPolicyProcessorProxy;

  // Friend class used for tests
  friend class MockFAAPolicyProcessor;

  FAAPolicyProcessor(SNTDecisionCache *decision_cache, std::shared_ptr<Enricher> enricher,
                     std::shared_ptr<Logger> logger, std::shared_ptr<TTYWriter> tty_writer,
                     std::shared_ptr<Metrics> metrics, uint32_t rate_limit_logs_per_sec,
                     uint32_t rate_limit_window_size_sec,
                     GenerateEventDetailLinkBlock generate_event_detail_link_block,
                     StoreAccessEventBlock store_access_event_block);

  virtual ~FAAPolicyProcessor() = default;

  virtual bool PolicyMatchesProcess(const WatchItemProcess &policy_proc,
                                    const es_process_t *es_proc);

  virtual SNTCachedDecision *__strong GetCachedDecision(const struct stat &stat_buf);

  virtual void ModifyRateLimiterSettings(uint32_t logs_per_sec, uint32_t window_size_sec);

 private:
  SNTDecisionCache *decision_cache_;
  std::shared_ptr<Enricher> enricher_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<TTYWriter> tty_writer_;
  std::shared_ptr<Metrics> metrics_;
  GenerateEventDetailLinkBlock generate_event_detail_link_block_;
  StoreAccessEventBlock store_access_event_block_;
  santa::SantaSetCache<ReadsCacheKey, std::pair<dev_t, ino_t>> reads_cache_;
  santa::SantaSetCache<std::pair<pid_t, int>, std::pair<std::string, std::string>>
      tty_message_cache_;
  SantaCache<SantaVnode, NSString *> cert_hash_cache_;
  SNTConfigurator *configurator_;
  dispatch_queue_t queue_;
  RateLimiter rate_limiter_;

  virtual NSString *__strong GetCertificateHash(const es_file_t *es_file);

  /// General flow of processing an ES message for FAA violations:
  /// 1. Client presents a vector of pairs of target paths being accessed and associated policies
  /// 2. Iterate each pair and compute a FileAccessPolicyDecision (ProcessTargetAndPolicy())
  ///     1. Compute the FileAccessPolicyDecision (ApplyPolicy())
  ///         1. Ensure a policy exists
  ///         2. Ensure the process is valid or EnableBadSignatureProtection is false
  ///         3. Check if policy allows for reading the target (PolicyAllowsReadsForTarget())
  ///             1. For the current event type, ensure the policy allows reads and the current
  ///                target being evaluated is readable
  ///         4. Check if the policy applies to the current ES message (CheckIfPolicyMatchesBlock())
  ///         5. Invert results and/or set audit-only based on configured options
  ///     2. Apply override if configured
  ///     3. Log telemetry if denied/audit-only and not rate-limited (LogTelemetry())
  ///     4. Notify the user if configured (SNTFileAccessDeniedBlock(), LogTTY())
  /// 3. Combine results of each target into an ES decision
  /// 4. Return the final ES decision
  FAAPolicyProcessor::ESResult ProcessMessage(
      const Message &msg, std::vector<TargetPolicyPair> target_policy_pairs,
      CheckIfPolicyMatchesBlock check_if_policy_matches_block,
      SNTFileAccessDeniedBlock file_access_denied_block, SNTOverrideFileAccessAction overrideAction,
      FAAClientType client_type);

  /// Checks if an immediate result can be returned without full policy evaluation.
  std::optional<FAAPolicyProcessor::ESResult> ImmediateResponse(const Message &msg,
                                                                FAAClientType client_type);

  /// Used by callers to inform when a process has exited and will no longer process events.
  void NotifyExit(const audit_token_t &tok, FAAClientType client_type);

  FileAccessPolicyDecision ProcessTargetAndPolicy(
      const Message &msg, const TargetPolicyPair &target_policy_pair,
      CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock,
      SNTFileAccessDeniedBlock file_access_denied_block,
      SNTOverrideFileAccessAction override_action);

  virtual FileAccessPolicyDecision ApplyPolicy(
      const Message &msg, const Message::PathTarget &target,
      const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
      CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock);

  virtual bool PolicyAllowsReadsForTarget(const Message &msg, const Message::PathTarget &target,
                                          std::shared_ptr<WatchItemPolicyBase> policy);

  /// Return true if the TTY was previously messaged for the given
  /// process/policy pair. Otherwise false.
  bool HaveMessagedTTYForPolicy(const WatchItemPolicyBase &policy, const Message &msg);

  void LogTelemetry(const WatchItemPolicyBase &policy, const Message &msg, size_t target_index,
                    FileAccessPolicyDecision decision);
  void LogTTY(SNTStoredFileAccessEvent *event, URLTextPair link_info, const Message &msg,
              const WatchItemPolicyBase &policy);
};

/// The proxy classes are used to wrap calls into the FAAPolicyProcessor and not expose
/// the FAAClientType to FAAPolicyProcessor users.
class FAAPolicyProcessorProxy {
 public:
  FAAPolicyProcessorProxy(std::shared_ptr<FAAPolicyProcessor> policy_processor)
      : policy_processor_(std::move(policy_processor)) {}

  FAAPolicyProcessor *operator->() { return policy_processor_.get(); }
  FAAPolicyProcessor &operator*() { return *policy_processor_; }

 protected:
  std::shared_ptr<FAAPolicyProcessor> policy_processor_;
};

class ProcessFAAPolicyProcessorProxy : public FAAPolicyProcessorProxy {
 public:
  ProcessFAAPolicyProcessorProxy(std::shared_ptr<FAAPolicyProcessor> policy_processor)
      : FAAPolicyProcessorProxy(std::move(policy_processor)) {}
  FAAPolicyProcessor::ESResult ProcessMessage(
      const Message &msg, std::vector<FAAPolicyProcessor::TargetPolicyPair> target_policy_pairs,
      FAAPolicyProcessor::CheckIfPolicyMatchesBlock check_if_policy_matches_block,
      SNTFileAccessDeniedBlock file_access_denied_block,
      SNTOverrideFileAccessAction overrideAction) {
    return policy_processor_->ProcessMessage(
        msg, std::move(target_policy_pairs), check_if_policy_matches_block,
        file_access_denied_block, overrideAction, FAAClientType::kProcess);
  }

  std::optional<FAAPolicyProcessor::ESResult> ImmediateResponse(const Message &msg) {
    return policy_processor_->ImmediateResponse(msg, FAAClientType::kProcess);
  }

  void NotifyExit(const audit_token_t &tok) {
    return policy_processor_->NotifyExit(tok, FAAClientType::kProcess);
  }
};

class DataFAAPolicyProcessorProxy : public FAAPolicyProcessorProxy {
 public:
  DataFAAPolicyProcessorProxy(std::shared_ptr<FAAPolicyProcessor> policy_processor)
      : FAAPolicyProcessorProxy(std::move(policy_processor)) {}

  FAAPolicyProcessor::ESResult ProcessMessage(
      const Message &msg, std::vector<FAAPolicyProcessor::TargetPolicyPair> target_policy_pairs,
      FAAPolicyProcessor::CheckIfPolicyMatchesBlock check_if_policy_matches_block,
      SNTFileAccessDeniedBlock file_access_denied_block,
      SNTOverrideFileAccessAction overrideAction) {
    return policy_processor_->ProcessMessage(
        msg, std::move(target_policy_pairs), check_if_policy_matches_block,
        file_access_denied_block, overrideAction, FAAClientType::kData);
  }

  std::optional<FAAPolicyProcessor::ESResult> ImmediateResponse(const Message &msg) {
    return policy_processor_->ImmediateResponse(msg, FAAClientType::kData);
  }

  void NotifyExit(const audit_token_t &tok) {
    return policy_processor_->NotifyExit(tok, FAAClientType::kData);
  }
};

}  // namespace santa

#pragma clang diagnostic pop

#endif
