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
#include <vector>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileAccessEvent.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
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

class FAAPolicyProcessor {
 public:
  // Small structure to hold a complete event path target being operated upon and
  // a bool indicating whether the path is a readable target (e.g. a file being
  // opened or cloned)
  struct PathTarget {
    std::string path;
    bool is_readable;
    std::optional<std::pair<dev_t, ino_t>> devno_ino;
  };

  using TargetPolicyPair =
      std::pair<PathTarget, std::optional<std::shared_ptr<WatchItemPolicyBase>>>;

  /// Block called when a policy enforcement client can cache actions on
  /// future reads of the given file by the given process.
  using ReadsCacheUpdateBlock = void (^)(const es_process_t *, std::pair<dev_t, ino_t>);
  /// When this block is called, the policy enforcement client must determine
  /// whether or not the given policy applies to the given ES message.
  using CheckIfPolicyMatchesBlock = bool (^)(const WatchItemPolicyBase &, const Message &msg);
  using URLTextPair = std::pair<NSString *, NSString *>;
  /// A block that generates custom URL and Text pairs from a given policy.
  using GenerateEventDetailLinkBlock =
      URLTextPair (^)(const std::shared_ptr<WatchItemPolicyBase> &watch_item);

  // Friend class used for tests
  friend class MockFAAPolicyProcessor;

  FAAPolicyProcessor(SNTDecisionCache *decision_cache, std::shared_ptr<Enricher> enricher,
                     std::shared_ptr<Logger> logger, std::shared_ptr<TTYWriter> tty_writer,
                     GenerateEventDetailLinkBlock generate_event_detail_link_block);

  virtual ~FAAPolicyProcessor() = default;

  virtual bool PolicyMatchesProcess(const WatchItemProcess &policy_proc,
                                    const es_process_t *es_proc);

  virtual SNTCachedDecision *__strong GetCachedDecision(const struct stat &stat_buf);

  es_auth_result_t ProcessMessage(const Message &msg,
                                  std::vector<TargetPolicyPair> target_policy_pairs,
                                  ReadsCacheUpdateBlock reads_cache_update_block,
                                  CheckIfPolicyMatchesBlock check_if_policy_matches_block,
                                  SNTFileAccessDeniedBlock file_access_denied_block,
                                  SNTOverrideFileAccessAction overrideAction);

  // TODO: PathTargets will replace PopulatePathTargets
  static std::vector<FAAPolicyProcessor::PathTarget> PathTargets(const Message &msg);
  static void PopulatePathTargets(const Message &msg, std::vector<PathTarget> &targets);

 private:
  SNTDecisionCache *decision_cache_;
  std::shared_ptr<Enricher> enricher_;
  std::shared_ptr<Logger> logger_;
  std::shared_ptr<TTYWriter> tty_writer_;
  GenerateEventDetailLinkBlock generate_event_detail_link_block_;
  SantaCache<SantaVnode, NSString *> cert_hash_cache_;
  SNTConfigurator *configurator_;
  dispatch_queue_t queue_;

  virtual NSString *__strong GetCertificateHash(const es_file_t *es_file);

  FileAccessPolicyDecision ProcessTargetAndPolicy(
      const Message &msg, const PathTarget &target,
      const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
      CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock,
      SNTFileAccessDeniedBlock file_access_denied_block,
      SNTOverrideFileAccessAction override_action);

  FileAccessPolicyDecision ApplyPolicy(
      const Message &msg, const PathTarget &target,
      const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
      CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock);

  bool PolicyAllowsReadsForTarget(const Message &msg, const PathTarget &target,
                                  std::shared_ptr<WatchItemPolicyBase> policy);

  void LogTelemetry(const WatchItemPolicyBase &policy, const PathTarget &target, const Message &msg,
                    FileAccessPolicyDecision decision);
  void LogTTY(SNTFileAccessEvent *event, URLTextPair link_info, const Message &msg,
              const WatchItemPolicyBase &policy);
};

}  // namespace santa

#pragma clang diagnostic pop

#endif
