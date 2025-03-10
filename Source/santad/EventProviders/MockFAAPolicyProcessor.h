/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA__SANTAD__EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H
#define SANTA__SANTAD__EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H

#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

#import <Foundation/Foundation.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#import "Source/common/SNTCachedDecision.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Enricher.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/SNTDecisionCache.h"
#include "Source/santad/TTYWriter.h"

namespace santa {

class MockFAAPolicyProcessor : public FAAPolicyProcessor {
 public:
  MockFAAPolicyProcessor(
      SNTDecisionCache *dc, std::shared_ptr<Enricher> enricher, std::shared_ptr<Logger> logger,
      std::shared_ptr<TTYWriter> tty_writer,
      FAAPolicyProcessor::GenerateEventDetailLinkBlock generate_event_detail_link_block)
      : FAAPolicyProcessor(dc, std::move(enricher), std::move(logger), std::move(tty_writer),
                           std::move(generate_event_detail_link_block)) {}
  virtual ~MockFAAPolicyProcessor() {}

  MOCK_METHOD(bool, PolicyMatchesProcess,
              (const WatchItemProcess &policy_proc, const es_process_t *es_proc), (override));
  MOCK_METHOD(SNTCachedDecision *, GetCachedDecision, (const struct stat &stat_buf), (override));
  MOCK_METHOD(NSString *, GetCertificateHash, (const es_file_t *es_file), (override));
  MOCK_METHOD(bool, PolicyAllowsReadsForTarget,
              (const Message &msg, const FAAPolicyProcessor::PathTarget &target,
               std::shared_ptr<WatchItemPolicyBase> policy),
              (override));
  MOCK_METHOD(FileAccessPolicyDecision, ApplyPolicy,
              (const Message &msg, const FAAPolicyProcessor::PathTarget &target,
               const std::optional<std::shared_ptr<santa::WatchItemPolicyBase>> optional_policy,
               FAAPolicyProcessor::CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock),
              (override));

  //
  // Wrappers for calling into private methods
  //
  NSString *GetCertificateHashWrapper(const es_file_t *es_file) {
    return FAAPolicyProcessor::GetCertificateHash(es_file);
  }

  bool PolicyAllowsReadsForTargetWrapper(const Message &msg,
                                         const FAAPolicyProcessor::PathTarget &target,
                                         std::shared_ptr<WatchItemPolicyBase> policy) {
    return FAAPolicyProcessor::PolicyAllowsReadsForTarget(msg, target, policy);
  }

  FileAccessPolicyDecision ApplyPolicyWrapper(
      const Message &msg, const FAAPolicyProcessor::PathTarget &target,
      const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
      FAAPolicyProcessor::CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock) {
    return FAAPolicyProcessor::ApplyPolicy(msg, target, optional_policy, checkIfPolicyMatchesBlock);
  }
};

}  // namespace santa

#endif
