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

#ifndef SANTA_SANTAD_EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H
#define SANTA_SANTAD_EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H

#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

#import <Foundation/Foundation.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/stat.h>

#import "Source/common/SNTCachedDecision.h"
#include "Source/common/es/Enricher.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"
#include "Source/santad/Metrics.h"
#import "Source/santad/SNTDecisionCache.h"
#include "Source/santad/TTYWriter.h"

namespace santa {

class MockFAAPolicyProcessor : public FAAPolicyProcessor {
 public:
  MockFAAPolicyProcessor(
      SNTDecisionCache* dc, std::shared_ptr<Enricher> enricher, std::shared_ptr<Logger> logger,
      std::shared_ptr<TTYWriter> tty_writer, std::shared_ptr<Metrics> metrics,
      uint32_t rate_limit_logs_per_sec, uint32_t rate_limit_window_size_sec,
      FAAPolicyProcessor::GenerateEventDetailLinkBlock generate_event_detail_link_block,
      FAAPolicyProcessor::StoreAccessEventBlock store_access_event_block)
      : FAAPolicyProcessor(dc, std::move(enricher), std::move(logger), std::move(tty_writer),
                           std::move(metrics), rate_limit_logs_per_sec, rate_limit_window_size_sec,
                           std::move(generate_event_detail_link_block),
                           std::move(store_access_event_block)) {}
  virtual ~MockFAAPolicyProcessor() {}

  MOCK_METHOD(bool, PolicyMatchesProcess,
              (const WatchItemProcess& policy_proc, const es_process_t* es_proc), (override));
  MOCK_METHOD(SNTCachedDecision*, GetCachedDecision, (const struct stat& stat_buf), (override));
  MOCK_METHOD(NSString*, GetCertificateHash, (const es_file_t* es_file), (override));
  MOCK_METHOD(bool, PolicyAllowsReadsForTarget,
              (const Message& msg, const Message::PathTarget& target, bool allow_read_access),
              (override));
  MOCK_METHOD(FAAPolicyProcessor::DecisionAndOptions, ApplyPolicy,
              (const Message& msg, const Message::PathTarget& target,
               const std::optional<std::shared_ptr<santa::WatchItemPolicyBase>> optional_policy,
               FAAPolicyProcessor::CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock),
              (override));

  /// Routes the mocked policy evaluation methods to the real implementations.
  /// Every process has an empty cached decision.
  void UseRealPolicyEvaluation() {
    EXPECT_CALL(*this, GetCachedDecision)
        .WillRepeatedly(testing::Return([[SNTCachedDecision alloc] init]));
    EXPECT_CALL(*this, PolicyAllowsReadsForTarget)
        .WillRepeatedly(
            [this](const Message& msg, const Message::PathTarget& target, bool allow_read_access) {
              return PolicyAllowsReadsForTargetWrapper(msg, target, allow_read_access);
            });
    EXPECT_CALL(*this, ApplyPolicy)
        .WillRepeatedly(
            [this](const Message& msg, const Message::PathTarget& target,
                   const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
                   FAAPolicyProcessor::CheckIfPolicyMatchesBlock block) {
              return ApplyPolicyWrapper(msg, target, optional_policy, block);
            });
  }

  //
  // Wrappers for calling into private methods
  //
  NSString* GetCertificateHashWrapper(const es_file_t* es_file) {
    return FAAPolicyProcessor::GetCertificateHash(es_file);
  }

  bool PolicyAllowsReadsForTargetWrapper(const Message& msg, const Message::PathTarget& target,
                                         bool allow_read_access) {
    return FAAPolicyProcessor::PolicyAllowsReadsForTarget(msg, target, allow_read_access);
  }

  FAAPolicyProcessor::DecisionAndOptions ApplyPolicyWrapper(
      const Message& msg, const Message::PathTarget& target,
      const std::optional<std::shared_ptr<WatchItemPolicyBase>> optional_policy,
      FAAPolicyProcessor::CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock) {
    return FAAPolicyProcessor::ApplyPolicy(msg, target, optional_policy, checkIfPolicyMatchesBlock);
  }

  FAAPolicyProcessor::DecisionAndOptions ProcessTargetAndPolicyWrapper(
      const Message& msg, const FAAPolicyProcessor::TargetPolicyPair& target_policy_pair,
      FAAPolicyProcessor::CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock,
      SNTFileAccessDeniedBlock fileAccessDeniedBlock, SNTOverrideFileAccessAction overrideAction) {
    FAAPolicyProcessor::TargetUIState ui_state;
    return FAAPolicyProcessor::ProcessTargetAndPolicy(
        msg, target_policy_pair, checkIfPolicyMatchesBlock, fileAccessDeniedBlock, overrideAction,
        ui_state);
  }

  FAAPolicyProcessor::ESResult ProcessMessageWrapper(
      const Message& msg,
      absl::Span<const FAAPolicyProcessor::TargetPolicyPair> target_policy_pairs,
      FAAPolicyProcessor::CheckIfPolicyMatchesBlock checkIfPolicyMatchesBlock,
      SNTFileAccessDeniedBlock fileAccessDeniedBlock) {
    return FAAPolicyProcessor::ProcessMessage(
        msg, target_policy_pairs, checkIfPolicyMatchesBlock, fileAccessDeniedBlock,
        SNTOverrideFileAccessActionNone, FAAClientType::kData);
  }

  std::optional<FAAPolicyProcessor::ESResult> ImmediateResponseWrapper(const Message& msg) {
    return FAAPolicyProcessor::ImmediateResponse(msg, FAAClientType::kData);
  }

  bool HaveMessagedTTYForPolicyWrapper(const WatchItemPolicyBase& policy, const Message& msg) {
    return FAAPolicyProcessor::HaveMessagedTTYForPolicy(policy, msg);
  }
};

}  // namespace santa

#endif  // SANTA_SANTAD_EVENTPROVIDERS_MOCKFAAPOLICYPROCESSOR_H
