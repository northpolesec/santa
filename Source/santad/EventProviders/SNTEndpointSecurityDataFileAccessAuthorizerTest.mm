/// Copyright 2022 Google LLC
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

#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <cstring>
#include <utility>

#include <array>
#include <cstddef>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

#import "Source/common/SNTConfigurator.h"
#include "Source/common/TestUtils.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDataFileAccessAuthorizer.h"

using santa::FAAPolicyProcessor;
using santa::LookupPoliciesBeneathBlock;
using santa::LookupPolicyBlock;
using santa::Message;
using santa::SetPairPathAndType;
using santa::WatchItemPathType;
using santa::WatchItemPolicyBase;

namespace santa {
extern FAAPolicyProcessor::TargetPolicyPairList TargetPolicyPairs(
    const std::vector<Message::PathTarget>& targets, bool directory_tree_op,
    LookupPolicyBlock lookup_policy_block,
    LookupPoliciesBeneathBlock lookup_policies_beneath_block);
}  // namespace santa

void SetExpectationsForDataFileAccessAuthorizerInit(
    std::shared_ptr<MockEndpointSecurityAPI> mockESApi) {
  EXPECT_CALL(*mockESApi, InvertTargetPathMuting).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));
}

@interface SNTEndpointSecurityDataFileAccessAuthorizer (Testing)
- (void)disable;

@property bool isSubscribed;
@end

@interface SNTEndpointSecurityDataFileAccessAuthorizerTest : XCTestCase
@property id mockConfigurator;
@end

@implementation SNTEndpointSecurityDataFileAccessAuthorizerTest

- (void)setUp {
  [super setUp];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
}

- (void)tearDown {
  [super tearDown];
}

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  EXPECT_CALL(*mockESApi, ClearCache)
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  id fileAccessClient = [[SNTEndpointSecurityDataFileAccessAuthorizer alloc]
      initWithESAPI:mockESApi
            metrics:nullptr
          processor:santa::Processor::kDataFileAccessAuthorizer];

  [fileAccessClient enable];

  for (const auto& event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testDisable {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForDataFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityDataFileAccessAuthorizer* accessClient =
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                                  logger:nullptr
                                                                enricher:nullptr
                                                      faaPolicyProcessor:nil
                                                               ttyWriter:nullptr
                                             findPoliciesForTargetsBlock:nil];

  EXPECT_CALL(*mockESApi, UnsubscribeAll);
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));

  accessClient.isSubscribed = true;
  [accessClient disable];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testTargetPolicyPairs {
  auto watched = std::make_shared<WatchItemPolicyBase>("watched", "v1");
  auto beneath1 = std::make_shared<WatchItemPolicyBase>("beneath1", "v1");
  auto beneath2 = std::make_shared<WatchItemPolicyBase>("beneath2", "v1");
  auto beneathDest = std::make_shared<WatchItemPolicyBase>("beneathDest", "v1");

  std::vector<Message::PathTarget> targets = {
      {.path = std::string_view("/a/dir")},
      {.path = std::string("/b/new")},
  };

  LookupPolicyBlock lookup =
      ^std::optional<std::shared_ptr<WatchItemPolicyBase>>(const char* path) {
    if (std::string_view(path) == "/a/dir") return watched;
    return std::nullopt;
  };
  LookupPoliciesBeneathBlock lookupBeneath =
      ^std::vector<std::shared_ptr<WatchItemPolicyBase>>(std::string_view path) {
    // The policy watching /a/dir also watches a path beneath it
    if (path == "/a/dir") return {beneath1, watched, beneath2};
    if (path == "/b/new") return {beneathDest};
    return {};
  };

  // Flatten to (index, policy name, via ancestor) for exact comparison. "-" is
  // no policy.
  using Pairs = std::vector<std::tuple<size_t, std::string, bool>>;
  auto names = [](const FAAPolicyProcessor::TargetPolicyPairList& pairs) {
    Pairs out;
    for (const FAAPolicyProcessor::TargetPolicyPair& pair : pairs) {
      out.emplace_back(pair.target_index, pair.policy.has_value() ? (*pair.policy)->name : "-",
                       pair.via_ancestor);
    }
    return out;
  };

  // Directory tree operations add the policies beneath every target, less the
  // policy already watching it. Only the added pairs are via an ancestor.
  XCTAssertTrue(names(santa::TargetPolicyPairs(targets, true, lookup, lookupBeneath)) ==
                Pairs({{0, "watched", false},
                       {0, "beneath1", true},
                       {0, "beneath2", true},
                       {1, "-", false},
                       {1, "beneathDest", true}}));

  // Other operations only pair each target with the policy watching it
  XCTAssertTrue(names(santa::TargetPolicyPairs(targets, false, lookup, lookupBeneath)) ==
                Pairs({{0, "watched", false}, {1, "-", false}}));
}

- (void)testWatchItemsCountUnmutesBeforeMuting {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForDataFileAccessAuthorizerInit(mockESApi);

  SNTEndpointSecurityDataFileAccessAuthorizer* accessClient =
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                                  logger:nullptr
                                                                enricher:nullptr
                                                      faaPolicyProcessor:nil
                                                               ttyWriter:nullptr
                                             findPoliciesForTargetsBlock:nil];
  accessClient.isSubscribed = true;

  // "/a" stops being a watched literal and becomes an ancestor, and "/b" does
  // the reverse. Both keep the same ES mute key, so each must be unmuted before
  // it is muted again or the unmute would clear the new mute.
  std::set<es_event_type_t> ancestorEvents = {
      ES_EVENT_TYPE_AUTH_CLONE,
      ES_EVENT_TYPE_AUTH_RENAME,
  };
  testing::Sequence seqA;
  testing::Sequence seqB;
  EXPECT_CALL(*mockESApi,
              UnmuteTargetPath(testing::_, std::string_view("/a"), WatchItemPathType::kLiteral))
      .InSequence(seqA)
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, MuteTargetPathEvents(testing::_, std::string_view("/a"),
                                               WatchItemPathType::kLiteral, ancestorEvents))
      .InSequence(seqA)
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi,
              UnmuteTargetPath(testing::_, std::string_view("/b"), WatchItemPathType::kLiteral))
      .InSequence(seqB)
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi,
              MuteTargetPath(testing::_, std::string_view("/b"), WatchItemPathType::kLiteral))
      .InSequence(seqB)
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, ClearCache).WillOnce(testing::Return(true));

  [accessClient watchItemsCount:2
                       newPaths:SetPairPathAndType({{"/b", WatchItemPathType::kLiteral}})
                   removedPaths:SetPairPathAndType({{"/a", WatchItemPathType::kLiteral}})
               newAncestorPaths:SetPairPathAndType({{"/a", WatchItemPathType::kLiteral}})
           removedAncestorPaths:SetPairPathAndType({{"/b", WatchItemPathType::kLiteral}})];

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

@end
