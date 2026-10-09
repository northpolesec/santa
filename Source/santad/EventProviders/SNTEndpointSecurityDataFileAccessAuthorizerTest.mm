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
#include <Kernel/kern/cs_blobs.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <cstring>
#include <utility>

#include <array>
#include <atomic>
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
#include "Source/common/es/ESCacheFlusher.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityDataFileAccessAuthorizer.h"

using santa::AuthResultCache;
using santa::ESCacheClearStrategy;
using santa::ESCacheFlusher;
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

@interface SNTEndpointSecurityAuthorizer (Testing)
- (void)processMessage:(santa::Message)msg;
@end

namespace {

// Counts the ES cache clears made through one client
struct ClearCounter {
  std::atomic<int> count{0};
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  void Record() {
    count++;
    dispatch_semaphore_signal(sema);
  }

  // Waits until at least `expected` clears were made
  bool WaitFor(int expected) {
    while (count.load() < expected) {
      if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) != 0) {
        return false;
      }
    }
    return true;
  }
};

// A real authorizer, Data FAA client, local exec cache, and flusher, each
// client with its own mock API so clears are attributed to the client that
// made them.
//
// `execCached` stands in for the ES EXEC cache: an ALLOW that the authorizer
// marks cacheable is held until the authorizer's ES cache is cleared, and
// while it is held, later executions of the same file from the same instigator
// are not delivered to the authorizer.
struct DataFAAHarness {
  std::shared_ptr<MockEndpointSecurityAPI> authAPI;
  std::shared_ptr<MockEndpointSecurityAPI> dataAPI;
  std::shared_ptr<ESCacheFlusher> flusher;
  std::shared_ptr<AuthResultCache> authResultCache;
  SNTEndpointSecurityAuthorizer* authorizer;
  SNTEndpointSecurityDataFileAccessAuthorizer* dataFAAClient;
  std::shared_ptr<std::atomic<bool>> execCached = std::make_shared<std::atomic<bool>>(false);
  std::shared_ptr<ClearCounter> authClears = std::make_shared<ClearCounter>();
  std::shared_ptr<ClearCounter> dataClears = std::make_shared<ClearCounter>();

  // Delivers AUTH_EXEC through the authorizer unless the modeled ES cache
  // holds the exec. Returns whether the authorizer received it.
  bool DeliverExec(es_message_t* msg) {
    if (execCached->load()) {
      return false;
    }
    [authorizer processMessage:santa::Message(authAPI, msg)];
    return true;
  }

  // Waits for a pass that runs after every request made so far. The client
  // registered here is only cleared by passes requested after it. Under
  // kEveryClient, this pass also clears every other client.
  bool WaitForPendingPasses() {
    auto api = std::make_shared<MockEndpointSecurityAPI>();
    auto barrier = std::make_shared<ClearCounter>();
    EXPECT_CALL(*api, ClearCache).WillRepeatedly([barrier] {
      barrier->Record();
      return true;
    });
    SNTEndpointSecurityClient* client =
        [[SNTEndpointSecurityClient alloc] initWithESAPI:api
                                                 metrics:nullptr
                                               processor:santa::Processor::kUnknown];
    flusher->AddClient(client);
    flusher->Flush(client);
    bool done = barrier->WaitFor(1);
    testing::Mock::VerifyAndClearExpectations(api.get());
    return done;
  }
};

bool AuditTokenEqual(const audit_token_t* a, const audit_token_t& b) {
  return memcmp(a, &b, sizeof(b)) == 0;
}

DataFAAHarness MakeDataFAAHarness(ESCacheClearStrategy strategy) {
  DataFAAHarness h;

  h.authAPI = std::make_shared<MockEndpointSecurityAPI>();
  h.authAPI->SetExpectationsESNewClient();
  h.authAPI->SetExpectationsRetainReleaseMessage();
  h.dataAPI = std::make_shared<MockEndpointSecurityAPI>();
  h.dataAPI->SetExpectationsESNewClient();
  h.dataAPI->SetExpectationsRetainReleaseMessage();
  SetExpectationsForDataFileAccessAuthorizerInit(h.dataAPI);

  auto execCached = h.execCached;
  EXPECT_CALL(*h.authAPI, RespondAuthResult)
      .WillRepeatedly([execCached](const santa::Client&, const santa::Message&,
                                   es_auth_result_t result, bool cacheable) {
        if (result == ES_AUTH_RESULT_ALLOW && cacheable) {
          execCached->store(true);
        }
        return true;
      });
  auto authClears = h.authClears;
  EXPECT_CALL(*h.authAPI, ClearCache).WillRepeatedly([execCached, authClears] {
    execCached->store(false);
    authClears->Record();
    return true;
  });
  auto dataClears = h.dataClears;
  EXPECT_CALL(*h.dataAPI, ClearCache).WillRepeatedly([dataClears] {
    dataClears->Record();
    return true;
  });
  EXPECT_CALL(*h.dataAPI, MuteTargetPath).WillRepeatedly(testing::Return(true));

  h.flusher = std::make_shared<ESCacheFlusher>(strategy);
  h.authResultCache = AuthResultCache::Create(h.flusher, nil);
  h.authorizer = [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:h.authAPI
                                                              metrics:nullptr
                                                       execController:nil
                                                   compilerController:nil
                                                      authResultCache:h.authResultCache
                                                            ttyWriter:nullptr
                                                          processTree:nullptr];
  h.dataFAAClient = [[SNTEndpointSecurityDataFileAccessAuthorizer alloc] initWithESAPI:h.dataAPI
                                                                               metrics:nullptr
                                                                                logger:nullptr
                                                                              enricher:nullptr
                                                                    faaPolicyProcessor:nil
                                                                             ttyWriter:nullptr
                                                           findPoliciesForTargetsBlock:nil
                                                                        esCacheFlusher:h.flusher];

  [h.authorizer registerAuthExecProbe:h.dataFAAClient];
  h.flusher->AddClient(h.authorizer);
  h.flusher->AddClient(h.dataFAAClient);

  return h;
}

void ActivateDataFAA(DataFAAHarness& h) {
  [h.dataFAAClient watchItemsCount:1
      newPaths:SetPairPathAndType({{"/protected", WatchItemPathType::kLiteral}})
      removedPaths:{}
      newAncestorPaths:{}
      removedAncestorPaths:{}];
}

}  // namespace

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
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForDataFileAccessAuthorizerInit(mockESApi);

  // Enabling requests invalidation through the flusher, which clears this
  // client's ES cache after subscribing.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mockESApi, ClearCache)
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce([sema] {
        dispatch_semaphore_signal(sema);
        return true;
      });

  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  SNTEndpointSecurityDataFileAccessAuthorizer* fileAccessClient =
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                                  logger:nullptr
                                                                enricher:nullptr
                                                      faaPolicyProcessor:nil
                                                               ttyWriter:nullptr
                                             findPoliciesForTargetsBlock:nil
                                                          esCacheFlusher:flusher];
  flusher->AddClient(fileAccessClient);

  [fileAccessClient enable];
  XCTAssertSemaTrue(sema, 5, "ES cache was not cleared");

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
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc]
                        initWithESAPI:mockESApi
                              metrics:nullptr
                               logger:nullptr
                             enricher:nullptr
                   faaPolicyProcessor:nil
                            ttyWriter:nullptr
          findPoliciesForTargetsBlock:nil
                       esCacheFlusher:std::make_shared<ESCacheFlusher>(
                                          ESCacheClearStrategy::kSingleClient)];

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

  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  SNTEndpointSecurityDataFileAccessAuthorizer* accessClient =
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                                  logger:nullptr
                                                                enricher:nullptr
                                                      faaPolicyProcessor:nil
                                                               ttyWriter:nullptr
                                             findPoliciesForTargetsBlock:nil
                                                          esCacheFlusher:flusher];
  flusher->AddClient(accessClient);
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
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  EXPECT_CALL(*mockESApi, ClearCache).WillOnce([sema] {
    dispatch_semaphore_signal(sema);
    return true;
  });

  [accessClient watchItemsCount:2
                       newPaths:SetPairPathAndType({{"/b", WatchItemPathType::kLiteral}})
                   removedPaths:SetPairPathAndType({{"/a", WatchItemPathType::kLiteral}})
               newAncestorPaths:SetPairPathAndType({{"/a", WatchItemPathType::kLiteral}})
           removedAncestorPaths:SetPairPathAndType({{"/b", WatchItemPathType::kLiteral}})];
  XCTAssertSemaTrue(sema, 5, "ES cache was not cleared");

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

/// Path muting is complete before invalidation is requested, so no operation
/// is evaluated against the previous set of watched paths once caches are
/// invalidated.
- (void)testWatchItemsCountUpdatesStateBeforeRequestingInvalidation {
  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  SetExpectationsForDataFileAccessAuthorizerInit(mockESApi);

  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  SNTEndpointSecurityDataFileAccessAuthorizer* accessClient =
      [[SNTEndpointSecurityDataFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                 metrics:nullptr
                                                                  logger:nullptr
                                                                enricher:nullptr
                                                      faaPolicyProcessor:nil
                                                               ttyWriter:nullptr
                                             findPoliciesForTargetsBlock:nil
                                                          esCacheFlusher:flusher];
  accessClient.isSubscribed = true;

  auto sentinelAPI = std::make_shared<MockEndpointSecurityAPI>();
  SNTEndpointSecurityClient* sentinel =
      [[SNTEndpointSecurityClient alloc] initWithESAPI:sentinelAPI
                                               metrics:nullptr
                                             processor:santa::Processor::kUnknown];
  dispatch_semaphore_t sentinelSema = dispatch_semaphore_create(0);
  EXPECT_CALL(*sentinelAPI, ClearCache).WillOnce([sentinelSema] {
    dispatch_semaphore_signal(sentinelSema);
    return true;
  });

  flusher->AddClient(accessClient);
  flusher->AddClient(sentinel);

  EXPECT_CALL(*mockESApi, UnmuteTargetPath).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, MuteTargetPath).WillOnce(testing::Return(true));

  // The last muting call. The flusher queue is serial, so waiting here for a
  // newly requested pass first runs any invalidation already requested.
  auto mutingDone = std::make_shared<std::atomic<bool>>(false);
  __weak SNTEndpointSecurityClient* weakSentinel = sentinel;
  EXPECT_CALL(*mockESApi, MuteTargetPathEvents)
      .WillOnce([flusher, weakSentinel, sentinelSema, mutingDone] {
        flusher->Flush(weakSentinel);
        dispatch_semaphore_wait(sentinelSema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        mutingDone->store(true);
        return true;
      });

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto clearedAfterMuting = std::make_shared<std::atomic<bool>>(false);
  EXPECT_CALL(*mockESApi, ClearCache).WillOnce([sema, mutingDone, clearedAfterMuting] {
    clearedAfterMuting->store(mutingDone->load());
    dispatch_semaphore_signal(sema);
    return true;
  });

  [accessClient watchItemsCount:1
                       newPaths:SetPairPathAndType({{"/b", WatchItemPathType::kLiteral}})
                   removedPaths:SetPairPathAndType({{"/a", WatchItemPathType::kLiteral}})
               newAncestorPaths:SetPairPathAndType({{"/c", WatchItemPathType::kLiteral}})
           removedAncestorPaths:SetPairPathAndType()];

  XCTAssertSemaTrue(sema, 5, "ES cache was not cleared");
  XCTAssertTrue(clearedAfterMuting->load());

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(sentinelAPI.get());
}

/// Warms a cacheable EXEC ALLOW of the bundle service while Data FAA is
/// disabled, activates Data FAA, and checks that a later execution reaches the
/// probe that exempts the bundle service.
- (void)assertBundleServiceProbeRunsAfterActivation:(DataFAAHarness&)h {
  es_file_t instigatorFile = MakeESFile("foo");
  es_process_t instigator = MakeESProcess(&instigatorFile);
  es_file_t execFile = MakeESFile("santabundleservice");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  execProc.codesigning_flags = CS_SIGNED | CS_VALID;
  execProc.team_id = MakeESStringToken("ZMCG7MLDV9");
  execProc.signing_id = MakeESStringToken("com.northpolesec.santa.bundleservice");
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &instigator);
  esMsg.event.exec.target = &execProc;

  // Warm the local and modeled ES caches while Data FAA is disabled
  santa::ExecTarget target = santa::ExecTarget::ForExecEvent(&esMsg);
  h.authResultCache->AddToCache(target, SNTActionRequestBinary);
  h.authResultCache->AddToCache(target, SNTActionRespondAllow);
  XCTAssertTrue(h.DeliverExec(&esMsg));
  XCTAssertTrue(h.execCached->load());
  // The cached exec is not delivered again
  execProc.audit_token = MakeAuditToken(12, 24);
  XCTAssertFalse(h.DeliverExec(&esMsg));

  int authClearsBefore = h.authClears->count.load();
  int dataClearsBefore = h.dataClears->count.load();

  ActivateDataFAA(h);

  // Both clients are cleared by the central pass. The authorizer is cleared
  // first, so it is done once the FAA client is.
  XCTAssertTrue(h.dataClears->WaitFor(dataClearsBefore + 1));
  XCTAssertEqual(h.authClears->count.load(), authClearsBefore + 1);

  // The FAA update keeps the local exec cache entry
  XCTAssertEqual(h.authResultCache->CheckCache(target).action, SNTActionRespondAllow);

  // The next execution reaches the authorizer, and on a local cache hit the
  // probe mutes the bundle service from Data FAA enforcement.
  audit_token_t newToken = MakeAuditToken(12, 25);
  execProc.audit_token = newToken;
  EXPECT_CALL(*h.dataAPI,
              MuteProcess(testing::_, testing::Truly([newToken](const audit_token_t* t) {
                            return AuditTokenEqual(t, newToken);
                          })))
      .WillOnce(testing::Return(true));
  XCTAssertTrue(h.DeliverExec(&esMsg));
  XCTAssertFalse(h.execCached->load());

  // The same executable without the bundle service's signing identity is not
  // exempted.
  execProc.audit_token = MakeAuditToken(12, 26);
  execProc.team_id = MakeESStringToken("ABCDEFGHIJ");
  XCTAssertTrue(h.DeliverExec(&esMsg));
  XCTAssertTrue(h.execCached->load());

  XCTBubbleMockVerifyAndClearExpectations(h.dataAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(h.authAPI.get());
}

- (void)testActivationInvalidatesCachedExecForBundleServiceProbe {
  DataFAAHarness h = MakeDataFAAHarness(ESCacheClearStrategy::kEveryClient);
  [self assertBundleServiceProbeRunsAfterActivation:h];
}

- (void)testReenableInvalidatesCachedExecForBundleServiceProbe {
  DataFAAHarness h = MakeDataFAAHarness(ESCacheClearStrategy::kEveryClient);
  h.dataFAAClient.isSubscribed = true;

  // Disabling requests no central invalidation, so the only clears are from
  // the pass that waits for pending requests.
  EXPECT_CALL(*h.dataAPI, UnsubscribeAll).WillOnce(testing::Return(true));
  EXPECT_CALL(*h.dataAPI, UnmuteAllTargetPaths).WillOnce(testing::Return(true));
  [h.dataFAAClient watchItemsCount:0
                          newPaths:{}
                      removedPaths:{}
                  newAncestorPaths:{}
              removedAncestorPaths:{}];
  XCTAssertTrue(h.WaitForPendingPasses());
  XCTAssertEqual(h.authClears->count.load(), 1);
  XCTAssertEqual(h.dataClears->count.load(), 1);

  [self assertBundleServiceProbeRunsAfterActivation:h];
}

- (void)testSingleClientFAAUpdateClearsOnlyTheFAAClient {
  DataFAAHarness h = MakeDataFAAHarness(ESCacheClearStrategy::kSingleClient);

  ActivateDataFAA(h);
  XCTAssertTrue(h.dataClears->WaitFor(1));
  XCTAssertTrue(h.WaitForPendingPasses());

  XCTAssertEqual(h.authClears->count.load(), 0);
  XCTAssertEqual(h.dataClears->count.load(), 1);

  XCTBubbleMockVerifyAndClearExpectations(h.dataAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(h.authAPI.get());
}

@end
