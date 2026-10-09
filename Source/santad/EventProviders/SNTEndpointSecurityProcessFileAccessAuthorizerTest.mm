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

#import "Source/common/es/SNTEndpointSecurityEventHandler.h"
#include "Source/santad/EventProviders/FAAPolicyProcessor.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityProcessFileAccessAuthorizer.h"

#include <EndpointSecurity/EndpointSecurity.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <bsm/libbsm.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <set>
#include <vector>

#import "Source/common/SNTConfigurator.h"

#include "Source/common/TestUtils.h"
#include "Source/common/es/ESCacheFlusher.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/EventProviders/AuthResultCache.h"
#include "Source/santad/EventProviders/MockFAAPolicyProcessor.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityAuthorizer.h"

using santa::AuthResultCache;
using santa::CheckPolicyBlock;
using santa::ESCacheClearStrategy;
using santa::ESCacheFlusher;
using santa::IterateProcessPoliciesBlock;
using santa::MockFAAPolicyProcessor;
using santa::PairPathAndType;
using santa::ProcessWatchItemPolicy;
using santa::SetPairPathAndType;
using santa::WatchItemParentDirectoryProtection;
using santa::WatchItemPathType;
using santa::WatchItemProcess;

void SetExpectationsForProcessFileAccessAuthorizerInit(
    std::shared_ptr<MockEndpointSecurityAPI> mockESApi) {
  EXPECT_CALL(*mockESApi, UnmuteAllPaths).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, UnmuteAllTargetPaths).WillOnce(testing::Return(true));
  EXPECT_CALL(*mockESApi, InvertProcessMuting).WillOnce(testing::Return(true));
}

@interface SNTEndpointSecurityProcessFileAccessAuthorizer (Testing)
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

// A real authorizer, Process FAA client, local exec cache, and flusher, each
// client with its own mock API so clears are attributed to the client that
// made them.
//
// `execCached` stands in for the ES EXEC cache: an ALLOW that the authorizer
// marks cacheable is held until the authorizer's ES cache is cleared, and
// while it is held, later executions of the same file from the same instigator
// are not delivered to the authorizer.
struct ProcessFAAHarness {
  std::shared_ptr<MockEndpointSecurityAPI> authAPI;
  std::shared_ptr<MockEndpointSecurityAPI> procAPI;
  std::shared_ptr<MockFAAPolicyProcessor> mockFAA;
  std::shared_ptr<ESCacheFlusher> flusher;
  std::shared_ptr<AuthResultCache> authResultCache;
  SNTEndpointSecurityAuthorizer* authorizer;
  SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient;
  std::shared_ptr<std::atomic<bool>> execCached = std::make_shared<std::atomic<bool>>(false);
  std::shared_ptr<std::atomic<bool>> policyMatches = std::make_shared<std::atomic<bool>>(false);
  std::shared_ptr<ClearCounter> authClears = std::make_shared<ClearCounter>();
  std::shared_ptr<ClearCounter> procClears = std::make_shared<ClearCounter>();

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

ProcessFAAHarness MakeProcessFAAHarness(ESCacheClearStrategy strategy) {
  ProcessFAAHarness h;

  h.authAPI = std::make_shared<MockEndpointSecurityAPI>();
  h.authAPI->SetExpectationsESNewClient();
  h.authAPI->SetExpectationsRetainReleaseMessage();
  h.procAPI = std::make_shared<MockEndpointSecurityAPI>();
  h.procAPI->SetExpectationsESNewClient();
  h.procAPI->SetExpectationsRetainReleaseMessage();
  SetExpectationsForProcessFileAccessAuthorizerInit(h.procAPI);

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
  auto procClears = h.procClears;
  EXPECT_CALL(*h.procAPI, ClearCache).WillRepeatedly([procClears] {
    procClears->Record();
    return true;
  });

  h.mockFAA = std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr, 0,
                                                       0, nil, nil);
  auto policyMatches = h.policyMatches;
  EXPECT_CALL(*h.mockFAA, PolicyMatchesProcess)
      .WillRepeatedly([policyMatches](const WatchItemProcess&, const es_process_t*) {
        return policyMatches->load();
      });
  auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(h.mockFAA);

  WatchItemProcess proc("bar", "", "", {}, "", false);
  auto pwip = std::make_shared<ProcessWatchItemPolicy>(
      "name", "ver", SetPairPathAndType{PairPathAndType{"path1", WatchItemPathType::kLiteral}},
      true, santa::WatchItemRuleType::kProcessesWithAllowedPaths, santa::WatchItemProcessOptions{},
      santa::WatchItemProcessList{proc});

  h.flusher = std::make_shared<ESCacheFlusher>(strategy);
  h.authResultCache = AuthResultCache::Create(h.flusher, nil);
  h.authorizer = [[SNTEndpointSecurityAuthorizer alloc] initWithESAPI:h.authAPI
                                                              metrics:nullptr
                                                       execController:nil
                                                   compilerController:nil
                                                      authResultCache:h.authResultCache
                                                            ttyWriter:nullptr
                                                          processTree:nullptr];
  h.procFAAClient = [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc]
                    initWithESAPI:h.procAPI
                          metrics:nullptr
               faaPolicyProcessor:mockFAAProxy
      iterateProcessPoliciesBlock:^(CheckPolicyBlock block) {
        block(pwip);
      }
                   esCacheFlusher:h.flusher];

  [h.authorizer registerAuthExecProbe:h.procFAAClient];
  h.flusher->AddClient(h.authorizer);
  h.flusher->AddClient(h.procFAAClient);

  return h;
}

}  // namespace

@interface SNTEndpointSecurityProcessFileAccessAuthorizerTest : XCTestCase
@end

@implementation SNTEndpointSecurityProcessFileAccessAuthorizerTest

- (void)testEnable {
  std::set<es_event_type_t> expectedEventSubs = {
      ES_EVENT_TYPE_AUTH_CLONE,        ES_EVENT_TYPE_AUTH_COPYFILE, ES_EVENT_TYPE_AUTH_CREATE,
      ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,     ES_EVENT_TYPE_AUTH_OPEN,
      ES_EVENT_TYPE_AUTH_RENAME,       ES_EVENT_TYPE_AUTH_TRUNCATE, ES_EVENT_TYPE_AUTH_UNLINK,
      ES_EVENT_TYPE_NOTIFY_EXEC,       ES_EVENT_TYPE_NOTIFY_EXIT,   ES_EVENT_TYPE_NOTIFY_FORK,
  };

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  SetExpectationsForProcessFileAccessAuthorizerInit(mockESApi);

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

  auto mockFAA = std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr,
                                                          0, 0, nil, nil);
  auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(mockFAA);

  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient =
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                    metrics:nullptr
                                                         faaPolicyProcessor:mockFAAProxy
                                                iterateProcessPoliciesBlock:nil
                                                             esCacheFlusher:flusher];
  flusher->AddClient(procFAAClient);

  [procFAAClient enable];
  XCTAssertSemaTrue(sema, 5, "ES cache was not cleared");

  for (const auto& event : expectedEventSubs) {
    XCTAssertNoThrow(santa::EventTypeToString(event));
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testProbeInterest {
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &esProc);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  SetExpectationsForProcessFileAccessAuthorizerInit(mockESApi);

  // First call will not match, second call will match
  auto mockFAA = std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr,
                                                          0, 0, nil, nil);
  EXPECT_CALL(*mockFAA, PolicyMatchesProcess)
      .WillOnce(testing::Return(false))
      .WillOnce(testing::Return(true));
  auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(mockFAA);

  // Test object to provide to the CheckPolicyBlock
  WatchItemProcess proc("proc_path_1", "com.example.proc", "PROCTEAMID", {}, "", false);
  auto pwip = std::make_shared<ProcessWatchItemPolicy>(
      "name", "ver", SetPairPathAndType{PairPathAndType{"path1", WatchItemPathType::kLiteral}},
      true, santa::WatchItemRuleType::kProcessesWithAllowedPaths, santa::WatchItemProcessOptions{},
      santa::WatchItemProcessList{proc});

  // Test iter block will call the given CheckPolicyBlock and capture the return
  __block bool checkPolicyBlockResult;
  IterateProcessPoliciesBlock iterPoliciesBlock = ^(CheckPolicyBlock block) {
    checkPolicyBlockResult = block(pwip);
  };

  SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient =
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc]
                        initWithESAPI:mockESApi
                              metrics:nullptr
                   faaPolicyProcessor:mockFAAProxy
          iterateProcessPoliciesBlock:iterPoliciesBlock
                       esCacheFlusher:std::make_shared<ESCacheFlusher>(
                                          ESCacheClearStrategy::kSingleClient)];

  // Fake being conected so the probe runs
  procFAAClient.isSubscribed = true;

  {
    santa::Message msg(mockESApi, &esMsg);

    // First test a non-matching policy. The probe should return uninterested
    // and the CheckPolicyBlock should not return true;
    XCTAssertEqual([procFAAClient probeInterest:msg], santa::ProbeInterest::kUninterested);
    XCTAssertFalse(checkPolicyBlockResult);

    // Next check a mtching policy. The probe should return interested, the
    // process should be muted, and CheckPolicyBlock should return true.
    EXPECT_CALL(*mockESApi, MuteProcess).WillOnce(testing::Return(true));

    XCTAssertEqual([procFAAClient probeInterest:msg], santa::ProbeInterest::kInterested);
    XCTAssertTrue(checkPolicyBlockResult);
  }
}

/// Enabling clears every matched process policy before requesting cache
/// invalidation, so a process is re-evaluated against the current policy by the
/// time its cached operations are invalidated.
- (void)testEnableClearsMatchedPoliciesBeforeRequestingInvalidation {
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &esProc);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  SetExpectationsForProcessFileAccessAuthorizerInit(mockESApi);

  auto mockFAA = std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr,
                                                          0, 0, nil, nil);
  EXPECT_CALL(*mockFAA, PolicyMatchesProcess).WillOnce(testing::Return(true));
  auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(mockFAA);

  WatchItemProcess proc("proc_path_1", "com.example.proc", "PROCTEAMID", {}, "", false);
  auto pwip = std::make_shared<ProcessWatchItemPolicy>(
      "name", "ver", SetPairPathAndType{PairPathAndType{"path1", WatchItemPathType::kLiteral}},
      true, santa::WatchItemRuleType::kProcessesWithAllowedPaths, santa::WatchItemProcessOptions{},
      santa::WatchItemProcessList{proc});
  IterateProcessPoliciesBlock iterPoliciesBlock = ^(CheckPolicyBlock block) {
    block(pwip);
  };

  auto flusher = std::make_shared<ESCacheFlusher>(ESCacheClearStrategy::kSingleClient);
  SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient =
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                    metrics:nullptr
                                                         faaPolicyProcessor:mockFAAProxy
                                                iterateProcessPoliciesBlock:iterPoliciesBlock
                                                             esCacheFlusher:flusher];
  procFAAClient.isSubscribed = true;

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

  flusher->AddClient(procFAAClient);
  flusher->AddClient(sentinel);

  // The process matches the policy when it executes
  EXPECT_CALL(*mockESApi, MuteProcess).WillOnce(testing::Return(true));
  {
    santa::Message msg(mockESApi, &esMsg);
    XCTAssertEqual([procFAAClient probeInterest:msg], santa::ProbeInterest::kInterested);
  }

  // Clearing the matched policy notifies the policy processor. The flusher
  // queue is serial, so waiting here for a newly requested pass first runs any
  // invalidation already requested.
  auto policiesCleared = std::make_shared<std::atomic<bool>>(false);
  __block audit_token_t clearedToken = {};
  __weak SNTEndpointSecurityClient* weakSentinel = sentinel;
  mockFAA->notifyExitHook = ^(const audit_token_t& tok) {
    clearedToken = tok;
    flusher->Flush(weakSentinel);
    dispatch_semaphore_wait(sentinelSema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
    policiesCleared->store(true);
  };

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  auto clearedAfterPolicies = std::make_shared<std::atomic<bool>>(false);
  EXPECT_CALL(*mockESApi, ClearCache).WillOnce([sema, policiesCleared, clearedAfterPolicies] {
    clearedAfterPolicies->store(policiesCleared->load());
    dispatch_semaphore_signal(sema);
    return true;
  });

  [procFAAClient processWatchItemsCount:1];

  XCTAssertSemaTrue(sema, 5, "ES cache was not cleared");
  XCTAssertTrue(clearedAfterPolicies->load());
  XCTAssertEqual(audit_token_to_pid(clearedToken), audit_token_to_pid(execProc.audit_token));
  XCTAssertEqual(audit_token_to_pidversion(clearedToken),
                 audit_token_to_pidversion(execProc.audit_token));

  mockFAA->notifyExitHook = nil;
  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
  XCTBubbleMockVerifyAndClearExpectations(sentinelAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(mockFAA.get());
}

/// The process list is ordered so that ProcessesWithOptions entries precede
/// Processes entries. Matching must visit them in that order and stop at the
/// first match so those entries take precedence.
- (void)testFindPolicyForProcessMatchesInOrder {
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &esProc);
  esMsg.event.exec.target = &execProc;

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsESNewClient();
  mockESApi->SetExpectationsRetainReleaseMessage();
  SetExpectationsForProcessFileAccessAuthorizerInit(mockESApi);

  auto mockFAA = std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr,
                                                          0, 0, nil, nil);

  // Record which entries were considered, in order. Only the second one matches
  // so that iteration is observed to continue past a miss and then stop.
  auto considered = std::make_shared<std::vector<std::string>>();
  EXPECT_CALL(*mockFAA, PolicyMatchesProcess)
      .WillRepeatedly([considered](const WatchItemProcess& policyProc, const es_process_t*) {
        considered->push_back(policyProc.binary_path);
        return policyProc.binary_path == "withopts2";
      });
  auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(mockFAA);

  santa::WatchItemProcessOptions opts;
  opts.action = santa::WatchItemProcessAction::kDeny;
  auto pwip = std::make_shared<ProcessWatchItemPolicy>(
      "name", "ver", SetPairPathAndType{PairPathAndType{"path1", WatchItemPathType::kLiteral}},
      true, santa::WatchItemRuleType::kProcessesWithAllowedPaths, santa::WatchItemProcessOptions{},
      santa::WatchItemProcessList{
          WatchItemProcess("withopts1", "", "", {}, "", false, opts),
          WatchItemProcess("withopts2", "", "", {}, "", false, opts),
          WatchItemProcess("plain", "", "", {}, "", false),
      });

  IterateProcessPoliciesBlock iterPoliciesBlock = ^(CheckPolicyBlock block) {
    block(pwip);
  };

  SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient =
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc]
                        initWithESAPI:mockESApi
                              metrics:nullptr
                   faaPolicyProcessor:mockFAAProxy
          iterateProcessPoliciesBlock:iterPoliciesBlock
                       esCacheFlusher:std::make_shared<ESCacheFlusher>(
                                          ESCacheClearStrategy::kSingleClient)];
  procFAAClient.isSubscribed = true;

  EXPECT_CALL(*mockESApi, MuteProcess).WillOnce(testing::Return(true));

  santa::Message msg(mockESApi, &esMsg);
  XCTAssertEqual([procFAAClient probeInterest:msg], santa::ProbeInterest::kInterested);

  // The trailing `plain` entry must never have been reached
  XCTAssertEqual(considered->size(), 2);
  XCTAssertCppStringEqual((*considered)[0], "withopts1");
  XCTAssertCppStringEqual((*considered)[1], "withopts2");
}

/// A ProcessesWithDeniedPaths rule's parent directory protection decides a
/// rename of a directory that holds one of its paths, but not a rename of the
/// path itself.
- (void)testParentDirectoryProtection {
  id mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([mockConfigurator configurator]).andReturn(mockConfigurator);
  OCMStub([mockConfigurator overrideFileAccessAction]).andReturn(SNTOverrideFileAccessActionNone);
  OCMStub([mockConfigurator enableBadSignatureProtection]).andReturn(NO);

  es_file_t procFile = MakeESFile("/proc/watched");
  es_process_t esProc = MakeESProcess(&procFile);
  esProc.codesigning_flags = CS_SIGNED | CS_VALID;

  struct stat dirStat = MakeStat();
  dirStat.st_mode = S_IFDIR | 0755;
  es_file_t ancestorDir = MakeESFile("/a/b", dirStat);
  es_file_t deniedDir = MakeESFile("/a/b/c", dirStat);
  es_file_t destDir = MakeESFile("/x");

  struct Outcome {
    es_auth_result_t result;
    std::vector<FileAccessPolicyDecision> stored;
  };

  // Responds to the watched process renaming `source` under a rule denying it
  // /a/b/c
  auto rename = [&](WatchItemParentDirectoryProtection pdp, es_file_t* source) {
    es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_RENAME, &esProc, ActionType::Auth);
    esMsg.event.rename.source = source;
    esMsg.event.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH;
    esMsg.event.rename.destination.new_path.dir = &destDir;
    esMsg.event.rename.destination.new_path.filename = MakeESStringToken("moved");

    auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
    mockESApi->SetExpectationsESNewClient();
    mockESApi->SetExpectationsRetainReleaseMessage();
    SetExpectationsForProcessFileAccessAuthorizerInit(mockESApi);

    Outcome outcome = {};
    dispatch_semaphore_t respondedSema = dispatch_semaphore_create(0);
    dispatch_semaphore_t processedSema = dispatch_semaphore_create(0);
    // A directory tree operation is never cacheable
    EXPECT_CALL(*mockESApi, RespondAuthResult(testing::_, testing::_, testing::_, false))
        .WillOnce([&outcome, respondedSema](const santa::Client&, const santa::Message&,
                                            es_auth_result_t result, bool) {
          outcome.result = result;
          dispatch_semaphore_signal(respondedSema);
          return true;
        });

    __block std::vector<FileAccessPolicyDecision> stored;
    auto mockFAA =
        std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr, 0, 0, nil,
                                                 ^(SNTStoredFileAccessEvent* event, bool) {
                                                   stored.push_back(event.decision);
                                                 });
    EXPECT_CALL(*mockFAA, PolicyMatchesProcess).WillRepeatedly(testing::Return(true));
    mockFAA->UseRealPolicyEvaluation();
    auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(mockFAA);

    auto pwip = std::make_shared<ProcessWatchItemPolicy>(
        "rule", "v1", SetPairPathAndType{{"/a/b/c", WatchItemPathType::kLiteral}},
        /*audit_only=*/false, santa::WatchItemRuleType::kProcessesWithDeniedPaths,
        santa::WatchItemProcessOptions{},
        santa::WatchItemProcessList{WatchItemProcess("/proc/watched", "", "", {}, "", false)}, 0,
        pdp);
    IterateProcessPoliciesBlock iterPoliciesBlock = ^(CheckPolicyBlock block) {
      block(pwip);
    };

    SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient =
        [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc]
                          initWithESAPI:mockESApi
                                metrics:nullptr
                     faaPolicyProcessor:mockFAAProxy
            iterateProcessPoliciesBlock:iterPoliciesBlock
                         esCacheFlusher:std::make_shared<ESCacheFlusher>(
                                            ESCacheClearStrategy::kSingleClient)];
    procFAAClient.fileAccessDeniedBlock =
        ^(SNTStoredFileAccessEvent*, NSString*, NSString*, NSString*) {
        };

    [procFAAClient handleMessage:santa::Message(mockESApi, &esMsg)
              recordEventMetrics:^(santa::EventDisposition) {
                dispatch_semaphore_signal(processedSema);
              }];
    XCTAssertSemaTrue(respondedSema, 5, "Rename was not responded to");
    XCTAssertSemaTrue(processedSema, 5, "Rename was not processed");
    outcome.stored = stored;

    XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
    return outcome;
  };

  using Stored = std::vector<FileAccessPolicyDecision>;

  // An ancestor match is audited in audit mode, denied in enforce mode, and not
  // evaluated at all when disabled
  Outcome got = rename(WatchItemParentDirectoryProtection::kAudit, &ancestorDir);
  XCTAssertEqual(got.result, ES_AUTH_RESULT_ALLOW);
  XCTAssertTrue(got.stored == Stored({FileAccessPolicyDecision::kAllowedAuditOnly}));

  got = rename(WatchItemParentDirectoryProtection::kEnforce, &ancestorDir);
  XCTAssertEqual(got.result, ES_AUTH_RESULT_DENY);
  XCTAssertTrue(got.stored == Stored({FileAccessPolicyDecision::kDenied}));

  got = rename(WatchItemParentDirectoryProtection::kDisabled, &ancestorDir);
  XCTAssertEqual(got.result, ES_AUTH_RESULT_ALLOW);
  XCTAssertTrue(got.stored.empty());

  // A direct match is denied whatever the setting
  for (WatchItemParentDirectoryProtection pdp : {WatchItemParentDirectoryProtection::kAudit,
                                                 WatchItemParentDirectoryProtection::kDisabled}) {
    got = rename(pdp, &deniedDir);
    XCTAssertEqual(got.result, ES_AUTH_RESULT_DENY);
    XCTAssertTrue(got.stored == Stored({FileAccessPolicyDecision::kDenied}));
  }

  [mockConfigurator stopMocking];
}

/// Warms a cacheable EXEC ALLOW, applies `update`, and checks that a later
/// execution of the same file reaches the Process FAA probe.
- (void)assertProcessProbeRunsAfterUpdate:(void (^)(ProcessFAAHarness&))update
                                  harness:(ProcessFAAHarness&)h {
  es_file_t instigatorFile = MakeESFile("foo");
  es_process_t instigator = MakeESProcess(&instigatorFile);
  es_file_t execFile = MakeESFile("bar");
  es_process_t execProc = MakeESProcess(&execFile, MakeAuditToken(12, 23), MakeAuditToken(34, 45));
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_EXEC, &instigator);
  esMsg.event.exec.target = &execProc;

  // Warm the local and modeled ES caches with an ALLOW the probe did not want
  santa::ExecTarget target = santa::ExecTarget::ForExecEvent(&esMsg);
  h.authResultCache->AddToCache(target, SNTActionRequestBinary);
  h.authResultCache->AddToCache(target, SNTActionRespondAllow);
  XCTAssertTrue(h.DeliverExec(&esMsg));
  XCTAssertTrue(h.execCached->load());
  // The cached exec is not delivered again
  execProc.audit_token = MakeAuditToken(12, 24);
  XCTAssertFalse(h.DeliverExec(&esMsg));

  int authClearsBefore = h.authClears->count.load();
  int procClearsBefore = h.procClears->count.load();

  update(h);

  // Both clients are cleared by the central pass. The authorizer is cleared
  // first, so it is done once the FAA client is.
  XCTAssertTrue(h.procClears->WaitFor(procClearsBefore + 1));
  XCTAssertEqual(h.authClears->count.load(), authClearsBefore + 1);
  XCTAssertEqual(h.procClears->count.load(), procClearsBefore + 1);

  // The FAA update keeps the local exec cache entry
  XCTAssertEqual(h.authResultCache->CheckCache(target).action, SNTActionRespondAllow);

  // The next execution reaches the authorizer, and on a local cache hit the
  // probe starts watching the new process.
  audit_token_t newToken = MakeAuditToken(12, 25);
  execProc.audit_token = newToken;
  EXPECT_CALL(*h.procAPI,
              MuteProcess(testing::_, testing::Truly([newToken](const audit_token_t* t) {
                            return AuditTokenEqual(t, newToken);
                          })))
      .WillOnce(testing::Return(true));
  XCTAssertTrue(h.DeliverExec(&esMsg));
  // Watched processes are not cached
  XCTAssertFalse(h.execCached->load());

  XCTBubbleMockVerifyAndClearExpectations(h.procAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(h.authAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(h.mockFAA.get());
}

- (void)testActivationInvalidatesCachedExecForProcessProbe {
  ProcessFAAHarness h = MakeProcessFAAHarness(ESCacheClearStrategy::kEveryClient);
  h.policyMatches->store(true);

  [self
      assertProcessProbeRunsAfterUpdate:^(ProcessFAAHarness& h) {
        [h.procFAAClient processWatchItemsCount:1];
      }
                                harness:h];
}

- (void)testMatcherExpansionInvalidatesCachedExecForProcessProbe {
  ProcessFAAHarness h = MakeProcessFAAHarness(ESCacheClearStrategy::kEveryClient);
  // Already active, with a policy that does not yet match the executable
  h.procFAAClient.isSubscribed = true;

  [self
      assertProcessProbeRunsAfterUpdate:^(ProcessFAAHarness& h) {
        h.policyMatches->store(true);
        [h.procFAAClient processWatchItemsCount:1];
      }
                                harness:h];
}

- (void)testReenableInvalidatesCachedExecForProcessProbe {
  ProcessFAAHarness h = MakeProcessFAAHarness(ESCacheClearStrategy::kEveryClient);
  h.policyMatches->store(true);
  h.procFAAClient.isSubscribed = true;

  // Disabling requests no central invalidation, so the only clears are from
  // the pass that waits for pending requests.
  EXPECT_CALL(*h.procAPI, UnsubscribeAll).WillOnce(testing::Return(true));
  [h.procFAAClient processWatchItemsCount:0];
  XCTAssertTrue(h.WaitForPendingPasses());
  XCTAssertEqual(h.authClears->count.load(), 1);
  XCTAssertEqual(h.procClears->count.load(), 1);

  [self
      assertProcessProbeRunsAfterUpdate:^(ProcessFAAHarness& h) {
        [h.procFAAClient processWatchItemsCount:1];
      }
                                harness:h];
}

- (void)testSingleClientFAAUpdateClearsOnlyTheFAAClient {
  ProcessFAAHarness h = MakeProcessFAAHarness(ESCacheClearStrategy::kSingleClient);
  h.policyMatches->store(true);

  [h.procFAAClient processWatchItemsCount:1];
  XCTAssertTrue(h.procClears->WaitFor(1));
  XCTAssertTrue(h.WaitForPendingPasses());

  XCTAssertEqual(h.authClears->count.load(), 0);
  XCTAssertEqual(h.procClears->count.load(), 1);

  XCTBubbleMockVerifyAndClearExpectations(h.procAPI.get());
  XCTBubbleMockVerifyAndClearExpectations(h.authAPI.get());
}

@end
