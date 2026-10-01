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

#include <memory>
#include <set>
#include <vector>

#import "Source/common/SNTConfigurator.h"

#include "Source/common/TestUtils.h"
#include "Source/common/es/Message.h"
#include "Source/common/es/MockEndpointSecurityAPI.h"
#include "Source/common/faa/WatchItemPolicy.h"
#include "Source/santad/EventProviders/MockFAAPolicyProcessor.h"

using santa::CheckPolicyBlock;
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

  EXPECT_CALL(*mockESApi, ClearCache)
      .After(EXPECT_CALL(*mockESApi, Subscribe(testing::_, expectedEventSubs))
                 .WillOnce(testing::Return(true)))
      .WillOnce(testing::Return(true));

  auto mockFAA = std::make_shared<MockFAAPolicyProcessor>(nil, nullptr, nullptr, nullptr, nullptr,
                                                          0, 0, nil, nil);
  auto mockFAAProxy = std::make_shared<santa::ProcessFAAPolicyProcessorProxy>(mockFAA);

  SNTEndpointSecurityProcessFileAccessAuthorizer* procFAAClient =
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                    metrics:nullptr
                                                         faaPolicyProcessor:mockFAAProxy
                                                iterateProcessPoliciesBlock:nil];

  [procFAAClient enable];

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
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                    metrics:nullptr
                                                         faaPolicyProcessor:mockFAAProxy
                                                iterateProcessPoliciesBlock:iterPoliciesBlock];

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
      [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                    metrics:nullptr
                                                         faaPolicyProcessor:mockFAAProxy
                                                iterateProcessPoliciesBlock:iterPoliciesBlock];
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
        [[SNTEndpointSecurityProcessFileAccessAuthorizer alloc] initWithESAPI:mockESApi
                                                                      metrics:nullptr
                                                           faaPolicyProcessor:mockFAAProxy
                                                  iterateProcessPoliciesBlock:iterPoliciesBlock];
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

@end
