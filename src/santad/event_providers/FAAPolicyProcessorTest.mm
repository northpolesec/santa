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

#include "src/santad/event_providers/FAAPolicyProcessor.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>
#include <optional>

#import "src/common/MOLCertificate.h"
#import "src/common/MOLCodesignChecker.h"
#import "src/common/SNTCachedDecision.h"
#include "src/common/TestUtils.h"
#include "src/common/faa/WatchItemPolicy.h"
#include "src/santad/event_providers/endpoint_security/Message.h"
#include "src/santad/event_providers/endpoint_security/MockEndpointSecurityAPI.h"
#include "src/santad/event_providers/MockFAAPolicyProcessor.h"
#include "src/santad/SNTDecisionCache.h"

using santa::FAAPolicyProcessor;
using santa::Message;
using santa::MockFAAPolicyProcessor;
using santa::WatchItemPolicyBase;
using santa::WatchItemProcess;

namespace santa {
extern FileAccessPolicyDecision ApplyOverrideToDecision(FileAccessPolicyDecision decision,
                                                        SNTOverrideFileAccessAction overrideAction);
extern es_auth_result_t CombinePolicyResults(es_auth_result_t result1, es_auth_result_t result2);
extern es_auth_result_t FileAccessPolicyDecisionToESAuthResult(FileAccessPolicyDecision decision);
extern bool IsBlockDecision(FileAccessPolicyDecision decision);
extern bool ShouldLogDecision(FileAccessPolicyDecision decision);
}  // namespace santa

// Helper to reset a policy to an empty state
static void ClearWatchItemPolicyProcess(WatchItemProcess &proc) {
  proc.binary_path = "";
  proc.UnsafeUpdateSigningId("");
  proc.team_id = "";
  proc.certificate_sha256 = "";
  proc.cdhash.clear();
  proc.platform_binary = false;
}

@interface FAAPolicyProcessorTest : XCTestCase
@property id mockConfigurator;
@property id cscMock;
@property id dcMock;
@end

@implementation FAAPolicyProcessorTest

- (void)setUp {
  [super setUp];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);

  self.dcMock = OCMStrictClassMock([SNTDecisionCache class]);
}

- (void)tearDown {
  [self.dcMock stopMocking];
  [self.dcMock stopMocking];

  [super tearDown];
}

- (void)testFileAccessPolicyDecisionToESAuthResult {
  std::map<FileAccessPolicyDecision, es_auth_result_t> policyDecisionToAuthResult = {
      {FileAccessPolicyDecision::kNoPolicy, ES_AUTH_RESULT_ALLOW},
      {FileAccessPolicyDecision::kDenied, ES_AUTH_RESULT_DENY},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, ES_AUTH_RESULT_DENY},
      {FileAccessPolicyDecision::kAllowed, ES_AUTH_RESULT_ALLOW},
      {FileAccessPolicyDecision::kAllowedReadAccess, ES_AUTH_RESULT_ALLOW},
      {FileAccessPolicyDecision::kAllowedAuditOnly, ES_AUTH_RESULT_ALLOW},
  };

  for (const auto &kv : policyDecisionToAuthResult) {
    XCTAssertEqual(santa::FileAccessPolicyDecisionToESAuthResult(kv.first), kv.second);
  }

  XCTAssertThrows(santa::FileAccessPolicyDecisionToESAuthResult((FileAccessPolicyDecision)123));
}

- (void)testShouldLogDecision {
  std::map<FileAccessPolicyDecision, bool> policyDecisionToShouldLog = {
      {FileAccessPolicyDecision::kNoPolicy, false},
      {FileAccessPolicyDecision::kDenied, true},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, true},
      {FileAccessPolicyDecision::kAllowed, false},
      {FileAccessPolicyDecision::kAllowedReadAccess, false},
      {FileAccessPolicyDecision::kAllowedAuditOnly, true},
      {(FileAccessPolicyDecision)123, false},
  };

  for (const auto &kv : policyDecisionToShouldLog) {
    XCTAssertEqual(santa::ShouldLogDecision(kv.first), kv.second);
  }
}

- (void)testIsBlockDecision {
  std::map<FileAccessPolicyDecision, bool> policyDecisionToIsBlockDecision = {
      {FileAccessPolicyDecision::kNoPolicy, false},
      {FileAccessPolicyDecision::kDenied, true},
      {FileAccessPolicyDecision::kDeniedInvalidSignature, true},
      {FileAccessPolicyDecision::kAllowed, false},
      {FileAccessPolicyDecision::kAllowedReadAccess, false},
      {FileAccessPolicyDecision::kAllowedAuditOnly, false},
      {(FileAccessPolicyDecision)123, false},
  };

  for (const auto &kv : policyDecisionToIsBlockDecision) {
    XCTAssertEqual(santa::IsBlockDecision(kv.first), kv.second);
  }
}

- (void)testApplyOverrideToDecision {
  std::map<std::pair<FileAccessPolicyDecision, SNTOverrideFileAccessAction>,
           FileAccessPolicyDecision>
      decisionAndOverrideToDecision = {
          // Override action: None - Policy shouldn't be changed
          {{FileAccessPolicyDecision::kNoPolicy, SNTOverrideFileAccessActionNone},
           FileAccessPolicyDecision::kNoPolicy},
          {{FileAccessPolicyDecision::kDenied, SNTOverrideFileAccessActionNone},
           FileAccessPolicyDecision::kDenied},

          // Override action: AuditOnly - Policy should be changed only on blocked decisions
          {{FileAccessPolicyDecision::kNoPolicy, SNTOverrideFileAccessActionAuditOnly},
           FileAccessPolicyDecision::kNoPolicy},
          {{FileAccessPolicyDecision::kAllowedAuditOnly, SNTOverrideFileAccessActionAuditOnly},
           FileAccessPolicyDecision::kAllowedAuditOnly},
          {{FileAccessPolicyDecision::kAllowedReadAccess, SNTOverrideFileAccessActionAuditOnly},
           FileAccessPolicyDecision::kAllowedReadAccess},
          {{FileAccessPolicyDecision::kDenied, SNTOverrideFileAccessActionAuditOnly},
           FileAccessPolicyDecision::kAllowedAuditOnly},
          {{FileAccessPolicyDecision::kDeniedInvalidSignature,
            SNTOverrideFileAccessActionAuditOnly},
           FileAccessPolicyDecision::kAllowedAuditOnly},

          // Override action: Disable - Always changes the decision to be no policy applied
          {{FileAccessPolicyDecision::kAllowed, SNTOverrideFileAccessActionDiable},
           FileAccessPolicyDecision::kNoPolicy},
          {{FileAccessPolicyDecision::kDenied, SNTOverrideFileAccessActionDiable},
           FileAccessPolicyDecision::kNoPolicy},
          {{FileAccessPolicyDecision::kAllowedReadAccess, SNTOverrideFileAccessActionDiable},
           FileAccessPolicyDecision::kNoPolicy},
          {{FileAccessPolicyDecision::kAllowedAuditOnly, SNTOverrideFileAccessActionDiable},
           FileAccessPolicyDecision::kNoPolicy},
  };

  for (const auto &kv : decisionAndOverrideToDecision) {
    XCTAssertEqual(santa::ApplyOverrideToDecision(kv.first.first, kv.first.second), kv.second);
  }

  XCTAssertThrows(santa::ApplyOverrideToDecision(FileAccessPolicyDecision::kAllowed,
                                                 (SNTOverrideFileAccessAction)123));
}

- (void)testCombinePolicyResults {
  // Ensure that the combined result is ES_AUTH_RESULT_DENY if both or either
  // input result is ES_AUTH_RESULT_DENY.
  XCTAssertEqual(santa::CombinePolicyResults(ES_AUTH_RESULT_DENY, ES_AUTH_RESULT_DENY),
                 ES_AUTH_RESULT_DENY);

  XCTAssertEqual(santa::CombinePolicyResults(ES_AUTH_RESULT_DENY, ES_AUTH_RESULT_ALLOW),
                 ES_AUTH_RESULT_DENY);

  XCTAssertEqual(santa::CombinePolicyResults(ES_AUTH_RESULT_ALLOW, ES_AUTH_RESULT_DENY),
                 ES_AUTH_RESULT_DENY);

  XCTAssertEqual(santa::CombinePolicyResults(ES_AUTH_RESULT_ALLOW, ES_AUTH_RESULT_ALLOW),
                 ES_AUTH_RESULT_ALLOW);
}

- (void)testSpecialCaseForPolicyMessage {
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, &esProc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  auto policy = std::make_shared<santa::WatchItemPolicyBase>("foo_policy", "ver", "/foo");
  Message::PathTarget target = {.path = "/some/random/path", .is_readable = true};

  MockFAAPolicyProcessor faaPolicyProcessor(self.dcMock, nullptr, nullptr, nullptr, nullptr, 0, 0,
                                            nil, nil);

  EXPECT_CALL(faaPolicyProcessor, PolicyAllowsReadsForTarget)
      .WillRepeatedly([&faaPolicyProcessor](const Message &msg, const Message::PathTarget &target,
                                            std::shared_ptr<santa::WatchItemPolicyBase> policy) {
        return faaPolicyProcessor.PolicyAllowsReadsForTargetWrapper(msg, target, policy);
      });

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_OPEN;

    // Write-only policy, Write operation
    {
      policy->allow_read_access = true;
      esMsg.event.open.fflag = FWRITE | FREAD;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), false);
    }

    // Write-only policy, Read operation
    {
      policy->allow_read_access = true;
      esMsg.event.open.fflag = FREAD;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), true);
    }

    // Read/Write policy, Read operation
    {
      policy->allow_read_access = false;
      esMsg.event.open.fflag = FREAD;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), false);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_CLONE;

    // Write-only policy, target readable
    {
      policy->allow_read_access = true;
      target.is_readable = true;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), true);
    }

    // Write-only policy, target not readable
    {
      policy->allow_read_access = true;
      target.is_readable = false;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), false);
    }
  }

  {
    esMsg.event_type = ES_EVENT_TYPE_AUTH_COPYFILE;

    // Write-only policy, target readable
    {
      policy->allow_read_access = true;
      target.is_readable = true;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), true);
    }

    // Write-only policy, target not readable
    {
      policy->allow_read_access = true;
      target.is_readable = false;
      Message msg(mockESApi, &esMsg);
      XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), false);
    }
  }

  // Ensure other event types do not have a special case
  std::set<es_event_type_t> eventTypes = {
      ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_AUTH_LINK,
      ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_TRUNCATE,     ES_EVENT_TYPE_AUTH_UNLINK,
  };

  for (const auto &event : eventTypes) {
    esMsg.event_type = event;
    Message msg(mockESApi, &esMsg);
    XCTAssertEqual(faaPolicyProcessor.PolicyAllowsReadsForTarget(msg, target, policy), false);
  }
}

- (void)testApplyPolicy {
  const char *instigatingPath = "/path/to/proc";
  WatchItemProcess policyProc(instigatingPath, "", "", {}, "", false);
  es_file_t esFile = MakeESFile(instigatingPath);
  es_process_t esProc = MakeESProcess(&esFile);
  es_message_t esMsg = MakeESMessage(ES_EVENT_TYPE_AUTH_OPEN, &esProc);

  auto mockESApi = std::make_shared<MockEndpointSecurityAPI>();
  mockESApi->SetExpectationsRetainReleaseMessage();

  MockFAAPolicyProcessor faaPolicyProcessor(self.dcMock, nullptr, nullptr, nullptr, nullptr, 0, 0,
                                            nil, nil);
  EXPECT_CALL(faaPolicyProcessor, PolicyAllowsReadsForTarget)
      .WillRepeatedly(testing::Return(false));

  Message::PathTarget target = {.path = "/some/random/path", .is_readable = true};

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  // If no policy exists, the operation is allowed
  {
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, std::nullopt,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kNoPolicy);
    XCTAssertSemaFalse(sema, "Semaphore should never have been signaled");
  }

  auto policy = std::make_shared<WatchItemPolicyBase>("foo_policy", "ver", "/foo");
  policy->processes.insert(policyProc);
  auto optionalPolicy = std::make_optional<std::shared_ptr<WatchItemPolicyBase>>(policy);

  // Signed but invalid instigating processes are automatically
  // denied when `EnableBadSignatureProtection` is true
  {
    OCMExpect([self.mockConfigurator enableBadSignatureProtection]).andReturn(YES);
    esMsg.process->codesigning_flags = CS_SIGNED;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kDeniedInvalidSignature);
    XCTAssertSemaFalse(sema, "Semaphore should never have been signaled");
  }

  // Signed but invalid instigating processes are not automatically
  // denied when `EnableBadSignatureProtection` is false. Policy
  // evaluation should continue normally.
  {
    OCMExpect([self.mockConfigurator enableBadSignatureProtection]).andReturn(NO);
    esMsg.process->codesigning_flags = CS_SIGNED;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return true;
                                              }),
        FileAccessPolicyDecision::kAllowed);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // Set the codesign flags to be signed and valid for the remaining tests
  esMsg.process->codesigning_flags = CS_SIGNED | CS_VALID;

  // If no exceptions, operations are logged and denied
  {
    policy->audit_only = false;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kDenied);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // For audit only policies with no exceptions, operations are logged but allowed
  {
    policy->audit_only = true;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kAllowedAuditOnly);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // The remainder of the tests set the policy's `rule_type` option to
  // invert process exceptions
  policy->rule_type = santa::WatchItemRuleType::kPathsWithDeniedProcesses;

  // If the policy wasn't matched, but the rule type specifies denied processes,
  // then the operation should be allowed.
  {
    policy->audit_only = false;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kAllowed);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // The remainder of the tests set the policy's `rule_type` option to
  // invert process exceptions
  policy->rule_type = santa::WatchItemRuleType::kProcessesWithDeniedPaths;

  // If the policy wasn't matched, but the rule type specifies denied processes/paths,
  // then the operation should be allowed.
  {
    policy->audit_only = false;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kAllowed);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // For audit only policies with no process match and the rule type specifies
  // denied processes/paths, operations are allowed.
  {
    policy->audit_only = true;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return false;
                                              }),
        FileAccessPolicyDecision::kAllowed);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // For audit only policies with matched process details and the rule type specifies
  // denied processes/paths, operations are allowed audit only.
  {
    policy->audit_only = true;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return true;
                                              }),
        FileAccessPolicyDecision::kAllowedAuditOnly);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  // For policies with matched process details and the rule type specifies
  // denied processes/paths, operations are denied.
  {
    policy->audit_only = false;
    XCTAssertEqual(
        faaPolicyProcessor.ApplyPolicyWrapper(Message(mockESApi, &esMsg), target, optionalPolicy,
                                              ^bool(const santa::WatchItemPolicyBase &,
                                                    const Message::PathTarget &, const Message &) {
                                                dispatch_semaphore_signal(sema);
                                                return true;
                                              }),
        FileAccessPolicyDecision::kDenied);
    XCTAssertSemaTrue(sema, 1, "CheckIfPolicyMatchesBlock was never called");
  }

  XCTBubbleMockVerifyAndClearExpectations(mockESApi.get());
}

- (void)testGetCertificateHash {
  es_file_t esFile1 = MakeESFile("foo", MakeStat(100));
  es_file_t esFile2 = MakeESFile("foo", MakeStat(200));
  es_file_t esFile3 = MakeESFile("foo", MakeStat(300));
  NSString *certHash2 = @"abc123";
  NSString *certHash3 = @"xyz789";
  NSString *got;
  NSString *want;
  id certMock = OCMClassMock([MOLCertificate class]);

  MockFAAPolicyProcessor faaPolicyProcessor(self.dcMock, nullptr, nullptr, nullptr, nullptr, 0, 0,
                                            nil, nil);

  EXPECT_CALL(faaPolicyProcessor, GetCertificateHash)
      .WillRepeatedly([&faaPolicyProcessor](const es_file_t *es_file) {
        return faaPolicyProcessor.GetCertificateHashWrapper(es_file);
      });

  //
  // Test 1 - Not in local cache or decision cache, and code sig lookup fails
  //
  OCMExpect([self.dcMock cachedDecisionForFile:esFile1.stat])
      .ignoringNonObjectArgs()
      .andReturn(nil);

  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY]).andReturn(nil);

  got = faaPolicyProcessor.GetCertificateHash(&esFile1);
  want = kBadCertHash;

  XCTAssertEqualObjects(got, want);

  // Call again without setting new expectations on dcMock to ensure the
  // cached value is used
  got = faaPolicyProcessor.GetCertificateHash(&esFile1);
  XCTAssertEqualObjects(got, want);

  XCTAssertTrue(OCMVerifyAll(self.dcMock));

  //
  // Test 2 - Not in local cache or decision cache, code sig lookup successful
  //
  OCMExpect([self.dcMock cachedDecisionForFile:esFile2.stat])
      .ignoringNonObjectArgs()
      .andReturn(nil);
  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY]).andReturn(self.cscMock);

  OCMExpect([self.cscMock leafCertificate]).andReturn(certMock);
  OCMExpect([certMock SHA256]).andReturn(certHash2);

  got = faaPolicyProcessor.GetCertificateHash(&esFile2);
  want = certHash2;

  XCTAssertEqualObjects(got, want);

  // Call again without setting new expectations on dcMock to ensure the
  // cached value is used
  got = faaPolicyProcessor.GetCertificateHash(&esFile2);
  XCTAssertEqualObjects(got, want);

  XCTAssertTrue(OCMVerifyAll(self.dcMock));

  //
  // Test 3 - Not in local cache, but is in decision cache
  //
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.certSHA256 = certHash3;
  OCMExpect([self.dcMock cachedDecisionForFile:esFile3.stat]).ignoringNonObjectArgs().andReturn(cd);

  got = faaPolicyProcessor.GetCertificateHash(&esFile3);
  want = certHash3;

  XCTAssertEqualObjects(got, want);

  // Call again without setting new expectations on dcMock to ensure the
  // cached value is used
  got = faaPolicyProcessor.GetCertificateHash(&esFile3);

  [certMock stopMocking];
}

- (void)testPolicyMatchesProcess {
  const char *instigatingCertHash = "abc123";
  const char *teamId = "myvalidtid";
  const char *signingId = "com.northpolesec.test";
  std::vector<uint8_t> cdhashBytes(CS_CDHASH_LEN);
  std::fill(cdhashBytes.begin(), cdhashBytes.end(), 0xAA);
  es_file_t esFile = MakeESFile("foo");
  es_process_t esProc = MakeESProcess(&esFile);
  esProc.codesigning_flags = CS_SIGNED;
  esProc.team_id = MakeESStringToken(teamId);
  esProc.signing_id = MakeESStringToken(signingId);
  esProc.is_platform_binary = true;
  std::memcpy(esProc.cdhash, cdhashBytes.data(), sizeof(esProc.cdhash));

  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.certSHA256 = @(instigatingCertHash);

  MockFAAPolicyProcessor faaPolicyProcessor(self.dcMock, nullptr, nullptr, nullptr, nullptr, 0, 0,
                                            nil, nil);

  EXPECT_CALL(faaPolicyProcessor, PolicyMatchesProcess)
      .WillRepeatedly([&faaPolicyProcessor](const WatchItemProcess &policy_proc,
                                            const es_process_t *es_proc) {
        return faaPolicyProcessor.FAAPolicyProcessor::PolicyMatchesProcess(policy_proc, es_proc);
      });

  EXPECT_CALL(faaPolicyProcessor, GetCertificateHash)
      .WillRepeatedly(testing::Return(@(instigatingCertHash)));

  WatchItemProcess policyProc("", "", "", {}, "", false);

  {
    // Process policy matching single attribute - path
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.binary_path = "foo";
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.binary_path = "badpath";
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
  }

  {
    // Process policy matching single attribute - SigningID
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.UnsafeUpdateSigningId(signingId);
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.UnsafeUpdateSigningId("badid");
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    es_process_t esProcEmptySigningID = MakeESProcess(&esFile);
    esProcEmptySigningID.codesigning_flags = CS_SIGNED;
    esProcEmptySigningID.team_id.data = NULL;
    esProcEmptySigningID.team_id.length = 0;
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProcEmptySigningID));
  }

  {
    // Process policy matching single attribute - SigningID prefix
    // This section tests various data permutations with an SID prefix
    // set including: platform binary being true/false/unset and TID being set/unset.
    ClearWatchItemPolicyProcess(policyProc);

    policyProc.UnsafeUpdateSigningId("com.northpolesec.*");
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    esProc.is_platform_binary = false;
    policyProc.platform_binary = false;
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    esProc.is_platform_binary = true;
    policyProc.platform_binary = true;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    esProc.is_platform_binary = false;
    policyProc.platform_binary = false;
    policyProc.team_id = teamId;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("badtid*");
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("com.*.test");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("*.northpolesec.test");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("*com.northpolesec.test");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("com.northpolesec.test");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("com.northpolesec.test*");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("*southpolesec.test");
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("this.is.very.long.*.com.northpolesec.test");
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("com.*.*");
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    es_string_token_t savedTok = esProc.signing_id;

    esProc.signing_id = MakeESStringToken("com.northpolesec.*");
    // Able to match on asterisks
    policyProc.UnsafeUpdateSigningId("com.*.*");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    policyProc.UnsafeUpdateSigningId("com.northpolesec.*");
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));

    esProc.signing_id = savedTok;

    // Reset to expected value for the remainding tests
    esProc.is_platform_binary = true;
  }

  {
    // Process policy matching single attribute - TeamID
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.team_id = teamId;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.team_id = "badid";
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    es_process_t esProcEmptyTeamID = MakeESProcess(&esFile);
    esProcEmptyTeamID.codesigning_flags = CS_SIGNED;
    esProcEmptyTeamID.signing_id.data = NULL;
    esProcEmptyTeamID.signing_id.length = 0;
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProcEmptyTeamID));
  }

  {
    // Process policy matching single attribute - cert hash
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.certificate_sha256 = instigatingCertHash;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.certificate_sha256 = "badcert";
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
  }

  {
    // Process policy matching single attribute - cdhash
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.cdhash = cdhashBytes;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.cdhash[0] = 0x0;
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
  }

  {
    // Process policy matching single attribute - platform binary
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.platform_binary = true;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    esProc.is_platform_binary = false;
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    // Reset for remaining tests
    esProc.is_platform_binary = true;
  }

  {
    // Process policy with only a subset of matching attributes
    ClearWatchItemPolicyProcess(policyProc);
    policyProc.binary_path = "foo";
    policyProc.team_id = "invalidtid";
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
  }

  {
    // Process policy with codesigning-based attributes, but unsigned ES process
    ClearWatchItemPolicyProcess(policyProc);
    esProc.codesigning_flags = 0x0;
    policyProc.team_id = "myvalidtid";
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
  }
}

@end
