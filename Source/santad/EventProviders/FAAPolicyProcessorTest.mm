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

#include "Source/santad/EventProviders/FAAPolicyProcessor.h"

#include <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <memory>

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#include "Source/common/TestUtils.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/MockFAAPolicyProcessor.h"
#include "Source/santad/SNTDecisionCache.h"

using santa::MockFAAPolicyProcessor;
using santa::WatchItemProcess;

// Helper to reset a policy to an empty state
static void ClearWatchItemPolicyProcess(WatchItemProcess &proc) {
  proc.binary_path = "";
  proc.signing_id = "";
  proc.team_id = "";
  proc.certificate_sha256 = "";
  proc.cdhash.clear();
}

@interface FAAPolicyProcessorTest : XCTestCase
@property id cscMock;
@property id dcMock;
@end

@implementation FAAPolicyProcessorTest

- (void)setUp {
  [super setUp];

  self.cscMock = OCMClassMock([MOLCodesignChecker class]);
  OCMStub([self.cscMock alloc]).andReturn(self.cscMock);

  self.dcMock = OCMStrictClassMock([SNTDecisionCache class]);
}

- (void)tearDown {
  [self.dcMock stopMocking];

  [super tearDown];
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

  MockFAAPolicyProcessor faaPolicyProcessor(self.dcMock);

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

  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureFailed userInfo:nil];
  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);

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
  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:nil]])
      .andReturn(self.cscMock);

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

- (void)testPolicyProcessMatchesESProcess {
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

  MockFAAPolicyProcessor faaPolicyProcessor(self.dcMock);

  EXPECT_CALL(faaPolicyProcessor, PolicyMatchesProcess)
      .WillRepeatedly([&faaPolicyProcessor](const WatchItemProcess &policy_proc,
                                            const es_process_t *es_proc) {
        return faaPolicyProcessor.FAAPolicyProcessor::PolicyMatchesProcess(policy_proc, es_proc);
      });

  EXPECT_CALL(faaPolicyProcessor, GetCertificateHash)
      .WillRepeatedly(testing::Return(@(instigatingCertHash)));

  NSError *err = [NSError errorWithDomain:@"" code:errSecCSSignatureFailed userInfo:nil];
  OCMExpect([self.cscMock initWithBinaryPath:OCMOCK_ANY error:[OCMArg setTo:err]])
      .andReturn(self.cscMock);

  WatchItemProcess policyProc("", "", "", {}, "", std::nullopt);

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
    policyProc.signing_id = signingId;
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.signing_id = "badid";
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    es_process_t esProcEmptySigningID = MakeESProcess(&esFile);
    esProcEmptySigningID.codesigning_flags = CS_SIGNED;
    esProcEmptySigningID.team_id.data = NULL;
    esProcEmptySigningID.team_id.length = 0;
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProcEmptySigningID));
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
    policyProc.platform_binary = std::make_optional(true);
    XCTAssertTrue(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
    policyProc.platform_binary = std::make_optional(false);
    XCTAssertFalse(faaPolicyProcessor.PolicyMatchesProcess(policyProc, &esProc));
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
