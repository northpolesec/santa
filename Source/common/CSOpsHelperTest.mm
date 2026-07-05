/// Copyright 2026 North Pole Security, Inc.
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

#import <XCTest/XCTest.h>

#include <unistd.h>

#include <optional>

#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"

@interface CSOpsHelperTest : XCTestCase
@end

@implementation CSOpsHelperTest

- (void)testTokenValidatedStatusFlagsForSelf {
  std::optional<audit_token_t> selfTok = santa::GetMyAuditToken();
  XCTAssertTrue(selfTok.has_value());

  std::optional<uint32_t> flags = santa::CSOpsStatusFlags(*selfTok);
  XCTAssertTrue(flags.has_value());
  XCTAssertNotEqual(*flags, 0u);
}

- (void)testTokenValidatedReadsRefuseMismatchedPidversion {
  // Same pid, wrong incarnation: the kernel must refuse every read with
  // ESRCH — this is the whole point of the token-validated variants.
  std::optional<audit_token_t> selfTok = santa::GetMyAuditToken();
  XCTAssertTrue(selfTok.has_value());
  audit_token_t stale = *selfTok;
  stale.val[7] += 1;  // pidversion

  XCTAssertFalse(santa::CSOpsStatusFlags(stale).has_value());
  XCTAssertFalse(santa::CSOpsGetCDHash(stale).has_value());
  XCTAssertFalse(santa::CSOpsGetTeamID(stale).has_value());
  XCTAssertFalse(santa::CSOpsGetSigningID(stale).has_value());
}

- (void)testTokenVariantsDeliverTokenToInjectedFunc {
  // Every token overload must route the flow token through its own BindToken to
  // the injected csops function. A shared probe records whether the delivered
  // token carries our pid; each getter is exercised independently so a
  // mis-wired overload (wrong token, or none) is caught per-getter.
  std::optional<audit_token_t> selfTok = santa::GetMyAuditToken();
  XCTAssertTrue(selfTok.has_value());

  auto probe = [](bool* seen) {
    return [seen](pid_t pid, unsigned int ops, void* addr, size_t size, audit_token_t* token) {
      *seen = (token != nullptr && token->val[5] == (unsigned int)getpid());
      return csops_audittoken(pid, ops, addr, size, token);
    };
  };

  bool statusSeen = false, cdhashSeen = false, teamIDSeen = false, signingIDSeen = false;
  santa::CSOpsStatusFlags(*selfTok, probe(&statusSeen));
  santa::CSOpsGetCDHash(*selfTok, probe(&cdhashSeen));
  santa::CSOpsGetTeamID(*selfTok, probe(&teamIDSeen));
  santa::CSOpsGetSigningID(*selfTok, probe(&signingIDSeen));

  XCTAssertTrue(statusSeen);
  XCTAssertTrue(cdhashSeen);
  XCTAssertTrue(teamIDSeen);
  XCTAssertTrue(signingIDSeen);
}

@end
