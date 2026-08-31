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

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTCommonEnums.h"

// Defined in SNTCommandRule.mm.
extern BOOL SNTCommandRuleChangesAreRefused(NSURL* syncBaseURL, NSUInteger staticRuleCount,
                                            BOOL check, BOOL importRules,
                                            SNTRuleCleanup cleanupType);

@interface SNTCommandRuleTest : XCTestCase
@end

@implementation SNTCommandRuleTest

static NSURL* SyncURL(void) {
  return [NSURL URLWithString:@"https://sync.example.com/"];
}

#pragma mark - StaticRules only

// Static rules only override the identifiers they name, so the rest of the database must stay
// clearable or a host moving to profile-only management is stuck with a former sync server's
// rules.
- (void)testClearingIsAllowedWithStaticRules {
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(nil, 1, NO, NO, SNTRuleCleanupNonTransitive));
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(nil, 1, NO, NO, SNTRuleCleanupAll));
}

- (void)testAddingIsRefusedWithStaticRules {
  XCTAssertTrue(SNTCommandRuleChangesAreRefused(nil, 1, NO, NO, SNTRuleCleanupNone));
}

// --import adds rules, so it is refused on its own, and combining it with a cleanup flag does not
// make it a cleanup-only operation.
- (void)testImportIsRefusedWithStaticRules {
  XCTAssertTrue(SNTCommandRuleChangesAreRefused(nil, 1, NO, YES, SNTRuleCleanupNone));
  XCTAssertTrue(SNTCommandRuleChangesAreRefused(nil, 1, NO, YES, SNTRuleCleanupNonTransitive));
  XCTAssertTrue(SNTCommandRuleChangesAreRefused(nil, 1, NO, YES, SNTRuleCleanupAll));
}

#pragma mark - SyncBaseURL

// The sync server owns the database, so nothing but a read-only check gets past this gate.
- (void)testEverythingIsRefusedWhileASyncServerIsConfigured {
  const SNTRuleCleanup cleanups[] = {SNTRuleCleanupNone, SNTRuleCleanupNonTransitive,
                                     SNTRuleCleanupAll};
  for (size_t i = 0; i < sizeof(cleanups) / sizeof(cleanups[0]); ++i) {
    for (int importRules = 0; importRules < 2; ++importRules) {
      for (NSUInteger staticCount = 0; staticCount < 2; ++staticCount) {
        XCTAssertTrue(
            SNTCommandRuleChangesAreRefused(SyncURL(), staticCount, NO, importRules, cleanups[i]),
            @"cleanup=%d import=%d static=%lu", (int)cleanups[i], importRules,
            (unsigned long)staticCount);
      }
    }
  }
}

#pragma mark - Exceptions

// --check only reads: it is mutually exclusive with every mutating option and returns before the
// rule database is touched, so it is never refused.
- (void)testCheckIsAlwaysAllowed {
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(SyncURL(), 1, YES, NO, SNTRuleCleanupNone));
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(nil, 1, YES, NO, SNTRuleCleanupNone));
}

#pragma mark - Unmanaged

- (void)testNothingIsRefusedWhenNothingElseManagesPolicy {
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(nil, 0, NO, NO, SNTRuleCleanupNone));
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(nil, 0, NO, NO, SNTRuleCleanupAll));
  XCTAssertFalse(SNTCommandRuleChangesAreRefused(nil, 0, NO, YES, SNTRuleCleanupNone));
}

@end
