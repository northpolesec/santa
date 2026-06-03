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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/common/AuditUtilities.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTRule.h"
#import "Source/common/TestUtils.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTRunningProcessRuleEvaluator.h"

static NSString* const kBinarySHA256 =
    @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

@interface SNTRunningProcessRuleEvaluatorTest : XCTestCase
@property id mockRuleTable;
@property id mockDecisionCache;
@end

@implementation SNTRunningProcessRuleEvaluatorTest

- (void)setUp {
  [super setUp];
  self.mockRuleTable = OCMClassMock([SNTRuleTable class]);
  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);
  OCMStub([self.mockRuleTable criticalSystemBinaries]).andReturn(@{});
}

- (void)tearDown {
  [self.mockRuleTable stopMocking];
  [self.mockDecisionCache stopMocking];
  [super tearDown];
}

- (SNTRule*)ruleWithState:(SNTRuleState)state
     runningProcessAction:(SNTRuleRunningProcessAction)runningProcessAction {
  return [[SNTRule alloc] initWithIdentifier:kBinarySHA256
                                       state:state
                                        type:SNTRuleTypeBinary
                                   customMsg:nil
                                   customURL:nil
                                   timestamp:0
                                     comment:nil
                                     celExpr:nil
                              seatbeltPolicy:nil
                                      ruleId:0
                        runningProcessAction:runningProcessAction
                                       error:nil];
}

- (SNTRunningProcessRuleEvaluator*)evaluatorWithRule:(SNTRule*)rule
                                           killBlock:(SNTRunningProcessKillBlock)killBlock {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = kBinarySHA256;
  OCMStub([self.mockDecisionCache rehydrateAndCacheDecisionForFileInfo:OCMOCK_ANY]).andReturn(cd);
  OCMStub([self.mockRuleTable executionRuleForIdentifiers:(struct RuleIdentifiers){}])
      .ignoringNonObjectArgs()
      .andReturn(rule);

  return [[SNTRunningProcessRuleEvaluator alloc] initWithRuleTable:self.mockRuleTable
      decisionCache:self.mockDecisionCache
      processListBlock:^NSArray<NSNumber*>* {
        return @[ @42 ];
      }
      pathForBlock:^NSString*(pid_t) {
        return @"/bin/ls";
      }
      auditTokenBlock:^BOOL(pid_t pid, audit_token_t* token) {
        *token = MakeAuditToken(pid, 7);
        return YES;
      }
      killBlock:killBlock];
}

- (void)testForceKillRuleKillsMatchingProcess {
  __block SNTKillRequestRunningProcess* killedRequest = nil;
  SNTRunningProcessRuleEvaluator* evaluator =
      [self evaluatorWithRule:[self ruleWithState:SNTRuleStateBlock
                                  runningProcessAction:SNTRuleRunningProcessActionForceKill]
                    killBlock:^SNTKillResponse*(SNTKillRequestRunningProcess* request) {
                      killedRequest = request;
                      SNTKilledProcess* proc =
                          [[SNTKilledProcess alloc] initWithPid:request.pid
                                                     pidversion:request.pidversion
                                                          error:SNTKilledProcessErrorNone];
                      return [[SNTKillResponse alloc] initWithKilledProcesses:@[ proc ]];
                    }];

  [evaluator reevaluateRunningProcessesSyncForTesting];

  XCTAssertNotNil(killedRequest);
  XCTAssertEqual(killedRequest.pid, 42);
  XCTAssertEqual(killedRequest.pidversion, 7);
}

- (void)testUnsetActionDoesNotKill {
  __block NSUInteger killCount = 0;
  SNTRunningProcessRuleEvaluator* evaluator =
      [self evaluatorWithRule:[self ruleWithState:SNTRuleStateBlock
                                  runningProcessAction:SNTRuleRunningProcessActionUnset]
                    killBlock:^SNTKillResponse*(SNTKillRequestRunningProcess*) {
                      killCount++;
                      return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
                    }];

  [evaluator reevaluateRunningProcessesSyncForTesting];

  XCTAssertEqual(killCount, 0u);
}

- (void)testPidversionChangeSkipsKill {
  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = kBinarySHA256;
  OCMStub([self.mockDecisionCache rehydrateAndCacheDecisionForFileInfo:OCMOCK_ANY]).andReturn(cd);
  OCMStub([self.mockRuleTable executionRuleForIdentifiers:(struct RuleIdentifiers){}])
      .ignoringNonObjectArgs()
      .andReturn([self ruleWithState:SNTRuleStateBlock
                runningProcessAction:SNTRuleRunningProcessActionForceKill]);

  __block NSUInteger tokenCalls = 0;
  __block NSUInteger killCount = 0;
  SNTRunningProcessRuleEvaluator* evaluator =
      [[SNTRunningProcessRuleEvaluator alloc] initWithRuleTable:self.mockRuleTable
          decisionCache:self.mockDecisionCache
          processListBlock:^NSArray<NSNumber*>* {
            return @[ @42 ];
          }
          pathForBlock:^NSString*(pid_t) {
            return @"/bin/ls";
          }
          auditTokenBlock:^BOOL(pid_t pid, audit_token_t* token) {
            *token = MakeAuditToken(pid, tokenCalls++ == 0 ? 7 : 8);
            return YES;
          }
          killBlock:^SNTKillResponse*(SNTKillRequestRunningProcess*) {
            killCount++;
            return [[SNTKillResponse alloc] initWithKilledProcesses:@[]];
          }];

  [evaluator reevaluateRunningProcessesSyncForTesting];

  XCTAssertEqual(killCount, 0u);
}

@end
