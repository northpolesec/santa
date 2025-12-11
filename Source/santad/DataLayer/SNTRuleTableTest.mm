
/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <stdint.h>
#include "Source/common/SNTError.h"

#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#include "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileAccessRule.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SigningIDHelpers.h"
#import "Source/common/TestUtils.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

/// This test case actually tests SNTRuleTable and SNTRule
@interface SNTRuleTableTest : XCTestCase
@property SNTRuleTable *sut;
@property FMDatabaseQueue *dbq;
@property id mockConfigurator;
@end

@interface SNTRule ()
// Making these properties readwrite makes some tests much easier to write.
@property(readwrite) SNTRuleState state;
@property(readwrite) SNTRuleType type;
@property(readwrite) NSString *customMsg;
@property(readwrite) NSString *identifier;
@property(readwrite) NSString *celExpr;
@end

@implementation SNTRuleTableTest

- (void)setUp {
  [super setUp];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.sut = [[SNTRuleTable alloc] initWithDatabaseQueue:self.dbq];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
}

- (SNTRule *)_exampleTeamIDRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"ABCDEFGHIJ";
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeTeamID;
  r.customMsg = @"A teamID rule";
  return r;
}

- (SNTRule *)_exampleSigningIDRuleIsPlatform:(BOOL)isPlatformBinary {
  SNTRule *r = [[SNTRule alloc] init];
  if (isPlatformBinary) {
    r.identifier = @"platform:signingID";
  } else {
    r.identifier = @"ABCDEFGHIJ:signingID";
  }
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeSigningID;
  r.customMsg = @"A signingID rule";
  return r;
}

- (SNTRule *)_exampleCDHashRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a";
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeCDHash;
  r.customMsg = @"A cdhash rule";
  return r;
}

- (SNTRule *)_exampleBinaryRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670";
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeBinary;
  r.customMsg = @"A rule";
  return r;
}

- (SNTRule *)_exampleTransitiveRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"1111e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b111";
  r.state = SNTRuleStateAllowTransitive;
  r.type = SNTRuleTypeBinary;
  r.customMsg = @"Transitive rule";
  return r;
}

- (SNTRule *)_exampleCertRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258";
  r.state = SNTRuleStateAllow;
  r.type = SNTRuleTypeCertificate;
  return r;
}

- (SNTFileAccessRule *)_exampleFileAccessAddRuleWithName:(NSString *)name {
  return [[SNTFileAccessRule alloc]
      initAddRuleWithName:name
                  details:@{@"Paths" : @[ @"/tmp" ], @"Options" : @{}, @"Processes" : @{}}];
}

- (SNTFileAccessRule *)_exampleFileAccessRemoveRuleWithName:(NSString *)name {
  return [[SNTFileAccessRule alloc] initRemoveRuleWithName:name];
}

- (void)testAddRulesNotClean {
  NSUInteger executionRuleCount = self.sut.executionRuleCount;
  NSUInteger binaryRuleCount = self.sut.binaryRuleCount;

  NSArray<NSError *> *errors;
  [self.sut addExecutionRules:@[ [self _exampleBinaryRule] ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];

  XCTAssertEqual(self.sut.executionRuleCount, executionRuleCount + 1);
  XCTAssertEqual(self.sut.binaryRuleCount, binaryRuleCount + 1);
  XCTAssertNil(errors);
}

- (void)testAddRulesClean {
  // Add a binary rule without clean slate
  NSArray<NSError *> *errors;
  XCTAssertTrue([self.sut addExecutionRules:@[ [self _exampleBinaryRule] ]
                                ruleCleanup:SNTRuleCleanupNone
                                     errors:&errors]);
  XCTAssertNil(errors);

  // Now add a cert rule with a clean slate, assert that the binary rule was removed
  XCTAssertTrue(([self.sut addExecutionRules:@[ [self _exampleCertRule] ]
                                 ruleCleanup:SNTRuleCleanupAll
                                      errors:&errors]));
  XCTAssertEqual([self.sut binaryRuleCount], 0);
  XCTAssertNil(errors);
}

- (void)testAddRulesCleanNonTransitive {
  // Add a multiple binary rules, including a transitive rule
  NSArray<NSError *> *errors;
  XCTAssertTrue(([self.sut addExecutionRules:@[
    [self _exampleBinaryRule], [self _exampleCertRule], [self _exampleTransitiveRule]
  ]
                                 ruleCleanup:SNTRuleCleanupNone
                                      errors:&errors]));
  XCTAssertEqual([self.sut binaryRuleCount], 2);
  XCTAssertNil(errors);

  // Now add a cert rule while cleaning non-transitive rules. Ensure the transitive rule remains
  XCTAssertTrue(([self.sut addExecutionRules:@[ [self _exampleCertRule] ]
                                 ruleCleanup:SNTRuleCleanupNonTransitive
                                      errors:&errors]));
  XCTAssertEqual([self.sut binaryRuleCount], 1);
  XCTAssertEqual([self.sut certificateRuleCount], 1);
  XCTAssertNil(errors);
}

- (void)testAddMultipleRules {
  NSUInteger executionRuleCount = self.sut.executionRuleCount;

  NSArray<NSError *> *errors;
  [self.sut addExecutionRules:@[
    [self _exampleBinaryRule], [self _exampleCertRule], [self _exampleBinaryRule]
  ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];

  XCTAssertEqual(self.sut.executionRuleCount, executionRuleCount + 2);
  XCTAssertNil(errors);
}

- (void)testAddRulesEmptyArray {
  NSArray<NSError *> *errors;
  XCTAssertFalse([self.sut addExecutionRules:@[] ruleCleanup:SNTRuleCleanupNone errors:&errors]);
  XCTAssertEqual(errors.count, 1);
  XCTAssertEqual(errors.firstObject.code, SNTErrorCodeEmptyRuleArray);
}

- (void)testAddRulesNilArray {
  NSArray<NSError *> *errors;
  XCTAssertFalse([self.sut addExecutionRules:nil ruleCleanup:SNTRuleCleanupNone errors:&errors]);
  XCTAssertEqual(errors.count, 1);
  XCTAssertEqual(errors.firstObject.code, SNTErrorCodeEmptyRuleArray);
}

- (void)testAddExecutionAndFileAccessRulesEmptyArray {
  NSArray<NSError *> *errors;
  XCTAssertFalse([self.sut addExecutionRules:@[]
                             fileAccessRules:@[]
                                 ruleCleanup:SNTRuleCleanupNone
                                      errors:&errors]);
  XCTAssertEqual(errors.count, 1);
  XCTAssertEqual(errors.firstObject.code, SNTErrorCodeEmptyRuleArray);
}

- (void)testAddInvalidRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258";
  r.type = SNTRuleTypeCertificate;

  NSArray<NSError *> *errors;
  XCTAssertFalse([self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors]);
  XCTAssertEqual(errors.count, 1);
  XCTAssertEqual(errors.firstObject.code, SNTErrorCodeRuleInvalid);
}

- (void)testAddInvalidCELExpression {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258";
  r.type = SNTRuleTypeCertificate;
  r.state = SNTRuleStateCEL;
  r.celExpr = @"this is an invalid expression";

  NSArray<NSError *> *errors;
  XCTAssertTrue([self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors]);
  XCTAssertEqual(errors.count, 1);
  XCTAssertEqual(errors.firstObject.code, SNTErrorCodeRuleInvalidCELExpression);
}

- (void)testAddRemoveFetchFileAccessRule {
  // Add some file access rules
  NSArray<NSError *> *errors;
  SNTFileAccessRule *r1 = [self _exampleFileAccessAddRuleWithName:@"my_first_rule"];
  SNTFileAccessRule *r2 = [self _exampleFileAccessAddRuleWithName:@"my_second_rule"];
  [self.sut addExecutionRules:@[]
              fileAccessRules:@[ r1 ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 0);
  XCTAssertEqual(self.sut.fileAccessRuleCount, 1);

  [self.sut addExecutionRules:@[]
              fileAccessRules:@[ r2 ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 0);
  XCTAssertEqual(self.sut.fileAccessRuleCount, 2);

  // Ensure both rules exist
  NSDictionary *rules = [self.sut retrieveAllFileAccessRules];
  XCTAssertEqual(rules.count, 2);
  XCTAssertTrue([rules[@"my_first_rule"] isKindOfClass:[NSDictionary class]]);
  XCTAssertTrue([rules[@"my_second_rule"] isKindOfClass:[NSDictionary class]]);

  // Now remove the first rule
  SNTFileAccessRule *r3 = [self _exampleFileAccessRemoveRuleWithName:r1.name];
  [self.sut addExecutionRules:@[]
              fileAccessRules:@[ r3 ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 0);
  XCTAssertEqual(self.sut.fileAccessRuleCount, 1);

  // Ensure the other rule still exists
  rules = [self.sut retrieveAllFileAccessRules];
  XCTAssertEqual(rules.count, 1);
  XCTAssertTrue([rules[@"my_second_rule"] isKindOfClass:[NSDictionary class]]);
}

- (void)testAddRemoveExecutionAndFileAccessRules {
  // Add both rule types simultaneously
  NSArray<NSError *> *errors;
  SNTRule *execRule = [self _exampleBinaryRule];
  SNTFileAccessRule *faaRule = [self _exampleFileAccessAddRuleWithName:@"foo"];

  __block int64_t ruleCount;
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  self.sut.fileAccessRulesChangedCallback = ^(int64_t count) {
    ruleCount = count;
    dispatch_semaphore_signal(sema);
  };

  [self.sut addExecutionRules:@[ execRule ]
              fileAccessRules:@[ faaRule ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];

  XCTAssertSemaTrue(sema, 0, "Rules changed callback was not called");
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.fileAccessRuleCount, 1);
  XCTAssertEqual(ruleCount, 1);

  // Re-add an exec rule that shouldn't trigger file access rule changed callback
  [self.sut addExecutionRules:@[ execRule ]
              fileAccessRules:@[]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];
  XCTAssertSemaFalse(sema, "Rules changed callback was unexpectedly called");
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.fileAccessRuleCount, 1);

  // Now remove both rule types
  execRule.state = SNTRuleStateRemove;
  faaRule = [self _exampleFileAccessRemoveRuleWithName:faaRule.name];
  [self.sut addExecutionRules:@[ execRule ]
              fileAccessRules:@[ faaRule ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&errors];

  XCTAssertSemaTrue(sema, 0, "Rules changed callback was not called");
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 0);
  XCTAssertEqual(self.sut.fileAccessRuleCount, 0);
  XCTAssertEqual(ruleCount, 0);
}

- (void)testFetchBinaryRule {
  [self.sut addExecutionRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];

  SNTRule *r = [self.sut
      executionRuleForIdentifiers:
          (struct RuleIdentifiers){
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
          }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(r.type, SNTRuleTypeBinary);

  r = [self.sut
      executionRuleForIdentifiers:
          (struct RuleIdentifiers){
              .binarySHA256 = @"b6ee1c3c5a715c049d14a8457faa6b6701b8507efe908300e238e0768bd759c2",
          }];
  XCTAssertNil(r);
}

- (void)testFetchCertificateRule {
  [self.sut addExecutionRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];

  SNTRule *r =
      [self.sut executionRuleForIdentifiers:
                    (struct RuleIdentifiers){
                        .certificateSHA256 =
                            @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
                    }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258");
  XCTAssertEqual(r.type, SNTRuleTypeCertificate);

  r = [self.sut executionRuleForIdentifiers:
                    (struct RuleIdentifiers){
                        .certificateSHA256 =
                            @"5bdab1288fc16892fef50c658db54f1e2e19cf8f71cc55f77de2b95e051e2562",
                    }];
  XCTAssertNil(r);
}

- (void)testFetchTeamIDRule {
  [self.sut addExecutionRules:@[ [self _exampleBinaryRule], [self _exampleTeamIDRule] ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];

  SNTRule *r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                         .teamID = @"ABCDEFGHIJ",
                                                     }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(r.type, SNTRuleTypeTeamID);
  XCTAssertEqual([self.sut teamIDRuleCount], 1);

  r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                .teamID = @"nonexistentTeamID",
                                            }];
  XCTAssertNil(r);
}

- (void)testFetchSigningIDRule {
  [self.sut addExecutionRules:@[
    [self _exampleBinaryRule], [self _exampleSigningIDRuleIsPlatform:YES],
    [self _exampleSigningIDRuleIsPlatform:NO]
  ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];

  XCTAssertEqual([self.sut signingIDRuleCount], 2);

  SNTRule *r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                         .signingID = @"ABCDEFGHIJ:signingID",
                                                     }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ:signingID");
  XCTAssertEqual(r.type, SNTRuleTypeSigningID);

  r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                .signingID = @"platform:signingID",
                                            }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"platform:signingID");
  XCTAssertEqual(r.type, SNTRuleTypeSigningID);

  r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                .signingID = @"nonexistent",
                                            }];
  XCTAssertNil(r);
}

- (void)testFetchCDHashRule {
  [self.sut addExecutionRules:@[
    [self _exampleBinaryRule], [self _exampleTeamIDRule], [self _exampleCDHashRule]
  ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];

  XCTAssertEqual([self.sut cdhashRuleCount], 1);

  SNTRule *r = [self.sut
      executionRuleForIdentifiers:(struct RuleIdentifiers){
                                      .cdhash = @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a",
                                  }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a");
  XCTAssertEqual(r.type, SNTRuleTypeCDHash);

  r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                .cdhash = @"nonexistent",
                                            }];
  XCTAssertNil(r);
}

- (void)testFetchRuleOrdering {
  NSArray<NSError *> *err;
  [self.sut addExecutionRules:@[
    [self _exampleCertRule],
    [self _exampleBinaryRule],
    [self _exampleTeamIDRule],
    [self _exampleSigningIDRuleIsPlatform:NO],
    [self _exampleCDHashRule],
  ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:&err];
  XCTAssertNil(err);

  // This test is only concerend about sqlite's behavior. Ensure static rules are ignored.
  [self.sut updateStaticRules:nil];

  // This test verifies that the implicit rule ordering we've been abusing is still working.
  // See the comment in SNTRuleTable#executionRuleForIdentifiers:
  SNTRule *r = [self.sut
      executionRuleForIdentifiers:
          (struct RuleIdentifiers){
              .cdhash = @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a",
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
              .signingID = @"ABCDEFGHIJ:signingID",
              .certificateSHA256 =
                  @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
              .teamID = @"ABCDEFGHIJ",
          }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a");
  XCTAssertEqual(r.type, SNTRuleTypeCDHash, @"Implicit rule ordering failed");

  r = [self.sut
      executionRuleForIdentifiers:
          (struct RuleIdentifiers){
              .cdhash = @"unknown",
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
              .signingID = @"ABCDEFGHIJ:signingID",
              .certificateSHA256 =
                  @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
              .teamID = @"ABCDEFGHIJ",
          }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(r.type, SNTRuleTypeBinary, @"Implicit rule ordering failed");

  r = [self.sut
      executionRuleForIdentifiers:
          (struct RuleIdentifiers){
              .cdhash = @"unknown",
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
              .signingID = @"ABCDEFGHIJ:signingID",
              .certificateSHA256 = @"unknown",
              .teamID = @"ABCDEFGHIJ",
          }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(r.type, SNTRuleTypeBinary, @"Implicit rule ordering failed");

  r = [self.sut executionRuleForIdentifiers:
                    (struct RuleIdentifiers){
                        .cdhash = @"unknown",
                        .binarySHA256 = @"unknown",
                        .signingID = @"unknown",
                        .certificateSHA256 =
                            @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
                        .teamID = @"ABCDEFGHIJ",
                    }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258");
  XCTAssertEqual(r.type, SNTRuleTypeCertificate, @"Implicit rule ordering failed");

  r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                .cdhash = @"unknown",
                                                .binarySHA256 = @"unknown",
                                                .signingID = @"ABCDEFGHIJ:signingID",
                                                .certificateSHA256 = @"unknown",
                                                .teamID = @"ABCDEFGHIJ",
                                            }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ:signingID");
  XCTAssertEqual(r.type, SNTRuleTypeSigningID, @"Implicit rule ordering failed (SigningID)");

  r = [self.sut executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                .cdhash = @"unknown",
                                                .binarySHA256 = @"unknown",
                                                .signingID = @"unknown",
                                                .certificateSHA256 = @"unknown",
                                                .teamID = @"ABCDEFGHIJ",
                                            }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(r.type, SNTRuleTypeTeamID, @"Implicit rule ordering failed (TeamID)");
}

- (void)testBadDatabase {
  NSString *dbPath = [NSTemporaryDirectory() stringByAppendingString:@"sntruletabletest_baddb.db"];
  [@"some text" writeToFile:dbPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

  FMDatabaseQueue *dbq = [[FMDatabaseQueue alloc] initWithPath:dbPath];
  SNTRuleTable *sut = [[SNTRuleTable alloc] initWithDatabaseQueue:dbq];

  [sut addExecutionRules:@[ [self _exampleBinaryRule] ] ruleCleanup:SNTRuleCleanupNone errors:nil];
  XCTAssertGreaterThan(sut.executionRuleCount, 0);

  [[NSFileManager defaultManager] removeItemAtPath:dbPath error:NULL];
}

- (void)testRetrieveAllRulesWithEmptyDatabase {
  NSArray<SNTRule *> *rules = [self.sut retrieveAllExecutionRules];
  XCTAssertEqual(rules.count, 0);
}

- (void)testRetrieveAllRulesWithMultipleRules {
  [self.sut addExecutionRules:@[
    [self _exampleCertRule],
    [self _exampleBinaryRule],
    [self _exampleTeamIDRule],
    [self _exampleSigningIDRuleIsPlatform:NO],
    [self _exampleCDHashRule],
  ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];

  NSArray<SNTRule *> *rules = [self.sut retrieveAllExecutionRules];
  XCTAssertEqual(rules.count, 5);
  XCTAssertEqualObjects(rules[0], [self _exampleCertRule]);
  XCTAssertEqualObjects(rules[1], [self _exampleBinaryRule]);
  XCTAssertEqualObjects(rules[2], [self _exampleTeamIDRule]);
  XCTAssertEqualObjects(rules[3], [self _exampleSigningIDRuleIsPlatform:NO]);
  XCTAssertEqualObjects(rules[4], [self _exampleCDHashRule]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithNewBlockRule {
  // Ensure that a brand new block rule flushes the decision cache.
  NSArray<NSError *> *errors;
  SNTRule *r = [self _exampleBinaryRule];
  [self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);

  // Change the identifer so that the hash of a block rule is not found in the
  // db.
  r.identifier = @"bfff7d3f6c389ebf7a76a666c484d42ea447834901bc29141439ae7c7b96ff09";
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithOldBlockRule {
  // Ensure that adding a block rule that already exists in the database does
  // not flush the decision cache.
  NSArray<NSError *> *errors;
  SNTRule *r = [self _exampleBinaryRule];
  [self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
  XCTAssertEqual(NO, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithLargeNumberOfBlocks {
  // Ensure that a large number of blocks flushes the decision cache.
  NSArray<NSError *> *errors;
  SNTRule *r = [self _exampleBinaryRule];
  [self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
  NSMutableArray<SNTRule *> *newRules = [NSMutableArray array];
  for (int i = 0; i < 1000; i++) {
    newRules[i] = r;
  }

  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:newRules]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithCompilerRule {
  // Ensure that an allow rule that overrides a compiler rule flushes the
  // decision cache.
  NSArray<NSError *> *errors;
  SNTRule *r = [self _exampleBinaryRule];
  r.type = SNTRuleTypeBinary;
  r.state = SNTRuleStateAllowCompiler;
  [self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
  // make the rule an allow rule
  r.state = SNTRuleStateAllow;
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithRemoveRule {
  // Ensure that a Remove rule targeting an allow rule causes a flush of the cache.
  NSArray<NSError *> *errors;
  SNTRule *r = [self _exampleBinaryRule];
  r.type = SNTRuleTypeBinary;
  r.state = SNTRuleStateAllow;
  [self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);

  r.state = SNTRuleStateRemove;
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithCELRule {
  // Ensure that a CEL rule that already exists in the database does not flush
  // the decision cache...
  NSArray<NSError *> *errors;
  SNTRule *r = [self _exampleTeamIDRule];
  r.state = SNTRuleStateCEL;
  r.celExpr = @"args.size() == 1";
  [self.sut addExecutionRules:@[ r ] ruleCleanup:SNTRuleCleanupNone errors:&errors];
  XCTAssertNil(errors);
  XCTAssertEqual(self.sut.executionRuleCount, 1);
  XCTAssertEqual(self.sut.teamIDRuleCount, 1);

  XCTAssertEqual(NO, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);

  // Unless the CEL expression is different.
  r.celExpr = @"args.size() == 2";
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

- (void)testCriticalBinariesProduceFullSigningInformation {
  // Get the hash of the critical binary
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/usr/libexec/trustd"];
  MOLCodesignChecker *csInfo = [fi codesignCheckerWithError:nil];

  NSString *signingID = FormatSigningID(csInfo);
  NSString *teamID = [signingID componentsSeparatedByString:@":"][0];

  SNTCachedDecision *cd = self.sut.criticalSystemBinaries[signingID];

  XCTAssertEqualObjects(fi.SHA256, cd.sha256, @"hashes should match");
  XCTAssertEqualObjects(csInfo.leafCertificate.SHA256, cd.certSHA256, @"cert hashes should match");
  XCTAssertEqualObjects(csInfo.cdhash, cd.cdhash, @"cdhashes should match");
  XCTAssertEqualObjects(csInfo.certificates, cd.certChain, @"cert chains should match");
  XCTAssertEqualObjects(signingID, cd.signingID, @"signing IDs should match");
  XCTAssertEqualObjects(teamID, cd.teamID, @"team IDs should match");
}

- (void)testCriticalBinariesHaveCachedDecisionsKeyedOffSigningIDs {
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/usr/libexec/trustd"];
  MOLCodesignChecker *csInfo = [fi codesignCheckerWithError:nil];
  NSString *signingID = FormatSigningID(csInfo);
  NSString *teamID = [signingID componentsSeparatedByString:@":"][0];

  SNTCachedDecision *cd = self.sut.criticalSystemBinaries[signingID];
  XCTAssertNotNil(cd, @"critical binary should have a decision");

  XCTAssertEqualObjects(fi.SHA256, cd.sha256, @"hashes should match");
  XCTAssertEqual(SNTEventStateAllowSigningID, cd.decision, @"decision should be allow by binary");
  XCTAssertEqualObjects(csInfo.leafCertificate.SHA256, cd.certSHA256, @"cert hashes should match");
  XCTAssertEqualObjects(csInfo.cdhash, cd.cdhash, @"cdhashes should match");
  XCTAssertEqualObjects(csInfo.certificates, cd.certChain, @"cert chains should match");
  XCTAssertEqualObjects(signingID, cd.signingID, @"signing IDs should match");
  XCTAssertEqualObjects(teamID, cd.teamID, @"team IDs should match");
}

// This test ensures that we bump the constant on updates to the rule table
// schema.
- (void)testConstantVersionIsUpdated {
  XCTAssertEqual([self.sut currentSupportedVersion], [self.sut currentVersion],
                 @"initialized database should update to the maximum supported version");
}

- (void)testHashOfHashes {
  NSArray<SNTRule *> *rules = @[
    [self _exampleCertRule],
    [self _exampleBinaryRule],
    [self _exampleTeamIDRule],
    [self _exampleSigningIDRuleIsPlatform:NO],
  ];
  NSArray<SNTFileAccessRule *> *faaRules = @[
    [self _exampleFileAccessAddRuleWithName:@"MyFirstRule"],
    [self _exampleFileAccessAddRuleWithName:@"AnotherRule"],
  ];

  [self.sut addExecutionRules:rules
              fileAccessRules:faaRules
                  ruleCleanup:SNTRuleCleanupAll
                       errors:nil];
  SNTRuleTableRulesHash *rulesHash = [self.sut hashOfHashes];
  XCTAssertEqualObjects(rulesHash.executionRulesHash, @"a6cb5171bbb8895820d61e395592b293");
  XCTAssertEqualObjects(rulesHash.fileAccessRulesHash, @"010a7393bae8f2e97c296063dd2f39cf");

  // Add a transitive rule. The hashes should not change.
  SNTRule *transitiveRule = [self _exampleTransitiveRule];
  [self.sut addExecutionRules:@[ transitiveRule ] ruleCleanup:SNTRuleCleanupNone errors:nil];
  rulesHash = [self.sut hashOfHashes];
  XCTAssertEqualObjects(rulesHash.executionRulesHash, @"a6cb5171bbb8895820d61e395592b293");
  XCTAssertEqualObjects(rulesHash.fileAccessRulesHash, @"010a7393bae8f2e97c296063dd2f39cf");

  // Add remove rules. The hashes should change.
  SNTRule *removeRule = self._exampleBinaryRule;
  removeRule.state = SNTRuleStateRemove;
  SNTFileAccessRule *faaRemoveRule =
      [[SNTFileAccessRule alloc] initRemoveRuleWithName:@"AnotherRule"];
  [self.sut addExecutionRules:@[ removeRule ]
              fileAccessRules:@[ faaRemoveRule ]
                  ruleCleanup:SNTRuleCleanupNone
                       errors:nil];
  rulesHash = [self.sut hashOfHashes];
  XCTAssertEqualObjects(rulesHash.executionRulesHash, @"d4dd223bafbdda2c36bb0513dfabb38b");
  XCTAssertEqualObjects(rulesHash.fileAccessRulesHash, @"146f85d95d0d21d5c04d048b2b69f908");
}

@end
