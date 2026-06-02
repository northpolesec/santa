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

#import "Source/common/SNTCELFallbackRule.h"

@interface SNTCELFallbackRuleTest : XCTestCase
@end

@implementation SNTCELFallbackRuleTest

- (SNTCELFallbackRule*)ruleWithExpr:(NSString*)expr {
  return [[SNTCELFallbackRule alloc] initWithCELExpr:expr customMsg:@"msg" customURL:@"https://x"];
}

- (void)testEqualRulesAreEqualAndShareHash {
  SNTCELFallbackRule* a = [self ruleWithExpr:@"true"];
  SNTCELFallbackRule* b = [self ruleWithExpr:@"true"];

  XCTAssertEqualObjects(a, b);
  XCTAssertEqual(a.hash, b.hash);
}

- (void)testDifferingFieldsAreNotEqual {
  SNTCELFallbackRule* base = [[SNTCELFallbackRule alloc] initWithCELExpr:@"true"
                                                               customMsg:@"msg"
                                                               customURL:@"https://x"];

  XCTAssertNotEqualObjects(base, [[SNTCELFallbackRule alloc] initWithCELExpr:@"false"
                                                                   customMsg:@"msg"
                                                                   customURL:@"https://x"]);
  XCTAssertNotEqualObjects(base, [[SNTCELFallbackRule alloc] initWithCELExpr:@"true"
                                                                   customMsg:@"other"
                                                                   customURL:@"https://x"]);
  XCTAssertNotEqualObjects(base, [[SNTCELFallbackRule alloc] initWithCELExpr:@"true"
                                                                   customMsg:@"msg"
                                                                   customURL:@"https://y"]);
}

- (void)testNilOptionalFields {
  SNTCELFallbackRule* a = [[SNTCELFallbackRule alloc] initWithCELExpr:@"true"
                                                            customMsg:nil
                                                            customURL:nil];
  SNTCELFallbackRule* b = [[SNTCELFallbackRule alloc] initWithCELExpr:@"true"
                                                            customMsg:nil
                                                            customURL:nil];
  XCTAssertEqualObjects(a, b);
  XCTAssertEqual(a.hash, b.hash);

  // A nil optional field is not equal to a populated one.
  XCTAssertNotEqualObjects(a, [[SNTCELFallbackRule alloc] initWithCELExpr:@"true"
                                                                customMsg:@"msg"
                                                                customURL:nil]);
}

- (void)testNotEqualToOtherTypesOrNil {
  SNTCELFallbackRule* a = [self ruleWithExpr:@"true"];
  XCTAssertNotEqualObjects(a, @"true");
  XCTAssertNotEqualObjects(a, nil);
}

// The celFallbackRules KVO guard in SNTPolicyProcessor compares the freshly
// deserialized array against the previous one via isEqualToArray:. That only
// short-circuits redundant CEL recompilation if value equality survives a
// serialize/deserialize round trip, so lock that in.
- (void)testEqualitySurvivesSerializationRoundTrip {
  NSArray<SNTCELFallbackRule*>* original = @[
    [[SNTCELFallbackRule alloc] initWithCELExpr:@"true" customMsg:@"msg" customURL:@"https://x"],
    [[SNTCELFallbackRule alloc] initWithCELExpr:@"false" customMsg:nil customURL:nil],
  ];

  NSData* data = [SNTCELFallbackRule serializeArray:original];
  XCTAssertNotNil(data);

  NSArray<SNTCELFallbackRule*>* roundTripped = [SNTCELFallbackRule deserializeArray:data];

  // Fresh object identities, equal by value.
  XCTAssertFalse(original[0] == roundTripped[0]);
  XCTAssertEqualObjects(original, roundTripped);
  XCTAssertTrue([original isEqualToArray:roundTripped]);

  // A genuine change is detected.
  NSArray<SNTCELFallbackRule*>* changed = @[
    [[SNTCELFallbackRule alloc] initWithCELExpr:@"true" customMsg:@"msg" customURL:@"https://x"],
    [[SNTCELFallbackRule alloc] initWithCELExpr:@"1 == 2" customMsg:nil customURL:nil],
  ];
  XCTAssertFalse([changed isEqualToArray:roundTripped]);
}

@end
