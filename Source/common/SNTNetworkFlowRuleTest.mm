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

#import "Source/common/SNTNetworkFlowRule.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTNetworkFlowRule (Testing)
@property(readwrite, copy) NSString* ruleName;
@property(readwrite) int64_t ruleId;
@property(readwrite) SNTNetworkFlowRuleState state;
@property(readwrite, copy) NSData* protoBlob;
@end

@interface SNTNetworkFlowRuleTest : XCTestCase
@end

@implementation SNTNetworkFlowRuleTest

- (void)testAddRuleCarriesBlob {
  NSData* blob = [@"fake-proto-bytes" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkFlowRule* rule = [[SNTNetworkFlowRule alloc] initAddRuleWithName:@"rule-a"
                                                                      ruleId:42
                                                                   protoBlob:blob];
  XCTAssertNotNil(rule);
  XCTAssertEqualObjects(rule.ruleName, @"rule-a");
  XCTAssertEqual(rule.ruleId, 42);
  XCTAssertEqual(rule.state, SNTNetworkFlowRuleStateAdd);
  XCTAssertEqualObjects(rule.protoBlob, blob);
}

- (void)testAddRuleRejectsNilBlob {
  SNTNetworkFlowRule* rule = [[SNTNetworkFlowRule alloc] initAddRuleWithName:@"rule-a"
                                                                      ruleId:42
                                                                   protoBlob:nil];
  XCTAssertNil(rule);
}

- (void)testAddRuleRejectsEmptyName {
  NSData* blob = [@"abc" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertNil([[SNTNetworkFlowRule alloc] initAddRuleWithName:@"" ruleId:42 protoBlob:blob]);
  XCTAssertNil([[SNTNetworkFlowRule alloc] initAddRuleWithName:nil ruleId:42 protoBlob:blob]);
}

- (void)testRemoveRuleHasNilBlob {
  SNTNetworkFlowRule* rule = [[SNTNetworkFlowRule alloc] initRemoveRuleWithName:@"rule-b"];
  XCTAssertNotNil(rule);
  XCTAssertEqualObjects(rule.ruleName, @"rule-b");
  XCTAssertEqual(rule.state, SNTNetworkFlowRuleStateRemove);
  XCTAssertNil(rule.protoBlob);
}

- (void)testRemoveRuleRejectsEmptyName {
  XCTAssertNil([[SNTNetworkFlowRule alloc] initRemoveRuleWithName:@""]);
  XCTAssertNil([[SNTNetworkFlowRule alloc] initRemoveRuleWithName:nil]);
}

- (void)testNSSecureCodingRoundTripAdd {
  NSData* blob = [@"abc" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkFlowRule* orig = [[SNTNetworkFlowRule alloc] initAddRuleWithName:@"rule-c"
                                                                      ruleId:7
                                                                   protoBlob:blob];
  NSError* err = nil;
  NSData* archived = [NSKeyedArchiver archivedDataWithRootObject:orig
                                           requiringSecureCoding:YES
                                                           error:&err];
  XCTAssertNil(err);
  XCTAssertNotNil(archived);

  SNTNetworkFlowRule* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkFlowRule class]
                                        fromData:archived
                                           error:&err];
  XCTAssertNil(err);
  XCTAssertEqualObjects(decoded.ruleName, @"rule-c");
  XCTAssertEqual(decoded.ruleId, 7);
  XCTAssertEqual(decoded.state, SNTNetworkFlowRuleStateAdd);
  XCTAssertEqualObjects(decoded.protoBlob, blob);
}

- (void)testNSSecureCodingRoundTripRemove {
  SNTNetworkFlowRule* orig = [[SNTNetworkFlowRule alloc] initRemoveRuleWithName:@"rule-d"];
  NSError* err = nil;
  NSData* archived = [NSKeyedArchiver archivedDataWithRootObject:orig
                                           requiringSecureCoding:YES
                                                           error:&err];
  XCTAssertNil(err);
  XCTAssertNotNil(archived);

  SNTNetworkFlowRule* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkFlowRule class]
                                        fromData:archived
                                           error:&err];
  XCTAssertNil(err);
  XCTAssertEqualObjects(decoded.ruleName, @"rule-d");
  XCTAssertEqual(decoded.state, SNTNetworkFlowRuleStateRemove);
  XCTAssertNil(decoded.protoBlob);
}

- (void)testProtoBlobIsCopied {
  NSMutableData* blob = [[@"abc" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  SNTNetworkFlowRule* rule = [[SNTNetworkFlowRule alloc] initAddRuleWithName:@"rule-e"
                                                                      ruleId:1
                                                                   protoBlob:blob];
  [blob appendBytes:"xyz" length:3];
  XCTAssertEqual(rule.protoBlob.length, 3u);
}

- (void)testDecodeRejectsUnspecifiedState {
  // Build a valid rule, stomp its state to Unspecified, archive, and verify
  // that decode refuses to reconstruct it.
  SNTNetworkFlowRule* corrupt = [[SNTNetworkFlowRule alloc] initRemoveRuleWithName:@"rule-f"];
  corrupt.state = SNTNetworkFlowRuleStateUnspecified;
  NSError* err = nil;
  NSData* archived = [NSKeyedArchiver archivedDataWithRootObject:corrupt
                                           requiringSecureCoding:YES
                                                           error:&err];
  XCTAssertNil(err);
  XCTAssertNotNil(archived);

  SNTNetworkFlowRule* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkFlowRule class]
                                        fromData:archived
                                           error:&err];
  XCTAssertNil(decoded);
}

@end
