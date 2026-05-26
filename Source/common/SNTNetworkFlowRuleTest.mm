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

@interface SNTNetworkFlowRuleTest : XCTestCase
@end

@implementation SNTNetworkFlowRuleTest

- (void)testAddRuleCarriesBlob {
  NSData* blob = [@"fake-proto-bytes" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkFlowRule* rule = [[SNTNetworkFlowRule alloc] initWithRuleId:42
                                                                  state:SNTNetworkFlowRuleStateAdd
                                                              protoBlob:blob];
  XCTAssertEqual(rule.ruleId, 42);
  XCTAssertEqual(rule.state, SNTNetworkFlowRuleStateAdd);
  XCTAssertEqualObjects(rule.protoBlob, blob);
}

- (void)testRemoveRuleHasNilBlob {
  SNTNetworkFlowRule* rule =
      [[SNTNetworkFlowRule alloc] initWithRuleId:99
                                           state:SNTNetworkFlowRuleStateRemove
                                       protoBlob:nil];
  XCTAssertEqual(rule.ruleId, 99);
  XCTAssertEqual(rule.state, SNTNetworkFlowRuleStateRemove);
  XCTAssertNil(rule.protoBlob);
}

- (void)testNSSecureCodingRoundTripAdd {
  NSData* blob = [@"abc" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkFlowRule* orig = [[SNTNetworkFlowRule alloc] initWithRuleId:7
                                                                  state:SNTNetworkFlowRuleStateAdd
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
  XCTAssertEqual(decoded.ruleId, 7);
  XCTAssertEqual(decoded.state, SNTNetworkFlowRuleStateAdd);
  XCTAssertEqualObjects(decoded.protoBlob, blob);
}

- (void)testNSSecureCodingRoundTripRemove {
  SNTNetworkFlowRule* orig =
      [[SNTNetworkFlowRule alloc] initWithRuleId:INT64_MAX
                                           state:SNTNetworkFlowRuleStateRemove
                                       protoBlob:nil];
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
  XCTAssertEqual(decoded.ruleId, INT64_MAX);
  XCTAssertEqual(decoded.state, SNTNetworkFlowRuleStateRemove);
  XCTAssertNil(decoded.protoBlob);
}

- (void)testProtoBlobIsCopied {
  NSMutableData* blob = [[@"abc" dataUsingEncoding:NSUTF8StringEncoding] mutableCopy];
  SNTNetworkFlowRule* rule = [[SNTNetworkFlowRule alloc] initWithRuleId:1
                                                                  state:SNTNetworkFlowRuleStateAdd
                                                              protoBlob:blob];
  [blob appendBytes:"xyz" length:3];
  XCTAssertEqual(rule.protoBlob.length, 3u);
}

@end
