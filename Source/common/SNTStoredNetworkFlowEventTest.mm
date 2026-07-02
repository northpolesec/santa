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

#import "Source/common/SNTStoredNetworkFlowEvent.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTStoredProcess.h"

@interface SNTStoredNetworkFlowEventTest : XCTestCase
@end

@implementation SNTStoredNetworkFlowEventTest

- (void)testUniqueIDReturnsEventDedupeKey {
  // uniqueID is an opaque pass-through of the santanetd-built event key; the
  // composition/dedup semantics are tested in santanetd, not here.
  SNTStoredNetworkFlowEvent* e = [[SNTStoredNetworkFlowEvent alloc] init];
  e.eventDedupeKey = @"TEAM:com.example.app|42|foo.com";
  e.remoteAddress = @"1.2.3.4";  // unrelated to the (opaque) key
  XCTAssertEqualObjects([e uniqueID], @"TEAM:com.example.app|42|foo.com");
}

- (void)testUnactionableAlwaysYes {
  XCTAssertTrue([[[SNTStoredNetworkFlowEvent alloc] init] unactionableEvent]);
}

- (void)testEncodeDecodeRoundTrip {
  SNTStoredNetworkFlowEvent* e = [[SNTStoredNetworkFlowEvent alloc] init];
  e.remoteAddress = @"93.184.216.34";
  e.remotePort = 443;
  e.localAddress = @"10.0.0.2";
  e.localPort = 51000;
  e.protocol = 6;
  e.socketFamily = SNTNetworkFlowSocketFamilyINET;
  e.direction = SNTNetworkFlowDirectionOutgoing;
  e.hostname = @"example.com";
  e.flowTime = [NSDate dateWithTimeIntervalSince1970:1700000000];
  e.decision = SNTNetworkFlowDecisionBlock;
  e.decisionTier = SNTNetworkFlowTierDomain;
  e.ruleId = 7;
  e.ruleName = @"block-example";
  e.competingRuleIds = @[ @(3), @(5) ];
  e.totalCompetingRuleCount = 12;
  e.eventDedupeKey = @"TEAM:com.apple.curl|7|example.com";
  e.uiDedupeKey = @"4242:1|7|example.com";
  e.silent = YES;
  e.customMsg = @"Contact IT before reaching this host";
  e.customURL = @"https://example.com/why?rule=%rule_name%";
  e.process.filePath = @"/usr/bin/curl";
  e.process.cdhash = @"deadbeef";
  e.process.parent = [[SNTStoredProcess alloc] init];
  e.process.parent.pid = @(1);

  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:e requiringSecureCoding:YES error:nil];
  XCTAssertNotNil(data);

  NSSet* allowed =
      [NSSet setWithObjects:[SNTStoredNetworkFlowEvent class], [SNTStoredProcess class], nil];
  SNTStoredEvent* out = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowed
                                                            fromData:data
                                                               error:nil];
  XCTAssertTrue([out isKindOfClass:[SNTStoredNetworkFlowEvent class]]);
  SNTStoredNetworkFlowEvent* d = (SNTStoredNetworkFlowEvent*)out;
  XCTAssertEqualObjects(d.remoteAddress, @"93.184.216.34");
  XCTAssertEqual(d.remotePort, 443);
  XCTAssertEqualObjects(d.localAddress, @"10.0.0.2");
  XCTAssertEqual(d.localPort, 51000);
  XCTAssertEqual(d.protocol, 6);
  XCTAssertEqual(d.socketFamily, SNTNetworkFlowSocketFamilyINET);
  XCTAssertEqual(d.direction, SNTNetworkFlowDirectionOutgoing);
  XCTAssertEqualObjects(d.hostname, @"example.com");
  XCTAssertEqualObjects(d.flowTime, [NSDate dateWithTimeIntervalSince1970:1700000000]);
  XCTAssertEqual(d.decision, SNTNetworkFlowDecisionBlock);
  XCTAssertEqual(d.decisionTier, SNTNetworkFlowTierDomain);
  XCTAssertEqual(d.ruleId, 7);
  XCTAssertEqualObjects(d.ruleName, @"block-example");
  XCTAssertEqualObjects(d.competingRuleIds, (@[ @(3), @(5) ]));
  XCTAssertEqual(d.totalCompetingRuleCount, 12u);
  XCTAssertEqualObjects(d.eventDedupeKey, @"TEAM:com.apple.curl|7|example.com");
  XCTAssertEqualObjects(d.uiDedupeKey, @"4242:1|7|example.com");
  XCTAssertTrue(d.silent);  // local field survives the round-trip
  XCTAssertEqualObjects(d.customMsg, @"Contact IT before reaching this host");
  XCTAssertEqualObjects(d.customURL, @"https://example.com/why?rule=%rule_name%");
  XCTAssertEqualObjects(d.process.filePath, @"/usr/bin/curl");
  XCTAssertEqualObjects(d.process.parent.pid, @(1));
  XCTAssertEqualObjects([d uniqueID],
                        @"TEAM:com.apple.curl|7|example.com");  // backed by eventDedupeKey
}

@end
