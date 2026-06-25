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

- (void)testUniqueIDCoarseOnRuleAndProcess {
  SNTStoredNetworkFlowEvent* e = [[SNTStoredNetworkFlowEvent alloc] init];
  e.ruleId = 42;
  e.process.cdhash = @"cd00";
  e.remoteAddress = @"1.2.3.4";  // destination must NOT affect uniqueID
  XCTAssertEqualObjects([e uniqueID], @"42|cd00");

  e.remoteAddress = @"9.9.9.9";  // different destination, same key
  XCTAssertEqualObjects([e uniqueID], @"42|cd00");

  e.process.cdhash = nil;  // falls back to signingID
  e.process.signingID = @"com.example.app";
  XCTAssertEqualObjects([e uniqueID], @"42|com.example.app");
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
  e.ruleId = 7;
  e.competingRuleIds = @[ @(3), @(5) ];
  e.totalCompetingRuleCount = 12;
  e.silent = YES;
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
  XCTAssertEqual(d.ruleId, 7);
  XCTAssertEqualObjects(d.competingRuleIds, (@[ @(3), @(5) ]));
  XCTAssertEqual(d.totalCompetingRuleCount, 12u);
  XCTAssertTrue(d.silent);  // local field survives the round-trip
  XCTAssertEqualObjects(d.process.filePath, @"/usr/bin/curl");
  XCTAssertEqualObjects(d.process.parent.pid, @(1));
}

@end
