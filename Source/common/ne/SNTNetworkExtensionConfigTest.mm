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

#import "Source/common/ne/SNTNetworkExtensionConfig.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTNetworkFlowRule.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"

@interface SNTNetworkExtensionConfigTest : XCTestCase
@end

@implementation SNTNetworkExtensionConfigTest

- (SNTNetworkExtensionConfig*)roundTrip:(SNTNetworkExtensionConfig*)config {
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:config
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);
  return [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionConfig class]
                                           fromData:data
                                              error:nil];
}

- (void)testInitializerStoresValues {
  SNTNetworkExtensionSettings* settings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  NSArray<SNTNetworkFlowRule*>* rules = @[
    [[SNTNetworkFlowRule alloc] initAddRuleWithId:1
                                        protoBlob:[@"x" dataUsingEncoding:NSUTF8StringEncoding]],
  ];

  SNTNetworkExtensionConfig* config = [[SNTNetworkExtensionConfig alloc] initWithSettings:settings
                                                                         networkFlowRules:rules];
  XCTAssertEqualObjects(config.settings, settings);
  XCTAssertEqual(config.networkFlowRules.count, 1u);
}

- (void)testRoundTripWithRules {
  SNTNetworkExtensionSettings* settings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  NSData* blob = [@"rule" dataUsingEncoding:NSUTF8StringEncoding];
  NSArray<SNTNetworkFlowRule*>* rules = @[
    [[SNTNetworkFlowRule alloc] initAddRuleWithId:1 protoBlob:blob],
    [[SNTNetworkFlowRule alloc] initAddRuleWithId:2 protoBlob:blob],
  ];

  SNTNetworkExtensionConfig* decoded =
      [self roundTrip:[[SNTNetworkExtensionConfig alloc] initWithSettings:settings
                                                         networkFlowRules:rules]];

  XCTAssertNotNil(decoded);
  XCTAssertTrue(decoded.settings.enable);
  XCTAssertEqual(decoded.settings.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);
  XCTAssertEqual(decoded.networkFlowRules.count, 2u);
  XCTAssertEqual(decoded.networkFlowRules[0].ruleId, 1);
  XCTAssertEqualObjects(decoded.networkFlowRules[0].protoBlob, blob);
}

- (void)testRoundTripWithNilRules {
  // nil rules (the "unchanged" runtime signal) must survive a round-trip as nil.
  SNTNetworkExtensionSettings* settings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:NO
                                        flowDefaultAction:SNTNetworkFlowDefaultActionAllow];

  SNTNetworkExtensionConfig* decoded = [self
      roundTrip:[[SNTNetworkExtensionConfig alloc] initWithSettings:settings networkFlowRules:nil]];

  XCTAssertNotNil(decoded);
  XCTAssertFalse(decoded.settings.enable);
  XCTAssertNil(decoded.networkFlowRules);
}

@end
