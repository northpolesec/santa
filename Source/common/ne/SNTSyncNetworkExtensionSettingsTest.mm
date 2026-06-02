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

#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface SNTSyncNetworkExtensionSettings (Testing)
@property(readwrite) BOOL enable;
@end

@interface SNTSyncNetworkExtensionSettingsTest : XCTestCase
@end

@implementation SNTSyncNetworkExtensionSettingsTest

- (void)testInitialization {
  // Test initialization with enable=YES
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  XCTAssertNotNil(settings);
  XCTAssertTrue(settings.enable);
  XCTAssertEqual(settings.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);

  // Test initialization with enable=NO
  settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:NO
                                            flowDefaultAction:SNTNetworkFlowDefaultActionAllow];
  XCTAssertNotNil(settings);
  XCTAssertFalse(settings.enable);
  XCTAssertEqual(settings.flowDefaultAction, SNTNetworkFlowDefaultActionAllow);
}

- (void)testEncodeDecodeSecureCoding {
  // Test with enable=YES
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  NSData* serialized = [settings serialize];
  XCTAssertNotNil(serialized);

  SNTSyncNetworkExtensionSettings* deserialized =
      [SNTSyncNetworkExtensionSettings deserialize:serialized];
  XCTAssertNotNil(deserialized);
  XCTAssertTrue(deserialized.enable);
  XCTAssertEqual(deserialized.enable, settings.enable);
  XCTAssertEqual(deserialized.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);
  XCTAssertEqualObjects(deserialized, settings);

  // Test with enable=NO
  settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:NO
                                            flowDefaultAction:SNTNetworkFlowDefaultActionAllow];
  serialized = [settings serialize];
  XCTAssertNotNil(serialized);

  deserialized = [SNTSyncNetworkExtensionSettings deserialize:serialized];
  XCTAssertNotNil(deserialized);
  XCTAssertFalse(deserialized.enable);
  XCTAssertEqual(deserialized.enable, settings.enable);
  XCTAssertEqual(deserialized.flowDefaultAction, SNTNetworkFlowDefaultActionAllow);
  XCTAssertEqualObjects(deserialized, settings);
}

- (void)testDeserializeNilData {
  // Test that deserializing nil data returns nil
  SNTSyncNetworkExtensionSettings* deserialized = [SNTSyncNetworkExtensionSettings deserialize:nil];
  XCTAssertNil(deserialized);
}

- (void)testDNSUpstreamTimeoutDefaultsToZeroWhenUnset {
  // The 2-arg convenience init leaves the carrier timeout at 0 ("unset").
  // Clamping/defaulting to 5s happens downstream in SNTNetworkExtensionSettings.
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  XCTAssertEqual(settings.dnsUpstreamTimeoutSecs, 0);
}

- (void)testDNSUpstreamTimeoutPreservedByDesignatedInit {
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                       dnsUpstreamTimeoutSecs:7.5];
  XCTAssertEqualWithAccuracy(settings.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
}

- (void)testDNSUpstreamTimeoutRoundTripsThroughCoder {
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                       dnsUpstreamTimeoutSecs:7.5];
  SNTSyncNetworkExtensionSettings* deserialized =
      [SNTSyncNetworkExtensionSettings deserialize:[settings serialize]];
  XCTAssertNotNil(deserialized);
  XCTAssertEqualWithAccuracy(deserialized.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
  XCTAssertEqualObjects(deserialized, settings);
}

- (void)testDNSUpstreamTimeoutDifferentiatesEquality {
  SNTSyncNetworkExtensionSettings* a =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                       dnsUpstreamTimeoutSecs:7.5];
  SNTSyncNetworkExtensionSettings* b =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:YES
                                            flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                       dnsUpstreamTimeoutSecs:3.0];
  XCTAssertNotEqualObjects(a, b);
}

@end
