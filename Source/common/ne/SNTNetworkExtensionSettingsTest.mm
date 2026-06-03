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

#import "Source/common/ne/SNTNetworkExtensionSettings.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#import "Source/common/SNTNetworkFlowRule.h"

@interface SNTNetworkExtensionSettings (Testing)
@property(readwrite) BOOL enable;
@property(readwrite) SNTNetworkFlowDefaultAction flowDefaultAction;
@end

// Simulates a future version of SNTNetworkExtensionSettings that encodes an additional
// unknown key. Used in testForwardCompatibility to produce archive data with extra keys.
@interface SNTNetworkExtensionSettingsFuture : SNTNetworkExtensionSettings
@end

@implementation SNTNetworkExtensionSettingsFuture
- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  [coder encodeObject:@"futureValue" forKey:@"futureProperty"];
}
@end

// Simulates a legacy version of SNTNetworkExtensionSettings that predates the 'enable'
// property. Its encodeWithCoder: intentionally encodes nothing, producing an archive
// that omits the 'enable' key entirely.
@interface SNTNetworkExtensionSettingsLegacy : SNTNetworkExtensionSettings
@end

@implementation SNTNetworkExtensionSettingsLegacy
- (void)encodeWithCoder:(NSCoder*)coder {
}
@end

// A frozen replica of an older santanetd's decoder: it reads only `enable`, and its allowed-class
// set excludes NSArray/SNTNetworkFlowRule. Kept as a standalone NSObject (not a subclass of
// SNTNetworkExtensionSettings) so it can't inherit the current, rules-aware -initWithCoder: and
// quietly defeat the simulation.
@interface SNTDeployedNetworkExtensionSettingsReceiver : NSObject <NSSecureCoding>
@property(readonly) BOOL enable;
@end

@implementation SNTDeployedNetworkExtensionSettingsReceiver
+ (BOOL)supportsSecureCoding {
  return YES;
}
- (void)encodeWithCoder:(NSCoder*)coder {
  [coder encodeObject:@(_enable) forKey:@"enable"];
}
- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    // Reads only `enable`, matching the older decoder.
    _enable = [[decoder decodeObjectOfClass:[NSNumber class] forKey:@"enable"] boolValue];
  }
  return self;
}
@end

@interface SNTNetworkExtensionSettingsTest : XCTestCase
@end

@implementation SNTNetworkExtensionSettingsTest

- (void)testInitialization {
  SNTNetworkExtensionSettings* settings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  XCTAssertNotNil(settings);
  XCTAssertTrue(settings.enable);
  XCTAssertEqual(settings.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);

  settings = [[SNTNetworkExtensionSettings alloc] initWithEnable:NO
                                               flowDefaultAction:SNTNetworkFlowDefaultActionAllow];
  XCTAssertNotNil(settings);
  XCTAssertFalse(settings.enable);
  XCTAssertEqual(settings.flowDefaultAction, SNTNetworkFlowDefaultActionAllow);
}

- (void)testRoundtripEncodeDecode {
  SNTNetworkExtensionSettings* settings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:settings
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  SNTNetworkExtensionSettings* deserialized =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                        fromData:data
                                           error:nil];
  XCTAssertNotNil(deserialized);
  XCTAssertTrue(deserialized.enable);
  XCTAssertEqual(deserialized.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);

  settings = [[SNTNetworkExtensionSettings alloc] initWithEnable:NO
                                               flowDefaultAction:SNTNetworkFlowDefaultActionAllow];
  data = [NSKeyedArchiver archivedDataWithRootObject:settings requiringSecureCoding:YES error:nil];
  XCTAssertNotNil(data);

  deserialized = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                                   fromData:data
                                                      error:nil];
  XCTAssertNotNil(deserialized);
  XCTAssertFalse(deserialized.enable);
  XCTAssertEqual(deserialized.flowDefaultAction, SNTNetworkFlowDefaultActionAllow);
}

- (void)testForwardCompatibility {
  // Simulate a new sender encoding an archive with an unknown key.
  // Old receiver should decode successfully, ignoring the unknown key.
  //
  // SNTNetworkExtensionSettingsFuture is a stand-in for a hypothetical future version of
  // SNTNetworkExtensionSettings that adds an extra property. We archive it, then remap the
  // class name back to SNTNetworkExtensionSettings during decode to simulate an old receiver
  // processing data produced by a new sender.
  SNTNetworkExtensionSettingsFuture* future =
      [[SNTNetworkExtensionSettingsFuture alloc] initWithEnable:YES
                                              flowDefaultAction:SNTNetworkFlowDefaultActionAllow];

  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:future
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:data error:nil];
  unarchiver.requiresSecureCoding = YES;
  [unarchiver setClass:[SNTNetworkExtensionSettings class]
          forClassName:NSStringFromClass([SNTNetworkExtensionSettingsFuture class])];

  SNTNetworkExtensionSettings* deserialized =
      [unarchiver decodeObjectOfClass:[SNTNetworkExtensionSettings class]
                               forKey:NSKeyedArchiveRootObjectKey];
  [unarchiver finishDecoding];

  XCTAssertNotNil(deserialized);
  XCTAssertTrue(deserialized.enable);
}

- (void)testBackwardCompatibility {
  // Simulate an old sender that predates the 'enable' property.
  // New receiver should get default value (NO for BOOL) for the missing key.
  //
  // SNTNetworkExtensionSettingsLegacy encodes nothing, so the archive completely
  // omits the 'enable' key. We remap the class name to SNTNetworkExtensionSettings
  // during decode to simulate a new receiver processing data from a legacy sender.
  SNTNetworkExtensionSettingsLegacy* legacy = [[SNTNetworkExtensionSettingsLegacy alloc] init];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:legacy
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:data error:nil];
  unarchiver.requiresSecureCoding = YES;
  [unarchiver setClass:[SNTNetworkExtensionSettings class]
          forClassName:NSStringFromClass([SNTNetworkExtensionSettingsLegacy class])];

  SNTNetworkExtensionSettings* deserialized =
      [unarchiver decodeObjectOfClass:[SNTNetworkExtensionSettings class]
                               forKey:NSKeyedArchiveRootObjectKey];
  [unarchiver finishDecoding];

  XCTAssertNotNil(deserialized);
  // Missing keys should result in default values (NO for BOOL).
  XCTAssertFalse(deserialized.enable);
}

- (void)testTimeoutDefaultFromEnableInit {
  // initWithEnable: should default the timeout to 7s.
  SNTNetworkExtensionSettings* s = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES];
  XCTAssertEqualWithAccuracy(s.dnsUpstreamTimeoutSecs, 7.0, 0.0001);
}

- (void)testTimeoutInRangePreserved {
  SNTNetworkExtensionSettings* s = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                                                dnsUpstreamTimeoutSecs:3.0];
  XCTAssertEqualWithAccuracy(s.dnsUpstreamTimeoutSecs, 3.0, 0.0001);
}

- (void)testTimeoutBelowFloorUsesDefault {
  // Below the 1.0 floor (incl. 0 / negative) is treated as "unset" -> 7s default.
  NSTimeInterval belowFloor[] = {0.0, 0.5, -1.0};
  for (size_t i = 0; i < sizeof(belowFloor) / sizeof(belowFloor[0]); i++) {
    SNTNetworkExtensionSettings* s =
        [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                     dnsUpstreamTimeoutSecs:belowFloor[i]];
    XCTAssertEqualWithAccuracy(s.dnsUpstreamTimeoutSecs, 7.0, 0.0001);
  }
}

- (void)testTimeoutAboveCeilingClampsToMax {
  SNTNetworkExtensionSettings* s = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                                                dnsUpstreamTimeoutSecs:60.0];
  XCTAssertEqualWithAccuracy(s.dnsUpstreamTimeoutSecs, 15.0, 0.0001);
}

- (void)testTimeoutBoundaryValuesPreserved {
  // The clamp is inclusive: exactly the floor and exactly the ceiling pass through unchanged.
  SNTNetworkExtensionSettings* floor = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                                                    dnsUpstreamTimeoutSecs:1.0];
  XCTAssertEqualWithAccuracy(floor.dnsUpstreamTimeoutSecs, 1.0, 0.0001);
  SNTNetworkExtensionSettings* ceiling = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                                                      dnsUpstreamTimeoutSecs:15.0];
  XCTAssertEqualWithAccuracy(ceiling.dnsUpstreamTimeoutSecs, 15.0, 0.0001);
}

- (void)testTimeoutNonFiniteUsesDefault {
  // NaN and infinities aren't meaningful timeouts and must not reach the DNS proxy's dispatch
  // timer, where (int64_t)(v * NSEC_PER_SEC) is undefined behavior. NaN in particular slips the
  // </> clamp because every NaN comparison is false, so guard non-finite values explicitly.
  NSTimeInterval nonFinite[] = {NAN, INFINITY, -INFINITY};
  for (size_t i = 0; i < sizeof(nonFinite) / sizeof(nonFinite[0]); i++) {
    SNTNetworkExtensionSettings* s =
        [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                     dnsUpstreamTimeoutSecs:nonFinite[i]];
    XCTAssertEqualWithAccuracy(s.dnsUpstreamTimeoutSecs, 7.0, 0.0001);
  }
}

- (void)testTimeoutRoundTripsThroughCoder {
  SNTNetworkExtensionSettings* s = [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                                                dnsUpstreamTimeoutSecs:7.5];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:s requiringSecureCoding:YES error:nil];
  SNTNetworkExtensionSettings* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                        fromData:data
                                           error:nil];
  XCTAssertTrue(decoded.enable);
  XCTAssertEqualWithAccuracy(decoded.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
}

- (void)testTimeoutMissingKeyDecodesToDefault {
  // A legacy archive omitting the key must decode to the 7s default, not 0.
  //
  // SNTNetworkExtensionSettingsLegacy encodes nothing, so the archive omits the
  // dnsUpstreamTimeoutSecs key. We remap the class name to SNTNetworkExtensionSettings during
  // decode to faithfully simulate a new receiver processing data from a legacy sender (whose
  // archive records the base class name).
  SNTNetworkExtensionSettingsLegacy* legacy =
      [[SNTNetworkExtensionSettingsLegacy alloc] initWithEnable:YES];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:legacy
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:data error:nil];
  unarchiver.requiresSecureCoding = YES;
  [unarchiver setClass:[SNTNetworkExtensionSettings class]
          forClassName:NSStringFromClass([SNTNetworkExtensionSettingsLegacy class])];

  SNTNetworkExtensionSettings* decoded =
      [unarchiver decodeObjectOfClass:[SNTNetworkExtensionSettings class]
                               forKey:NSKeyedArchiveRootObjectKey];
  [unarchiver finishDecoding];

  XCTAssertEqualWithAccuracy(decoded.dnsUpstreamTimeoutSecs, 7.0, 0.0001);
}

- (void)testEqualityAndHashDistinguishDNSUpstreamTimeout {
  // isEqual: gates whether a sync-only timeout change is pushed to santanetd in
  // SNTNetworkExtensionQueue's reconcileNetworkExtensionConfig, so settings that differ only in
  // the timeout must not compare equal. (3.0 and 7.5 are both in range, so they're preserved.)
  SNTNetworkExtensionSettings* a =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                   dnsUpstreamTimeoutSecs:3.0];
  SNTNetworkExtensionSettings* b =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                   dnsUpstreamTimeoutSecs:7.5];
  XCTAssertNotEqualObjects(a, b);

  SNTNetworkExtensionSettings* c =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                   dnsUpstreamTimeoutSecs:7.5];
  XCTAssertEqualObjects(b, c);
  XCTAssertEqual(b.hash, c.hash);
}

- (void)testNetworkFlowRulesRoundTrip {
  // New santad ⇄ new santanetd: the rules ride inside Settings and survive the round-trip
  // alongside the scalar settings.
  NSData* blob = [@"rule" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkExtensionSettings* settings = [[SNTNetworkExtensionSettings alloc]
              initWithEnable:YES
           flowDefaultAction:SNTNetworkFlowDefaultActionDeny
      dnsUpstreamTimeoutSecs:7.5
            networkFlowRules:@[
              [[SNTNetworkFlowRule alloc] initAddRuleWithId:1 protoBlob:blob],
              [[SNTNetworkFlowRule alloc] initAddRuleWithId:2 protoBlob:blob],
            ]];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:settings
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  SNTNetworkExtensionSettings* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                        fromData:data
                                           error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertTrue(decoded.enable);
  XCTAssertEqual(decoded.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);
  XCTAssertEqualWithAccuracy(decoded.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
  XCTAssertEqual(decoded.networkFlowRules.count, 2u);
  XCTAssertEqual(decoded.networkFlowRules[0].ruleId, 1);
  XCTAssertEqualObjects(decoded.networkFlowRules[0].protoBlob, blob);
}

- (void)testNetworkFlowRulesNilPreserved {
  // nil rules — the runtime "rules unchanged" signal — must survive as nil, not be coerced to @[].
  SNTNetworkExtensionSettings* settings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:NO
                                        flowDefaultAction:SNTNetworkFlowDefaultActionAllow
                                   dnsUpstreamTimeoutSecs:5.0
                                         networkFlowRules:nil];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:settings
                                       requiringSecureCoding:YES
                                                       error:nil];
  SNTNetworkExtensionSettings* decoded =
      [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTNetworkExtensionSettings class]
                                        fromData:data
                                           error:nil];
  XCTAssertNotNil(decoded);
  XCTAssertNil(decoded.networkFlowRules);
}

- (void)testEqualityIgnoresNetworkFlowRules {
  // networkFlowRules is transport-only and intentionally excluded from -isEqual:/-hash so the
  // settings-vs-rules delta signals in reconcileNetworkExtensionConfig stay independent (scalars
  // by value here; rules by cached hash). Two settings that differ only in rules compare equal.
  NSData* blob = [@"rule" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkExtensionSettings* withRules = [[SNTNetworkExtensionSettings alloc]
              initWithEnable:YES
           flowDefaultAction:SNTNetworkFlowDefaultActionDeny
      dnsUpstreamTimeoutSecs:5.0
            networkFlowRules:@[
              [[SNTNetworkFlowRule alloc] initAddRuleWithId:1 protoBlob:blob],
            ]];
  SNTNetworkExtensionSettings* withoutRules =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny
                                   dnsUpstreamTimeoutSecs:5.0
                                         networkFlowRules:nil];
  XCTAssertEqualObjects(withRules, withoutRules);
  XCTAssertEqual(withRules.hash, withoutRules.hash);
}

- (void)testSettingsByAttachingNetworkFlowRules {
  NSData* blob = [@"rule" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkExtensionSettings* base = [[SNTNetworkExtensionSettings alloc]
              initWithEnable:YES
           flowDefaultAction:SNTNetworkFlowDefaultActionDeny
      dnsUpstreamTimeoutSecs:7.5
            networkFlowRules:@[ [[SNTNetworkFlowRule alloc] initAddRuleWithId:1 protoBlob:blob] ]];

  SNTNetworkExtensionSettings* attached = [base settingsByAttachingNetworkFlowRules:@[
    [[SNTNetworkFlowRule alloc] initAddRuleWithId:2 protoBlob:blob],
    [[SNTNetworkFlowRule alloc] initAddRuleWithId:3 protoBlob:blob],
  ]];

  // Scalars are carried forward from the receiver.
  XCTAssertTrue(attached.enable);
  XCTAssertEqual(attached.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);
  XCTAssertEqualWithAccuracy(attached.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
  // The rules are set from the argument, not merged with the receiver's.
  XCTAssertEqual(attached.networkFlowRules.count, 2u);
  XCTAssertEqual(attached.networkFlowRules[0].ruleId, 2);
  // networkFlowRules is excluded from equality, so the copy compares equal to the receiver — the
  // property that lets it stand in as cached last-pushed state.
  XCTAssertEqualObjects(attached, base);
}

- (void)testEncodingStaysReadableByDeployedDecoder {
  // A frozen older decoder — reads only `enable`, allowed-class set excludes
  // NSArray/SNTNetworkFlowRule — must still decode a current archive that also carries a
  // networkFlowRules array, ignoring the keys it doesn't read. Guards against restructuring the
  // encoding in a way that an older santanetd could no longer read.
  NSData* blob = [@"rule" dataUsingEncoding:NSUTF8StringEncoding];
  SNTNetworkExtensionSettings* newFormat = [[SNTNetworkExtensionSettings alloc]
              initWithEnable:YES
           flowDefaultAction:SNTNetworkFlowDefaultActionDeny
      dnsUpstreamTimeoutSecs:7.5
            networkFlowRules:@[
              [[SNTNetworkFlowRule alloc] initAddRuleWithId:1 protoBlob:blob],
              [[SNTNetworkFlowRule alloc] initAddRuleWithId:2 protoBlob:blob],
            ]];
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:newFormat
                                       requiringSecureCoding:YES
                                                       error:nil];
  XCTAssertNotNil(data);

  NSError* err = nil;
  NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:data
                                                                              error:&err];
  XCTAssertNil(err);
  unarchiver.requiresSecureCoding = YES;
  // The archive records the class name "SNTNetworkExtensionSettings"; remap it to the frozen
  // decoder. NSArray and SNTNetworkFlowRule are deliberately left out of the allowed-class set.
  [unarchiver setClass:[SNTDeployedNetworkExtensionSettingsReceiver class]
          forClassName:NSStringFromClass([SNTNetworkExtensionSettings class])];

  SNTDeployedNetworkExtensionSettingsReceiver* received =
      [unarchiver decodeObjectOfClass:[SNTDeployedNetworkExtensionSettingsReceiver class]
                               forKey:NSKeyedArchiveRootObjectKey];
  [unarchiver finishDecoding];

  XCTAssertNil(unarchiver.error,
               @"older decoder must decode a rules-bearing archive without error: %@",
               unarchiver.error);
  XCTAssertNotNil(received);
  XCTAssertTrue(received.enable, @"enable must survive for the older decoder");
}

@end
