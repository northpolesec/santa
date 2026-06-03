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

#import "Source/santad/SNTNetworkExtensionQueue.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTNetworkFlowRule.h"
#import "Source/common/ne/SNDXPCNetworkExtensionInterface.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"
#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

@interface SNTNetworkExtensionQueue (Testing)
@property MOLXPCConnection* netExtConnection;
@property SNTRuleTable* ruleTable;
@property SNTNetworkExtensionSettings* lastPushedSettings;
@property NSString* lastPushedNetworkFlowRulesHash;
@property(readwrite) NSString* connectedProtocolVersion;
- (void)establishNetworkExtensionConnection;
- (void)clearNetworkExtensionConnection;
- (SNTNetworkExtensionSettings*)generateSettingsForProtocolVersion:(NSString*)protocolVersion;
@end

@interface SNTNetworkExtensionQueueTest : XCTestCase
@property SNTNetworkExtensionQueue* sut;
@property id mockRuleTable;
@property id mockConfigurator;
@property id mockConnection;
@property id mockProxy;
@end

@implementation SNTNetworkExtensionQueueTest

- (void)setUp {
  self.mockRuleTable = OCMClassMock([SNTRuleTable class]);

  // Construct the SUT before mocking the configurator so its init-time KVO watchers attach
  // to the real configurator singleton (KVO on a class mock is unreliable).
  self.sut = [[SNTNetworkExtensionQueue alloc] initWithNotifierQueue:nil
                                                          syncdQueue:nil
                                                           ruleTable:self.mockRuleTable
                                                              logger:nullptr];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);

  self.mockConnection = OCMClassMock([MOLXPCConnection class]);
  self.mockProxy = OCMProtocolMock(@protocol(SNDNetworkExtensionXPC));
  OCMStub([self.mockConnection remoteObjectProxy]).andReturn(self.mockProxy);

  self.sut.netExtConnection = self.mockConnection;
  self.sut.connectedProtocolVersion = @"1.0";
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
}

// Make the configurator report the given sync-side network extension settings.
- (void)stubConfiguratorEnable:(BOOL)enable action:(SNTNetworkFlowDefaultAction)action {
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:enable flowDefaultAction:action];
  OCMStub([self.mockConfigurator syncNetworkExtensionSettings]).andReturn(settings);
}

// Like stubConfiguratorEnable:action: but also sets the sync-side DNS upstream timeout.
- (void)stubConfiguratorEnable:(BOOL)enable
                        action:(SNTNetworkFlowDefaultAction)action
                    dnsTimeout:(NSTimeInterval)dnsTimeout {
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:enable
                                            flowDefaultAction:action
                                       dnsUpstreamTimeoutSecs:dnsTimeout];
  OCMStub([self.mockConfigurator syncNetworkExtensionSettings]).andReturn(settings);
}

// Make the rule table report the given network flow rules hash + ruleset.
- (void)stubRuleTableHash:(NSString*)hash rules:(NSArray<SNTNetworkFlowRule*>*)rules {
  // reconcile reads the hash via the narrow -networkFlowRulesHash getter.
  OCMStub([self.mockRuleTable networkFlowRulesHash]).andReturn(hash);
  SNTNetworkFlowRulesSnapshot* snapshot = [[SNTNetworkFlowRulesSnapshot alloc] initWithRules:rules
                                                                        networkFlowRulesHash:hash];
  OCMStub([self.mockRuleTable retrieveAllNetworkFlowRulesSnapshot]).andReturn(snapshot);
}

- (SNTNetworkFlowRule*)rule:(int64_t)ruleId {
  return [[SNTNetworkFlowRule alloc]
      initAddRuleWithId:ruleId
              protoBlob:[@"blob" dataUsingEncoding:NSUTF8StringEncoding]];
}

- (void)testReconcileSeedsFullConfigWhenNothingPushedYet {
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];
  [self stubRuleTableHash:@"h1" rules:@[ [self rule:1], [self rule:2] ]];

  OCMExpect([self.mockProxy
      updateNetworkExtensionSettings:[OCMArg checkWithBlock:^BOOL(SNTNetworkExtensionSettings* c) {
        return c.enable && c.flowDefaultAction == SNTNetworkFlowDefaultActionDeny &&
               c.networkFlowRules.count == 2;
      }]
                               reply:[OCMArg invokeBlock]]);

  [self.sut reconcileNetworkExtensionConfig];
  OCMVerifyAll(self.mockProxy);
}

- (void)testReconcileSettingsOnlyChangePushesNilRules {
  // Rules already pushed (hash matches), only settings differ.
  self.sut.lastPushedNetworkFlowRulesHash = @"h1";
  self.sut.lastPushedSettings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:NO
                                        flowDefaultAction:SNTNetworkFlowDefaultActionAllow];
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionAllow];
  [self stubRuleTableHash:@"h1" rules:@[ [self rule:1] ]];

  OCMExpect([self.mockProxy
      updateNetworkExtensionSettings:[OCMArg checkWithBlock:^BOOL(SNTNetworkExtensionSettings* c) {
        return c.enable && c.flowDefaultAction == SNTNetworkFlowDefaultActionAllow &&
               c.networkFlowRules == nil;
      }]
                               reply:[OCMArg invokeBlock]]);
  // Settings-only change must not materialize the ruleset.
  OCMReject([self.mockRuleTable retrieveAllNetworkFlowRulesSnapshot]);

  [self.sut reconcileNetworkExtensionConfig];
  OCMVerifyAll(self.mockProxy);
}

- (void)testReconcileRulesOnlyChangePushesRules {
  self.sut.lastPushedNetworkFlowRulesHash = @"h1";
  self.sut.lastPushedSettings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];  // settings unchanged
  [self stubRuleTableHash:@"h2" rules:@[ [self rule:1] ]];                   // rules changed

  OCMExpect([self.mockProxy
      updateNetworkExtensionSettings:[OCMArg checkWithBlock:^BOOL(SNTNetworkExtensionSettings* c) {
        return c.enable && c.flowDefaultAction == SNTNetworkFlowDefaultActionDeny &&
               c.networkFlowRules.count == 1;
      }]
                               reply:[OCMArg invokeBlock]]);

  [self.sut reconcileNetworkExtensionConfig];
  OCMVerifyAll(self.mockProxy);
}

- (void)testReconcileNoChangeDoesNotPush {
  self.sut.lastPushedNetworkFlowRulesHash = @"h1";
  self.sut.lastPushedSettings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];
  [self stubRuleTableHash:@"h1" rules:@[ [self rule:1] ]];

  OCMReject([self.mockProxy updateNetworkExtensionSettings:OCMOCK_ANY reply:OCMOCK_ANY]);

  [self.sut reconcileNetworkExtensionConfig];
  OCMVerifyAll(self.mockProxy);
}

- (void)testReconcileNoConnectionIsNoOp {
  self.sut.netExtConnection = nil;
  OCMReject([self.mockProxy updateNetworkExtensionSettings:OCMOCK_ANY reply:OCMOCK_ANY]);
  [self.sut reconcileNetworkExtensionConfig];
  OCMVerifyAll(self.mockProxy);
}

- (void)testReconcileSuccessReplyRecordsLastPushed {
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];
  [self stubRuleTableHash:@"h1" rules:@[ [self rule:1] ]];

  OCMStub([self.mockProxy updateNetworkExtensionSettings:OCMOCK_ANY reply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [invocation getArgument:&replyBlock atIndex:3];
        replyBlock(YES);
      });

  [self.sut reconcileNetworkExtensionConfig];

  XCTAssertEqualObjects(self.sut.lastPushedNetworkFlowRulesHash, @"h1");
  XCTAssertTrue(self.sut.lastPushedSettings.enable);
  XCTAssertEqual(self.sut.lastPushedSettings.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);
}

- (void)testReconcileFailureReplyDoesNotRecordLastPushed {
  // Pre-existing state so we can verify it isn't overwritten on failure.
  self.sut.lastPushedNetworkFlowRulesHash = @"h0";
  self.sut.lastPushedSettings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:NO
                                        flowDefaultAction:SNTNetworkFlowDefaultActionAllow];

  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];
  [self stubRuleTableHash:@"h1" rules:@[ [self rule:1] ]];

  OCMStub([self.mockProxy updateNetworkExtensionSettings:OCMOCK_ANY reply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [invocation getArgument:&replyBlock atIndex:3];
        replyBlock(NO);
      });

  [self.sut reconcileNetworkExtensionConfig];

  // Stale lastPushed preserved so the next reconcile retries.
  XCTAssertEqualObjects(self.sut.lastPushedNetworkFlowRulesHash, @"h0");
  XCTAssertFalse(self.sut.lastPushedSettings.enable);
}

- (void)testRegistrationSeedsViaReplyAndRecordsLastPushed {
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];
  [self stubRuleTableHash:@"h1" rules:@[ [self rule:1], [self rule:2] ]];

  // santanetd builds a real reverse connection on registration; stub that out. Registration
  // must seed via the reply and must NOT push over the reverse channel.
  id sutMock = OCMPartialMock(self.sut);
  OCMStub([sutMock establishNetworkExtensionConnection]).andDo(^(NSInvocation* inv) {
    self.sut.netExtConnection = self.mockConnection;
  });
  OCMReject([self.mockProxy updateNetworkExtensionSettings:OCMOCK_ANY reply:OCMOCK_ANY]);

  NSError* err = nil;
  SNTNetworkExtensionSettings* settings = [self.sut handleRegistrationWithProtocolVersion:@"1.0"
                                                                                    error:&err];

  // Reply carries the scalar settings and the full ruleset (in networkFlowRules) for atomic
  // application.
  XCTAssertNil(err);
  XCTAssertTrue(settings.enable);
  XCTAssertEqual(settings.flowDefaultAction, SNTNetworkFlowDefaultActionDeny);
  XCTAssertEqual(settings.networkFlowRules.count, 2);

  // last-pushed reflects what the reply seeded (scalars equal; networkFlowRules is excluded from
  // -isEqual:), so an immediate no-change reconcile is a no-op.
  XCTAssertEqualObjects(self.sut.lastPushedSettings, settings);
  XCTAssertEqualObjects(self.sut.lastPushedNetworkFlowRulesHash, @"h1");

  OCMVerifyAll(self.mockProxy);
  [sutMock stopMocking];
}

- (void)testConnectionClearResetsLastPushedSoNextSeedIsFull {
  self.sut.lastPushedNetworkFlowRulesHash = @"h1";
  self.sut.lastPushedSettings =
      [[SNTNetworkExtensionSettings alloc] initWithEnable:YES
                                        flowDefaultAction:SNTNetworkFlowDefaultActionDeny];

  [self.sut clearNetworkExtensionConnection];

  XCTAssertNil(self.sut.lastPushedSettings);
  XCTAssertNil(self.sut.lastPushedNetworkFlowRulesHash);
}

- (void)testGenerateSettingsPropagatesDNSUpstreamTimeout {
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny dnsTimeout:7.5];
  SNTNetworkExtensionSettings* settings = [self.sut generateSettingsForProtocolVersion:@"1.0"];
  XCTAssertEqualWithAccuracy(settings.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
}

- (void)testGenerateSettingsDefaultsDNSUpstreamTimeoutWhenSyncUnset {
  // Carrier timeout 0 -> SNTNetworkExtensionSettings normalizes to the 7s default.
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny dnsTimeout:0];
  SNTNetworkExtensionSettings* settings = [self.sut generateSettingsForProtocolVersion:@"1.0"];
  XCTAssertEqualWithAccuracy(settings.dnsUpstreamTimeoutSecs, 7.0, 0.0001);
}

- (void)testGenerateSettingsIgnoresSyncBelowProtocolV1 {
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny dnsTimeout:7.5];
  SNTNetworkExtensionSettings* settings = [self.sut generateSettingsForProtocolVersion:@"0.9"];
  XCTAssertFalse(settings.enable);
  // Sync timeout is ignored below protocol v1 -> 7s default.
  XCTAssertEqualWithAccuracy(settings.dnsUpstreamTimeoutSecs, 7.0, 0.0001);
}

@end
