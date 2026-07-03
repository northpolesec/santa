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

#include <unistd.h>
#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTNetworkFlowRule.h"
#import "Source/common/SNTStoredNetworkFlowEvent.h"
#import "Source/common/SNTStoredProcess.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SantaVnode.h"
#import "Source/common/TestUtils.h"
#import "Source/common/ne/SNDXPCNetworkExtensionInterface.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"
#import "Source/common/ne/SNTSyncNetworkExtensionSettings.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/MockTTYWriter.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#import "src/santanetd/SNDNetworkFlowDecision.h"

@interface SNTNetworkExtensionQueue (Testing)
@property MOLXPCConnection* netExtConnection;
@property(weak) SNTNotificationQueue* notifierQueue;
@property SNTRuleTable* ruleTable;
@property SNTNetworkExtensionSettings* lastPushedSettings;
@property NSString* lastPushedNetworkFlowRulesHash;
@property(readwrite) NSString* connectedProtocolVersion;
- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                           syncdQueue:(SNTSyncdQueue*)syncdQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                        decisionCache:(SNTDecisionCache*)decisionCache
                            ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter
                               logger:(std::shared_ptr<santa::Logger>)logger;
- (void)establishNetworkExtensionConnection;
- (void)clearNetworkExtensionConnection;
- (SNTNetworkExtensionSettings*)generateSettingsForProtocolVersion:(NSString*)protocolVersion;
@end

@interface SNTNetworkExtensionQueueTest : XCTestCase
@property SNTNetworkExtensionQueue* sut;
@property id mockRuleTable;
@property id mockSyncdQueue;
@property id mockDecisionCache;
@property id mockConfigurator;
@property id mockConnection;
@property id mockProxy;
@property id mockNotifierQueue;
@property id mockNotifierConnection;
@property id mockNotifierProxy;
@property std::shared_ptr<santa::MockTTYWriter> mockTTYWriter;
@end

@implementation SNTNetworkExtensionQueueTest

- (void)setUp {
  self.mockRuleTable = OCMClassMock([SNTRuleTable class]);
  self.mockSyncdQueue = OCMClassMock([SNTSyncdQueue class]);
  self.mockDecisionCache = OCMClassMock([SNTDecisionCache class]);

  self.mockTTYWriter = std::make_shared<santa::MockTTYWriter>();

  // Construct the SUT before mocking the configurator so its init-time KVO watchers attach
  // to the real configurator singleton (KVO on a class mock is unreliable).
  self.sut = [[SNTNetworkExtensionQueue alloc] initWithNotifierQueue:nil
                                                          syncdQueue:self.mockSyncdQueue
                                                           ruleTable:self.mockRuleTable
                                                       decisionCache:self.mockDecisionCache
                                                           ttyWriter:self.mockTTYWriter
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
  // Release the SUT and the injected mock so the gmock MockTTYWriter is destroyed here
  // (verifying its expectations) rather than leaking to program exit under retained XCTest cases.
  self.sut = nil;
  self.mockTTYWriter = nullptr;
}

// Make the configurator report the given sync-side network extension settings.
- (void)stubConfiguratorEnable:(BOOL)enable action:(SNTNetworkFlowDefaultAction)action {
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:enable flowDefaultAction:action];
  OCMStub([self.mockConfigurator syncNetworkExtensionSettings]).andReturn(settings);
}

// Like stubConfiguratorEnable:action: but also sets the MDM-sourced DNS upstream timeout.
- (void)stubConfiguratorEnable:(BOOL)enable
                        action:(SNTNetworkFlowDefaultAction)action
                    dnsTimeout:(NSTimeInterval)dnsTimeout {
  SNTSyncNetworkExtensionSettings* settings =
      [[SNTSyncNetworkExtensionSettings alloc] initWithEnable:enable flowDefaultAction:action];
  OCMStub([self.mockConfigurator syncNetworkExtensionSettings]).andReturn(settings);
  OCMStub([self.mockConfigurator dnsUpstreamTimeoutSecs]).andReturn(dnsTimeout);
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
      initAddRuleWithName:[NSString stringWithFormat:@"rule-%lld", ruleId]
                   ruleId:ruleId
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

- (void)testGenerateSettingsDefaultsDNSUpstreamTimeoutWhenUnset {
  // MDM timeout 0 -> SNTNetworkExtensionSettings normalizes to the 30s default.
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny dnsTimeout:0];
  SNTNetworkExtensionSettings* settings = [self.sut generateSettingsForProtocolVersion:@"1.0"];
  XCTAssertEqualWithAccuracy(settings.dnsUpstreamTimeoutSecs, 30.0, 0.0001);
}

- (void)testGenerateSettingsIgnoresSyncBelowProtocolV1 {
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny dnsTimeout:7.5];
  SNTNetworkExtensionSettings* settings = [self.sut generateSettingsForProtocolVersion:@"0.9"];
  XCTAssertFalse(settings.enable);  // sync (enable/action) ignored below protocol v1
  // The MDM timeout is local config, not a sync setting, so it applies regardless of version.
  XCTAssertEqualWithAccuracy(settings.dnsUpstreamTimeoutSecs, 7.5, 0.0001);
}

// Make shouldInstallNetworkExtension report YES (sync v2 + enabled NE settings).
- (void)stubNetworkExtensionEnabled {
  OCMStub([self.mockConfigurator isSyncV2Enabled]).andReturn(YES);
  [self stubConfiguratorEnable:YES action:SNTNetworkFlowDefaultActionDeny];
}

- (void)testHandleNetworkFlowDecisionsEnrichesAndEnqueues {
  [self stubNetworkExtensionEnabled];

  // A real event from the converter; cd enrichment fills sha256 + certs.
  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  event.decision = SNTNetworkFlowDecisionBlock;
  event.ruleId = 7;
  event.process.filePath = @"/usr/bin/curl";

  SantaVnode vnode = {.fsid = 1, .fileid = 2};
  id decision = OCMClassMock([SNDNetworkFlowDecision class]);
  OCMStub([decision storedEvent]).andReturn(event);
  OCMStub([(SNDNetworkFlowDecision*)decision vnode]).andReturn(vnode);

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = @"abc123";
  cd.certChain = @[];  // empty chain is fine; non-nil proves the assignment path
  OCMStub([self.mockDecisionCache cachedDecisionForVnode:vnode])
      .ignoringNonObjectArgs()
      .andReturn(cd);

  OCMExpect([self.mockSyncdQueue addStoredEvent:event]);
  [self.sut handleNetworkFlowDecisions:@[ decision ]];
  OCMVerifyAll(self.mockSyncdQueue);

  XCTAssertEqualObjects(event.process.fileSHA256, @"abc123");
  XCTAssertEqualObjects(event.process.signingChain, @[]);
}

- (void)testHandleNetworkFlowDecisionsNilConverterNoOps {
  [self stubNetworkExtensionEnabled];

  // The open-build stub returns nil from storedEvent -> nothing enqueued.
  id decision = OCMClassMock([SNDNetworkFlowDecision class]);
  OCMStub([decision storedEvent]).andReturn(nil);

  OCMReject([self.mockSyncdQueue addStoredEvent:OCMOCK_ANY]);
  [self.sut handleNetworkFlowDecisions:@[ decision ]];
}

// Create a (sparse) temp file of the given size and return its path.
- (NSString*)tempFileOfSize:(off_t)size name:(NSString*)name {
  NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:name];
  NSFileManager* fm = [NSFileManager defaultManager];
  [fm removeItemAtPath:path error:nil];
  [fm createFileAtPath:path contents:nil attributes:nil];
  truncate(path.fileSystemRepresentation, size);
  return path;
}

// A mock decision whose storedEvent points at the given on-disk path, with a cache
// miss so the handler falls through to rehydrate.
- (id)decisionForCacheMissWithEvent:(SNTStoredNetworkFlowEvent*)event {
  id decision = OCMClassMock([SNDNetworkFlowDecision class]);
  OCMStub([decision storedEvent]).andReturn(event);
  OCMStub([(SNDNetworkFlowDecision*)decision vnode]).andReturn(SantaVnode{});
  // cachedDecisionForVnode: left unstubbed -> nil (miss).
  return decision;
}

- (void)testHandleNetworkFlowDecisionsRehydratesSmallBinarySynchronously {
  [self stubNetworkExtensionEnabled];
  NSString* path = [self tempFileOfSize:1024 name:@"flow-small.bin"];

  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  event.process.filePath = path;
  id decision = [self decisionForCacheMissWithEvent:event];

  OCMExpect([self.mockDecisionCache rehydrateAndCacheDecisionForFileInfo:OCMOCK_ANY]);
  OCMReject([self.mockDecisionCache asyncRehydrateAndCacheDecisionForFileInfo:OCMOCK_ANY]);
  OCMExpect([self.mockSyncdQueue addStoredEvent:event]);

  [self.sut handleNetworkFlowDecisions:@[ decision ]];

  OCMVerifyAll(self.mockDecisionCache);
  OCMVerifyAll(self.mockSyncdQueue);
  [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
}

- (void)testHandleNetworkFlowDecisionsRehydratesLargeBinaryAsynchronously {
  [self stubNetworkExtensionEnabled];
  NSString* path = [self tempFileOfSize:(kMaxSyncRehydrateBytes + 1) name:@"flow-large.bin"];

  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  event.process.filePath = path;
  id decision = [self decisionForCacheMissWithEvent:event];

  // Oversized binary: warm the cache async, never hash on this serial queue.
  OCMExpect([self.mockDecisionCache asyncRehydrateAndCacheDecisionForFileInfo:OCMOCK_ANY]);
  OCMReject([self.mockDecisionCache rehydrateAndCacheDecisionForFileInfo:OCMOCK_ANY]);
  OCMExpect([self.mockSyncdQueue addStoredEvent:event]);  // still uploads, thin

  [self.sut handleNetworkFlowDecisions:@[ decision ]];

  OCMVerifyAll(self.mockDecisionCache);
  OCMVerifyAll(self.mockSyncdQueue);
  [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
}

// Wire up a notifier connection so the loud-deny post branch reaches a verifiable proxy.
// Returns the proxy mock for expectations; the strong test refs keep the queue's weak
// notifierQueue alive for the test's duration.
- (id)setUpNotifierProxy {
  self.mockNotifierQueue = OCMClassMock([SNTNotificationQueue class]);
  self.mockNotifierConnection = OCMClassMock([MOLXPCConnection class]);
  self.mockNotifierProxy = OCMProtocolMock(@protocol(SNTNotifierXPC));
  OCMStub([self.mockNotifierQueue notifierConnection]).andReturn(self.mockNotifierConnection);
  OCMStub([self.mockNotifierConnection remoteObjectProxy]).andReturn(self.mockNotifierProxy);
  self.sut.notifierQueue = self.mockNotifierQueue;
  return self.mockNotifierProxy;
}

- (SNTStoredNetworkFlowEvent*)loudDenyEventWithUIKey:(NSString*)uiDedupeKey {
  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  event.decision = SNTNetworkFlowDecisionBlock;
  event.silent = NO;
  event.uiDedupeKey = uiDedupeKey;
  return event;
}

- (void)testHandleNetworkFlowDecisionsLoudDenyPostsDialog {
  [self stubNetworkExtensionEnabled];
  id proxy = [self setUpNotifierProxy];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"4242:1|7|example.com"];
  // isNotNil guards the queue -> NetworkFlowConfigBundle -> post wiring (a real bundle is built).
  OCMExpect([proxy postNetworkFlowBlockNotification:event configBundle:[OCMArg isNotNil]]);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  OCMVerifyAll(proxy);
}

- (void)testHandleNetworkFlowDecisionsAuditDoesNotPostDialog {
  [self stubNetworkExtensionEnabled];
  id proxy = [self setUpNotifierProxy];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.decision = SNTNetworkFlowDecisionAudit;
  OCMReject([proxy postNetworkFlowBlockNotification:OCMOCK_ANY configBundle:OCMOCK_ANY]);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  OCMVerifyAll(proxy);
}

- (void)testHandleNetworkFlowDecisionsSilentDenyDoesNotPostDialog {
  [self stubNetworkExtensionEnabled];
  id proxy = [self setUpNotifierProxy];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.silent = YES;
  OCMReject([proxy postNetworkFlowBlockNotification:OCMOCK_ANY configBundle:OCMOCK_ANY]);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  OCMVerifyAll(proxy);
}

- (void)testHandleNetworkFlowDecisionsDeDupesRepeatDialogByUIKey {
  [self stubNetworkExtensionEnabled];
  id proxy = [self setUpNotifierProxy];

  // Same uiDedupeKey within the window: only the first prompts.
  SNTStoredNetworkFlowEvent* first = [self loudDenyEventWithUIKey:@"same-key"];
  SNTStoredNetworkFlowEvent* second = [self loudDenyEventWithUIKey:@"same-key"];
  OCMExpect([proxy postNetworkFlowBlockNotification:first configBundle:OCMOCK_ANY]);
  OCMReject([proxy postNetworkFlowBlockNotification:second configBundle:OCMOCK_ANY]);

  [self.sut handleNetworkFlowDecisions:@[
    [self decisionForCacheMissWithEvent:first], [self decisionForCacheMissWithEvent:second]
  ]];

  OCMVerifyAll(proxy);
}

- (void)testHandleNetworkFlowDecisionsNoGUIConnectionDoesNotConsumeDedupeSlot {
  [self stubNetworkExtensionEnabled];

  // No notifier connection yet (notifierQueue is nil): the post is skipped, and the dedupe slot
  // must NOT be consumed so the dialog still shows once a GUI connects within the window.
  SNTStoredNetworkFlowEvent* first = [self loudDenyEventWithUIKey:@"same-key"];
  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:first] ]];

  // GUI connects; the same flow must still prompt (the earlier disconnected deny didn't burn it).
  id proxy = [self setUpNotifierProxy];
  SNTStoredNetworkFlowEvent* second = [self loudDenyEventWithUIKey:@"same-key"];
  OCMExpect([proxy postNetworkFlowBlockNotification:second configBundle:[OCMArg isNotNil]]);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:second] ]];

  OCMVerifyAll(proxy);
}

- (void)testHandleNetworkFlowDecisionsDistinctUIKeysBothPost {
  [self stubNetworkExtensionEnabled];
  id proxy = [self setUpNotifierProxy];

  SNTStoredNetworkFlowEvent* first = [self loudDenyEventWithUIKey:@"key-1"];
  SNTStoredNetworkFlowEvent* second = [self loudDenyEventWithUIKey:@"key-2"];
  OCMExpect([proxy postNetworkFlowBlockNotification:first configBundle:OCMOCK_ANY]);
  OCMExpect([proxy postNetworkFlowBlockNotification:second configBundle:OCMOCK_ANY]);

  [self.sut handleNetworkFlowDecisions:@[
    [self decisionForCacheMissWithEvent:first], [self decisionForCacheMissWithEvent:second]
  ]];

  OCMVerifyAll(proxy);
}

- (void)testHandleNetworkFlowDecisionsLoudDenyWritesTTYWhenPathPresent {
  [self stubNetworkExtensionEnabled];
  [self setUpNotifierProxy];  // loud-deny branch also posts the dialog

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.ttyPath = @"/dev/ttys003";
  event.process.filePath = @"/usr/bin/curl";
  event.ruleName = @"block-example";
  event.hostname = @"example.com";
  event.remotePort = 443;
  event.customURL = @"https://example.com/why";

  EXPECT_CALL(*self.mockTTYWriter,
              WriteWithoutSignal(
                  testing::Truly([](NSString* p) { return [p isEqualToString:@"/dev/ttys003"]; }),
                  testing::Truly([](NSString* msg) {
                    return [msg containsString:@"block-example"] &&
                           [msg containsString:@"/usr/bin/curl"] &&
                           [msg containsString:@"example.com"] && [msg containsString:@":443"] &&
                           [msg containsString:@"https://example.com/why"];
                  })))
      .Times(1);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  XCTBubbleMockVerifyAndClearExpectations(self.mockTTYWriter.get());
}

- (void)testHandleNetworkFlowDecisionsLoudDenyOmitsMoreInfoWhenNoURL {
  [self stubNetworkExtensionEnabled];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.ttyPath = @"/dev/ttys003";
  event.customURL = nil;  // no custom URL resolves -> no "More info:" line in the message

  EXPECT_CALL(*self.mockTTYWriter, WriteWithoutSignal(testing::_, testing::Truly([](NSString* msg) {
                                                        return ![msg containsString:@"More info:"];
                                                      })))
      .Times(1);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  XCTBubbleMockVerifyAndClearExpectations(self.mockTTYWriter.get());
}

- (void)testHandleNetworkFlowDecisionsLoudDenyWritesTTYWithoutGUIConnection {
  [self stubNetworkExtensionEnabled];
  // No setUpNotifierProxy: notifierQueue stays nil, so the dialog post is a no-op. The TTY
  // write must still fire -- it's independent of the GUI connection (e.g. at the loginwindow).

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.ttyPath = @"/dev/ttys003";
  event.process.filePath = @"/usr/bin/curl";

  EXPECT_CALL(*self.mockTTYWriter, WriteWithoutSignal(testing::Truly([](NSString* p) {
                                                        return [p isEqualToString:@"/dev/ttys003"];
                                                      }),
                                                      testing::_))
      .Times(1);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  XCTBubbleMockVerifyAndClearExpectations(self.mockTTYWriter.get());
}

- (void)testHandleNetworkFlowDecisionsLoudDenyNoTTYWhenPathNil {
  [self stubNetworkExtensionEnabled];
  [self setUpNotifierProxy];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];  // ttyPath nil
  EXPECT_CALL(*self.mockTTYWriter, WriteWithoutSignal(testing::_, testing::_)).Times(0);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  XCTBubbleMockVerifyAndClearExpectations(self.mockTTYWriter.get());
}

- (void)testHandleNetworkFlowDecisionsSilentDenyDoesNotWriteTTY {
  [self stubNetworkExtensionEnabled];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.silent = YES;
  event.ttyPath = @"/dev/ttys003";  // present but ignored on a silent deny
  EXPECT_CALL(*self.mockTTYWriter, WriteWithoutSignal(testing::_, testing::_)).Times(0);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  XCTBubbleMockVerifyAndClearExpectations(self.mockTTYWriter.get());
}

- (void)testHandleNetworkFlowDecisionsAuditDoesNotWriteTTY {
  [self stubNetworkExtensionEnabled];

  SNTStoredNetworkFlowEvent* event = [self loudDenyEventWithUIKey:@"k"];
  event.decision = SNTNetworkFlowDecisionAudit;
  event.ttyPath = @"/dev/ttys003";
  EXPECT_CALL(*self.mockTTYWriter, WriteWithoutSignal(testing::_, testing::_)).Times(0);

  [self.sut handleNetworkFlowDecisions:@[ [self decisionForCacheMissWithEvent:event] ]];

  XCTBubbleMockVerifyAndClearExpectations(self.mockTTYWriter.get());
}

@end
