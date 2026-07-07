/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#import "Source/gui/SNTMessageWindowController.h"
#import "Source/gui/SNTNetworkFlowMessageWindowController.h"
#import "Source/gui/SNTNotificationManager.h"
#import "Source/gui/SNTStatusItemManager.h"

#import "Source/common/SNTConfigBundle.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredNetworkFlowEvent.h"

@class SNTBinaryMessageWindowController;

@interface SNTNotificationManager (Testing)
- (void)hashBundleBinariesForEvent:(SNTStoredEvent*)event
                    withController:(SNTBinaryMessageWindowController*)controller;
- (void)queueMessage:(SNTMessageWindowController*)pendingMsg enableSilences:(BOOL)enableSilences;
@end

// Overrides only messageHash, to confirm the base queueDedupeHash defaults to it.
@interface DedupeHashPassthroughController : SNTMessageWindowController
@end

@implementation DedupeHashPassthroughController
- (NSString*)messageHash {
  return @"passthrough-key";
}
@end

@interface SNTNotificationManagerTest : XCTestCase
@end

@implementation SNTNotificationManagerTest

- (void)setUp {
  [super setUp];
  fclose(stdout);
}

- (void)testPostBlockNotificationSendsDistributedNotification {
  SNTStoredExecutionEvent* ev = [[SNTStoredExecutionEvent alloc] init];
  ev.fileSHA256 = @"the-sha256";
  ev.filePath = @"/Applications/Safari.app/Contents/MacOS/Safari";
  ev.fileBundleName = @"Safari";
  ev.fileBundlePath = @"/Applications/Safari.app";
  ev.fileBundleID = @"com.apple.Safari";
  ev.fileBundleVersion = @"18614.1.14.1.15";
  ev.fileBundleVersionString = @"16.0";
  ev.executingUser = @"rah";
  ev.occurrenceDate = [NSDate dateWithTimeIntervalSince1970:1660221048];
  ev.decision = SNTEventStateBlockBinary;
  ev.pid = @84156;
  ev.ppid = @1;
  ev.parentName = @"launchd";

  SNTNotificationManager* sut = OCMPartialMock([[SNTNotificationManager alloc] init]);
  OCMStub([sut hashBundleBinariesForEvent:OCMOCK_ANY withController:OCMOCK_ANY]).andDo(nil);

  id dncMock = OCMClassMock([NSDistributedNotificationCenter class]);
  OCMStub([dncMock defaultCenter]).andReturn(dncMock);

  [sut postBlockNotification:ev
           withCustomMessage:@""
                   customURL:nil
                 configState:nil
                    andReply:^(BOOL authenticated){
                    }];

  OCMVerify([dncMock postNotificationName:@"com.northpolesec.santa.notification.blockedeexecution"
                                   object:@"com.northpolesec.santa"
                                 userInfo:[OCMArg checkWithBlock:^BOOL(NSDictionary* userInfo) {
                                   XCTAssertEqualObjects(userInfo[@"file_sha256"], @"the-sha256");
                                   XCTAssertEqualObjects(userInfo[@"pid"], @84156);
                                   XCTAssertEqualObjects(userInfo[@"ppid"], @1);
                                   XCTAssertEqualObjects(userInfo[@"execution_time"], @1660221048);
                                   return YES;
                                 }]
                       deliverImmediately:YES]);
}

- (void)testPostNetworkFlowBlockNotificationQueuesAWindow {
  SNTNotificationManager* mgr = [[SNTNotificationManager alloc] init];
  id mgrMock = OCMPartialMock(mgr);
  // Silences track the bundle's EnableNotificationSilences (here: disabled).
  OCMExpect([mgrMock
        queueMessage:[OCMArg isKindOfClass:[SNTNetworkFlowMessageWindowController class]]
      enableSilences:NO]);

  SNTConfigBundle* configBundle = [[SNTConfigBundle alloc] init];
  [configBundle setValue:@NO forKey:@"enableNotificationSilences"];

  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  event.decision = SNTNetworkFlowDecisionBlock;
  [mgr postNetworkFlowBlockNotification:event configBundle:configBundle];

  OCMVerifyAll(mgrMock);
  [mgrMock stopMocking];
}

// The silence key (messageHash) is app-level + cross-version; the already-queued key
// (queueDedupeHash) stays fine-grained on the full uiDedupeKey.
- (void)testNetworkFlowControllerSilenceAndDedupeHashes {
  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  event.uiDedupeKey = @"4242:1|7|example.com";
  event.process.signingID = @"com.example.app";
  event.process.teamID = @"ABCDE12345";
  event.process.cdhash = @"cd123";
  event.process.fileSHA256 = @"sha123";

  SNTNetworkFlowMessageWindowController* controller =
      [[SNTNetworkFlowMessageWindowController alloc] initWithEvent:event
                                                      configBundle:[[SNTConfigBundle alloc] init]];

  XCTAssertEqualObjects([controller messageHash], @"netflow:signingid:ABCDE12345:com.example.app");
  XCTAssertEqualObjects([controller queueDedupeHash], @"netflow:4242:1|7|example.com");
}

// Silence key degrades cdhash -> sha256 when no signing ID is present.
- (void)testNetworkFlowControllerSilenceHashFallback {
  SNTStoredNetworkFlowEvent* cdhashEvent = [[SNTStoredNetworkFlowEvent alloc] init];
  cdhashEvent.process.cdhash = @"cd123";
  cdhashEvent.process.fileSHA256 = @"sha123";
  XCTAssertEqualObjects([[[SNTNetworkFlowMessageWindowController alloc]
                            initWithEvent:cdhashEvent
                             configBundle:[[SNTConfigBundle alloc] init]] messageHash],
                        @"netflow:cdhash:cd123");

  SNTStoredNetworkFlowEvent* shaEvent = [[SNTStoredNetworkFlowEvent alloc] init];
  shaEvent.process.fileSHA256 = @"sha123";
  XCTAssertEqualObjects([[[SNTNetworkFlowMessageWindowController alloc]
                            initWithEvent:shaEvent
                             configBundle:[[SNTConfigBundle alloc] init]] messageHash],
                        @"netflow:sha256:sha123");
}

// No stable identity / no uiDedupeKey -> nil, so unidentified events don't collapse onto a
// shared key.
- (void)testNetworkFlowControllerHashesNilWhenUnidentified {
  SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
  SNTNetworkFlowMessageWindowController* controller =
      [[SNTNetworkFlowMessageWindowController alloc] initWithEvent:event
                                                      configBundle:[[SNTConfigBundle alloc] init]];

  XCTAssertNil([controller messageHash]);
  XCTAssertNil([controller queueDedupeHash]);
}

// The core decoupling invariant: two flows from the same app to different destinations share one
// silence key (silencing covers both) but keep distinct already-queued keys (each still shown).
- (void)testNetworkFlowSilenceScopeIsAppWideButDedupeIsPerFlow {
  SNTStoredNetworkFlowEvent* (^flow)(NSString*) = ^(NSString* uiDedupeKey) {
    SNTStoredNetworkFlowEvent* event = [[SNTStoredNetworkFlowEvent alloc] init];
    event.process.signingID = @"com.example.app";
    event.process.teamID = @"ABCDE12345";
    event.uiDedupeKey = uiDedupeKey;
    return event;
  };
  SNTNetworkFlowMessageWindowController* a =
      [[SNTNetworkFlowMessageWindowController alloc] initWithEvent:flow(@"k|1|host-a")
                                                      configBundle:[[SNTConfigBundle alloc] init]];
  SNTNetworkFlowMessageWindowController* b =
      [[SNTNetworkFlowMessageWindowController alloc] initWithEvent:flow(@"k|1|host-b")
                                                      configBundle:[[SNTConfigBundle alloc] init]];

  XCTAssertEqualObjects([a messageHash], [b messageHash]);             // one silence covers both
  XCTAssertNotEqualObjects([a queueDedupeHash], [b queueDedupeHash]);  // but each is still shown
}

// The base queueDedupeHash defaults to messageHash, so non-overriding dialogs (binary/FAA/mount/
// device) keep collapsing on their silence key exactly as before.
- (void)testQueueDedupeHashDefaultsToMessageHash {
  DedupeHashPassthroughController* controller = [[DedupeHashPassthroughController alloc] init];
  XCTAssertEqualObjects([controller queueDedupeHash], @"passthrough-key");
}

#pragma mark Timed-mode push threading

// Regression tests for the status-menu main-thread-assert crash.
//
// The daemon->GUI notifier XPC connection delivers messages on a background queue, not the main
// thread. Every daemon-pushed timed-mode handler forwards into SNTStatusItemManager, which mutates
// AppKit menu state -- and mutating a menu item's visibility while the status menu is open forces a
// live popup-window resize that traps ("Must only be used from the main thread") when done off the
// main thread. Each handler must therefore hop to the main thread before touching the status item.
//
// The helper drives a push from a background queue (mimicking the XPC delivery queue) and asserts
// the forwarded SNTStatusItemManager call lands on the main thread.
- (void)verifyPush:(NSString*)name
    hopsToMainThread:(void (^)(SNTNotificationManager* mgr))push
             stubSIM:(void (^)(id sim, dispatch_block_t record))stubSIM {
  SNTNotificationManager* mgr = [[SNTNotificationManager alloc] init];
  id sim = OCMClassMock([SNTStatusItemManager class]);
  mgr.statusItemManager = sim;

  XCTestExpectation* called = [self expectationWithDescription:name];
  __block BOOL onMainThread = NO;
  stubSIM(sim, ^{
    onMainThread = [NSThread isMainThread];
    [called fulfill];
  });

  dispatch_async(dispatch_get_global_queue(0, 0), ^{
    push(mgr);
  });

  [self waitForExpectationsWithTimeout:5.0 handler:nil];
  XCTAssertTrue(onMainThread, @"%@ must reach SNTStatusItemManager on the main thread", name);
  [sim stopMocking];
}

- (void)testTemporaryAdminModeAvailableHopsToMainThread {
  [self verifyPush:@"temporaryAdminModeAvailable:"
      hopsToMainThread:^(SNTNotificationManager* mgr) {
        [mgr temporaryAdminModeAvailable:YES];
      }
      stubSIM:^(id sim, dispatch_block_t record) {
        OCMStub([sim setTemporaryAdminModeAvailable:YES]).andDo(^(NSInvocation* i) {
          record();
        });
      }];
}

- (void)testTemporaryMonitorModePolicyAvailableHopsToMainThread {
  [self verifyPush:@"temporaryMonitorModePolicyAvailable:"
      hopsToMainThread:^(SNTNotificationManager* mgr) {
        [mgr temporaryMonitorModePolicyAvailable:YES];
      }
      stubSIM:^(id sim, dispatch_block_t record) {
        OCMStub([sim setTemporaryMonitorModePolicyAvailable:YES]).andDo(^(NSInvocation* i) {
          record();
        });
      }];
}

- (void)testEnterTemporaryAdminModeHopsToMainThread {
  [self verifyPush:@"enterTemporaryAdminMode:"
      hopsToMainThread:^(SNTNotificationManager* mgr) {
        [mgr enterTemporaryAdminMode:[NSDate dateWithTimeIntervalSinceNow:600]];
      }
      stubSIM:^(id sim, dispatch_block_t record) {
        OCMStub([sim enterAdminModeWithExpiration:OCMOCK_ANY]).andDo(^(NSInvocation* i) {
          record();
        });
      }];
}

- (void)testLeaveTemporaryAdminModeHopsToMainThread {
  [self verifyPush:@"leaveTemporaryAdminMode"
      hopsToMainThread:^(SNTNotificationManager* mgr) {
        [mgr leaveTemporaryAdminMode];
      }
      stubSIM:^(id sim, dispatch_block_t record) {
        OCMStub([sim leaveAdminMode]).andDo(^(NSInvocation* i) {
          record();
        });
      }];
}

- (void)testEnterTemporaryMonitorModeHopsToMainThread {
  [self verifyPush:@"enterTemporaryMonitorMode:"
      hopsToMainThread:^(SNTNotificationManager* mgr) {
        [mgr enterTemporaryMonitorMode:[NSDate dateWithTimeIntervalSinceNow:600]];
      }
      stubSIM:^(id sim, dispatch_block_t record) {
        OCMStub([sim enterMonitorModeWithExpiration:OCMOCK_ANY]).andDo(^(NSInvocation* i) {
          record();
        });
      }];
}

- (void)testLeaveTemporaryMonitorModeHopsToMainThread {
  [self verifyPush:@"leaveTemporaryMonitorMode"
      hopsToMainThread:^(SNTNotificationManager* mgr) {
        [mgr leaveTemporaryMonitorMode];
      }
      stubSIM:^(id sim, dispatch_block_t record) {
        OCMStub([sim leaveMonitorMode]).andDo(^(NSInvocation* i) {
          record();
        });
      }];
}

@end
