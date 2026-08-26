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
#import "Source/gui/SNTTimedRuleKillMessageWindowController.h"

#import "Source/common/SNTConfigBundle.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredNetworkFlowEvent.h"

@class SNTBinaryMessageWindowController;

@interface SNTNotificationManager (Testing)
@property(readonly) NSMutableArray* pendingNotifications;
- (void)hashBundleBinariesForEvent:(SNTStoredEvent*)event
                    withController:(SNTBinaryMessageWindowController*)controller;
- (void)queueMessage:(SNTMessageWindowController*)pendingMsg enableSilences:(BOOL)enableSilences;
- (void)showQueuedWindow;
@end

// Overrides only messageHash, to confirm the base queueDedupeHash defaults to it.
@interface DedupeHashPassthroughController : SNTMessageWindowController
@end

@implementation DedupeHashPassthroughController
- (NSString*)messageHash {
  return @"passthrough-key";
}
@end

// A real NSWindow that refuses to come on screen. Nothing any test here asserts
// needs a window to be visible: a dialog is closed through -close and its
// delegate, both of which work the same off screen.
@interface OffScreenWindow : NSWindow
@end

@implementation OffScreenWindow
- (instancetype)init {
  return [super initWithContentRect:NSZeroRect
                          styleMask:NSWindowStyleMaskTitled
                            backing:NSBackingStoreBuffered
                              defer:NO];
}

- (void)makeKeyAndOrderFront:(id)sender {
}
@end

@interface SNTNotificationManagerTest : XCTestCase
@property id mockConfigurator;
@property id mockWindowControllerClass;
@property NSApplicationActivationPolicy savedActivationPolicy;
@end

@implementation SNTNotificationManagerTest

- (void)setUp {
  [super setUp];
  fclose(stdout);

  // Nothing in this suite may reach the screen. Several tests here run the real
  // queueMessage:, which shows the dialog it accepted, so without these two lines
  // a test run puts santa dialogs in front of whoever is running it: an xctest
  // bundle has a real WindowServer connection and a live NSApplication.
  //
  // +defaultWindow is the single place any message window controller gets its
  // window, so handing back one that refuses to be ordered in covers every path,
  // and a prohibited activation policy makes the base class's
  // [NSApp activateIgnoringOtherApps:YES] a no-op.
  self.mockWindowControllerClass = OCMClassMock([SNTMessageWindowController class]);
  OCMStub([self.mockWindowControllerClass defaultWindow]).andReturn([[OffScreenWindow alloc] init]);
  self.savedActivationPolicy = NSApp.activationPolicy;
  [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
}

- (void)tearDown {
  // Class mocks swizzle the class itself, so they have to be undone or they
  // follow the process into the next test. The activation policy is process
  // state too, so it goes back to whatever it was before setUp changed it.
  [NSApp setActivationPolicy:self.savedActivationPolicy];
  [self.mockConfigurator stopMocking];
  [self.mockWindowControllerClass stopMocking];
  [super tearDown];
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
       eventDetailButtonText:nil
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

#pragma mark Timed rule kill warning

- (void)mockSilentMode:(BOOL)silent {
  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
  OCMStub([self.mockConfigurator enableSilentMode]).andReturn(silent);
}

// Every window the message-window base class hands out for the rest of the test
// is one that cannot come on screen. +defaultWindow is the single place any
// controller gets its window, so stubbing it is enough to keep a test run silent
// no matter which path ends up creating a window.
//
// The warning is a window on the block-dialog queue, not a UNUserNotificationCenter
// banner, because Do Not Disturb and Focus modes suppress banners. Silences stay
// off: a warning that something is about to be quit is not silenceable per app.
- (void)testPostTimedRuleKillNotificationQueuesAWindow {
  SNTNotificationManager* mgr = [[SNTNotificationManager alloc] init];
  id mgrMock = OCMPartialMock(mgr);
  OCMExpect([mgrMock
        queueMessage:[OCMArg isKindOfClass:[SNTTimedRuleKillMessageWindowController class]]
      enableSilences:NO]);

  [mgr postTimedRuleKillNotificationForApplication:@"Calculator"
                                          deadline:[NSDate dateWithTimeIntervalSinceNow:600]];

  OCMVerifyAll(mgrMock);
  [mgrMock stopMocking];
}

- (void)testPostTimedRuleKillNotificationIgnoresIncompleteWarnings {
  SNTNotificationManager* mgr = [[SNTNotificationManager alloc] init];
  id mgrMock = OCMPartialMock(mgr);
  OCMReject([mgrMock queueMessage:OCMOCK_ANY enableSilences:NO]);

  [mgr postTimedRuleKillNotificationForApplication:nil
                                          deadline:[NSDate dateWithTimeIntervalSinceNow:600]];
  // An empty name has no identity either: its messageHash is nil, so repeats
  // would stack rather than collapse.
  [mgr postTimedRuleKillNotificationForApplication:@""
                                          deadline:[NSDate dateWithTimeIntervalSinceNow:600]];
  [mgr postTimedRuleKillNotificationForApplication:@"Calculator" deadline:nil];

  OCMVerifyAll(mgrMock);
  [mgrMock stopMocking];
}

// One window per (application, deadline): the queue collapses on this key, so a
// repeated warning for the same deadline cannot stack a second window, while a
// moved deadline or a different application still gets its own.
- (void)testTimedRuleKillWindowIdentityIsApplicationAndDeadline {
  NSDate* deadline = [NSDate dateWithTimeIntervalSince1970:1660221048];
  NSString* (^key)(NSString*, NSDate*) = ^(NSString* app, NSDate* d) {
    return [[[SNTTimedRuleKillMessageWindowController alloc] initWithApplication:app deadline:d]
        queueDedupeHash];
  };

  XCTAssertEqualObjects(key(@"Calculator", deadline), key(@"Calculator", deadline));
  XCTAssertNotEqualObjects(key(@"Calculator", deadline),
                           key(@"Calculator", [deadline dateByAddingTimeInterval:60]));
  XCTAssertNotEqualObjects(key(@"Calculator", deadline), key(@"Chess", deadline));
}

// Silent mode is enforced once, by the queue, so the warning path carries no gate
// of its own. Both rows run the real queueMessage: and differ only in the
// configurator's answer.
- (void)testTimedRuleKillWarningIsQueuedUnlessSilentMode {
  for (NSNumber* silent in @[ @NO, @YES ]) {
    [self mockSilentMode:silent.boolValue];

    SNTNotificationManager* mgr = [[SNTNotificationManager alloc] init];
    id mgrMock = OCMPartialMock(mgr);
    // What the queue accepted is the assertion; presentation is stubbed out so
    // the test cannot put anything on screen.
    OCMStub([mgrMock showQueuedWindow]).andDo(nil);

    [mgr postTimedRuleKillNotificationForApplication:@"Calculator"
                                            deadline:[NSDate dateWithTimeIntervalSinceNow:600]];

    // queueMessage: finishes its bookkeeping in a block on the main queue, so
    // hop through that queue to let the block run before asserting.
    XCTestExpectation* drained = [self expectationWithDescription:@"main queue drained"];
    dispatch_async(dispatch_get_main_queue(), ^{
      [drained fulfill];
    });
    [self waitForExpectationsWithTimeout:5.0 handler:nil];

    XCTAssertEqual(mgr.pendingNotifications.count, silent.boolValue ? 0u : 1u);

    [mgrMock stopMocking];
    [self.mockConfigurator stopMocking];
    self.mockConfigurator = nil;
  }
}

// Queues a warning for real and hands back the manager once the queue has retired
// it again. The manager's own cleanup callback is the signal, so what is being
// waited on is the queue advancing, not merely a window closing.
- (SNTNotificationManager*)queueUntilRetired:(SNTMessageWindowController*)controller
                                 describedAs:(NSString*)description
                                  onRetiring:(void (^)(void))onRetiring {
  [self mockSilentMode:NO];

  SNTNotificationManager* mgr = [[SNTNotificationManager alloc] init];
  id mgrMock = OCMPartialMock(mgr);

  XCTestExpectation* retired = [self expectationWithDescription:description];
  OCMStub([mgrMock windowDidCloseSilenceHash:OCMOCK_ANY withInterval:0])
      .andDo(^(NSInvocation* i) {
        onRetiring();
        [retired fulfill];
      })
      .andForwardToRealObject();

  [mgr queueMessage:controller enableSilences:NO];

  [self waitForExpectationsWithTimeout:10.0 handler:nil];
  [mgrMock stopMocking];
  return mgr;
}

// The warning stops being true at its deadline, and it holds the one dialog slot
// until it closes, so it closes itself with nobody touching it.
- (void)testTimedRuleKillWindowClosesItselfAtTheDeadline {
  SNTTimedRuleKillMessageWindowController* controller =
      [[SNTTimedRuleKillMessageWindowController alloc]
          initWithApplication:@"Calculator"
                     deadline:[NSDate dateWithTimeIntervalSinceNow:0.25]];

  // The window was stood up and its delegate wired, which is what the deadline
  // timer closed. windowWillClose: runs while the window is still in the screen
  // list, so a window that had been displayed would read visible here: that is
  // the assertion that keeps the suite from ever flashing a dialog.
  dispatch_block_t nothingWasSeen = ^{
    XCTAssertNotNil(controller.window);
    XCTAssertFalse(controller.window.isVisible);
  };

  SNTNotificationManager* mgr = [self queueUntilRetired:controller
                                            describedAs:@"warning closed itself at its deadline"
                                             onRetiring:nothingWasSeen];

  XCTAssertEqual(mgr.pendingNotifications.count, 0u);
}

// A warning whose deadline passed while it waited behind another dialog must not
// be drawn at all: it says something untrue and would steal focus on its way out.
// It still has to be retired through the delegate, or it would hold the one dialog
// slot and everything behind it would wait on it forever.
- (void)testExpiredTimedRuleKillWindowIsRetiredWithoutBeingShown {
  SNTTimedRuleKillMessageWindowController* controller =
      [[SNTTimedRuleKillMessageWindowController alloc]
          initWithApplication:@"Calculator"
                     deadline:[NSDate dateWithTimeIntervalSinceNow:-1]];

  // No window was ever built, so there was nothing to order in, draw, or activate.
  dispatch_block_t noWindowAtAll = ^{
    XCTAssertNil(controller.window);
  };

  SNTNotificationManager* mgr =
      [self queueUntilRetired:controller
                  describedAs:@"expired warning retired without being shown"
                   onRetiring:noWindowAtAll];

  XCTAssertEqual(mgr.pendingNotifications.count, 0u);
}

@end
