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

#import "Source/santad/SNTNotificationQueue.h"

#import <Foundation/Foundation.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>

#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigState.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#include "Source/common/TestUtils.h"

@interface SNTNotificationQueue (Testing)
- (void)clearAllPendingWithRepliesSerialized;
@end

@interface SNTNotificationQueueTest : XCTestCase
@property santa::RingBuffer<NSMutableDictionary*>* ringbuf;
@property SNTNotificationQueue* sut;
@property id mockConnection;
@property id mockProxy;
@end

@implementation SNTNotificationQueueTest

- (void)setUp {
  auto rbUnique = std::make_unique<santa::RingBuffer<NSMutableDictionary*>>(3);
  self.ringbuf = rbUnique.get();
  self.sut = [[SNTNotificationQueue alloc] initWithRingBuffer:std::move(rbUnique)];

  self.mockConnection = OCMClassMock([MOLXPCConnection class]);
  self.mockProxy = OCMProtocolMock(@protocol(SNTNotifierXPC));

  // Setup mock connection to return mock proxy
  OCMStub([self.mockConnection remoteObjectProxy]).andReturn(self.mockProxy);
  [self.sut setNotifierConnection:self.mockConnection ownerUID:501];
}

- (void)testAddEventBasic {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  NSString* customMessage = @"custom msg";
  NSString* customURL = @"https://northpolesec.com";

  OCMExpect([self.mockProxy postBlockNotification:se
                                withCustomMessage:customMessage
                                        customURL:customURL
                            eventDetailButtonText:OCMOCK_ANY
                                      configState:OCMOCK_ANY
                                         andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* inv) {
        // Extract the reply block from the invocation and call it
        void (^__unsafe_unretained replyBlock)(BOOL);
        [inv getArgument:&replyBlock atIndex:7];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  [self.sut addEvent:se
          withCustomMessage:customMessage
                  customURL:customURL
      eventDetailButtonText:nil
                configState:nil
                   andReply:^(BOOL) {
                     dispatch_semaphore_signal(sema);
                   }];

  XCTAssertSemaTrue(sema, 3, "Reply block not called within expected window");
  OCMVerifyAll(self.mockProxy);
}

- (void)testAddEventNil {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  NSString* customMessage = @"custom msg";
  NSString* customURL = @"https://northpolesec.com";

  [self.sut addEvent:nil
          withCustomMessage:customMessage
                  customURL:customURL
      eventDetailButtonText:nil
                configState:OCMOCK_ANY
                   andReply:^(BOOL val) {
                     XCTAssertFalse(val);
                     dispatch_semaphore_signal(sema);
                   }];

  XCTAssertSemaTrue(sema, 3, "Reply block not called within expected window");

  OCMVerify(never(), [self.mockProxy postBlockNotification:OCMOCK_ANY
                                         withCustomMessage:OCMOCK_ANY
                                                 customURL:OCMOCK_ANY
                                     eventDetailButtonText:OCMOCK_ANY
                                               configState:OCMOCK_ANY
                                                  andReply:OCMOCK_ANY]);
}

// This test pre-populates the ring buffer to be full to ensure that when a newly added
// message forcefully dequeues the first item, the reply block is called with FALSE, as
// well as posting messages for everything in the queue.
- (void)testAddEventMulti {
  NSString* customMessage = @"custom msg";
  NSString* customURL = @"https://northpolesec.com";

  SNTStoredExecutionEvent* se1 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent* se2 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent* se3 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent* se4 = [[SNTStoredExecutionEvent alloc] init];

  XCTestExpectation* reply1Expectation = [self expectationWithDescription:@"Reply 1 called"];
  XCTestExpectation* reply2Expectation = [self expectationWithDescription:@"Reply 2 called"];
  XCTestExpectation* reply3Expectation = [self expectationWithDescription:@"Reply 3 called"];
  XCTestExpectation* reply4Expectation = [self expectationWithDescription:@"Reply 4 called"];

  void (^replyBlock1)(BOOL) = ^(BOOL val) {
    XCTAssertFalse(val);
    [reply1Expectation fulfill];
  };

  void (^replyBlock2)(BOOL) = ^(BOOL val) {
    XCTAssertTrue(val);
    [reply2Expectation fulfill];
  };

  void (^replyBlock3)(BOOL) = ^(BOOL val) {
    XCTAssertTrue(val);
    [reply3Expectation fulfill];
  };

  void (^replyBlock4)(BOOL) = ^(BOOL val) {
    XCTAssertTrue(val);
    [reply4Expectation fulfill];
  };

  // Create dictionaries to enqueue
  NSMutableDictionary* d1 = [NSMutableDictionary dictionary];
  [d1 setValue:se1 forKey:@"event"];
  [d1 setValue:@"Message 1" forKey:@"message"];
  [d1 setValue:@"https://northpolesec.com/1" forKey:@"url"];
  [d1 setValue:replyBlock1 forKey:@"reply"];

  NSMutableDictionary* d2 = [NSMutableDictionary dictionary];
  [d2 setValue:se2 forKey:@"event"];
  [d2 setValue:@"Message 2" forKey:@"message"];
  [d2 setValue:@"https://northpolesec.com/2" forKey:@"url"];
  [d2 setValue:replyBlock2 forKey:@"reply"];

  NSMutableDictionary* d3 = [NSMutableDictionary dictionary];
  [d3 setValue:se3 forKey:@"event"];
  [d3 setValue:@"Message 3" forKey:@"message"];
  [d3 setValue:@"https://northpolesec.com/3" forKey:@"url"];
  [d3 setValue:replyBlock3 forKey:@"reply"];

  self.ringbuf->Enqueue(d1);
  self.ringbuf->Enqueue(d2);
  self.ringbuf->Enqueue(d3);

  XCTAssertTrue(self.ringbuf->Full());
  XCTAssertFalse(self.ringbuf->Empty());

  // postBlockNotification should never be called for `se1` since it will fall out of the ring
  OCMVerify(never(), [self.mockProxy postBlockNotification:se1
                                         withCustomMessage:@"Message 1"
                                                 customURL:@"https://northpolesec.com/1"
                                     eventDetailButtonText:OCMOCK_ANY
                                               configState:OCMOCK_ANY
                                                  andReply:OCMOCK_ANY]);

  OCMExpect([self.mockProxy postBlockNotification:se2
                                withCustomMessage:@"Message 2"
                                        customURL:@"https://northpolesec.com/2"
                            eventDetailButtonText:OCMOCK_ANY
                                      configState:OCMOCK_ANY
                                         andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [invocation getArgument:&replyBlock atIndex:7];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  OCMExpect([self.mockProxy postBlockNotification:se3
                                withCustomMessage:@"Message 3"
                                        customURL:@"https://northpolesec.com/3"
                            eventDetailButtonText:OCMOCK_ANY
                                      configState:OCMOCK_ANY
                                         andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* invocation) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [invocation getArgument:&replyBlock atIndex:7];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  OCMExpect([self.mockProxy postBlockNotification:se4
                                withCustomMessage:customMessage
                                        customURL:customURL
                            eventDetailButtonText:OCMOCK_ANY
                                      configState:OCMOCK_ANY
                                         andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* inv) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [inv getArgument:&replyBlock atIndex:7];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  [self.sut addEvent:se4
          withCustomMessage:customMessage
                  customURL:customURL
      eventDetailButtonText:nil
                configState:nil
                   andReply:replyBlock4];

  [self waitForExpectationsWithTimeout:4.0 handler:nil];

  XCTAssertFalse(self.ringbuf->Full());
  XCTAssertTrue(self.ringbuf->Empty());

  OCMVerifyAll(self.mockProxy);
}

- (void)testClearAllPendingWithRepliesSerialized {
  SNTStoredExecutionEvent* se1 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent* se2 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent* se3 = [[SNTStoredExecutionEvent alloc] init];

  // Setup expectations for reply blocks
  XCTestExpectation* reply1Expectation =
      [self expectationWithDescription:@"Reply 1 called with NO"];
  XCTestExpectation* reply2Expectation =
      [self expectationWithDescription:@"Reply 2 called with NO"];

  void (^replyBlock1)(BOOL) = ^(BOOL val) {
    XCTAssertFalse(val);
    [reply1Expectation fulfill];
  };
  void (^replyBlock2)(BOOL) = ^(BOOL val) {
    XCTAssertFalse(val);
    [reply2Expectation fulfill];
  };

  // Create dictionaries to enqueue
  NSMutableDictionary* d1 = [NSMutableDictionary dictionary];
  [d1 setValue:se1 forKey:@"event"];
  [d1 setValue:@"Message 1" forKey:@"message"];
  [d1 setValue:@"https://northpolesec.com/1" forKey:@"url"];
  [d1 setValue:[replyBlock1 copy] forKey:@"reply"];

  NSMutableDictionary* d2 = [NSMutableDictionary dictionary];
  [d2 setValue:se2 forKey:@"event"];
  [d2 setValue:@"Message 2" forKey:@"message"];
  [d2 setValue:@"https://northpolesec.com/2" forKey:@"url"];
  [d2 setValue:[replyBlock2 copy] forKey:@"reply"];

  // Create dictionary with no reply block
  NSMutableDictionary* d3 = [NSMutableDictionary dictionary];
  [d3 setValue:se3 forKey:@"event"];
  [d3 setValue:@"Message 3" forKey:@"message"];
  [d3 setValue:@"https://northpolesec.com/3" forKey:@"url"];
  // Intentionally not setting a reply block for d3

  self.ringbuf->Enqueue(d1);
  self.ringbuf->Enqueue(d2);
  self.ringbuf->Enqueue(d3);

  XCTAssertTrue(self.ringbuf->Full());
  XCTAssertFalse(self.ringbuf->Empty());

  [self.sut clearAllPendingWithRepliesSerialized];

  // Wait for the reply blocks to be called
  [self waitForExpectationsWithTimeout:1.0 handler:nil];

  // Check the ring is no longer full (entries with replyBlocks were removed)
  XCTAssertFalse(self.ringbuf->Full());
  XCTAssertFalse(self.ringbuf->Empty());

  // There should only be one item left in the ringbuf, d3, which didn't have a replyBlock
  NSMutableDictionary* d = self.ringbuf->Dequeue().value_or(nil);
  XCTAssertNotNil(d);
  XCTAssertEqualObjects(d, d3);

  XCTAssertTrue(self.ringbuf->Empty());
}

// Patch 1: with no GUI connection, the TAM auth request must invoke its reply
// synchronously with (NO, @"") rather than leaving it uninvoked — otherwise the
// daemon-side grant stalls its full fail-closed timeout.
- (void)testAuthorizeTemporaryAdminModeNoConnectionFailsClosed {
  [self.sut setNotifierConnection:nil ownerUID:501];
  XCTAssertEqual(self.sut.notifierOwnerUID, kSNTNotifierNoOwner);

  __block BOOL replied = NO;
  __block BOOL gotAuthed = YES;
  __block NSString* gotReason = nil;
  [self.sut authorizeTemporaryAdminModeForUID:501
                       requiringJustification:YES
                                        reply:^(BOOL authed, NSString* reason) {
                                          replied = YES;
                                          gotAuthed = authed;
                                          gotReason = reason;
                                        }];

  XCTAssertTrue(replied);  // invoked synchronously, no stall
  XCTAssertFalse(gotAuthed);
  XCTAssertEqualObjects(gotReason, @"");
}

// Patch 1: if the synchronous proxy returns without ever invoking the reply block
// (e.g. the GUI died mid-auth), the queue must still fail closed synchronously.
- (void)testAuthorizeTemporaryAdminModeProxyNeverRepliesFailsClosed {
  OCMStub([self.mockConnection synchronousRemoteObjectProxy]).andReturn(self.mockProxy);
  // Proxy accepts the call but never runs the reply block.
  OCMStub([self.mockProxy authorizeTemporaryAdminModeRequiringJustification:YES
                                                                      reply:[OCMArg any]]);

  __block BOOL replied = NO;
  __block BOOL gotAuthed = YES;
  [self.sut authorizeTemporaryAdminModeForUID:501
                       requiringJustification:YES
                                        reply:^(BOOL authed, NSString* reason) {
                                          replied = YES;
                                          gotAuthed = authed;
                                        }];

  XCTAssertTrue(replied);  // fail-fast via the replied guard
  XCTAssertFalse(gotAuthed);
}

#pragma mark - Temporary Admin Mode: the prompt only vouches for the connection's owner

// The GUI was registered from uid 501's session. A grant for any other uid is refused without
// the GUI being asked.
- (void)testAuthorizeTemporaryAdminModeForAnotherUserNeverReachesTheGUI {
  OCMStub([self.mockConnection synchronousRemoteObjectProxy]).andReturn(self.mockProxy);
  OCMReject([self.mockProxy authorizeTemporaryAdminModeRequiringJustification:YES
                                                                        reply:[OCMArg any]]);
  OCMReject([self.mockProxy authorizeTemporaryAdminModeRequiringJustification:NO
                                                                        reply:[OCMArg any]]);

  __block BOOL replied = NO;
  __block BOOL gotAuthed = YES;
  __block NSString* gotReason = nil;
  [self.sut authorizeTemporaryAdminModeForUID:502
                       requiringJustification:YES
                                        reply:^(BOOL authed, NSString* reason) {
                                          replied = YES;
                                          gotAuthed = authed;
                                          gotReason = reason;
                                        }];

  XCTAssertTrue(replied);  // synchronously, so the grant fails fast
  XCTAssertFalse(gotAuthed);
  XCTAssertEqualObjects(gotReason, @"");
  OCMVerifyAll(self.mockProxy);
}

- (void)testAuthorizeTemporaryAdminModeForTheOwnerReachesTheGUI {
  OCMStub([self.mockConnection synchronousRemoteObjectProxy]).andReturn(self.mockProxy);
  OCMStub([self.mockProxy
      authorizeTemporaryAdminModeRequiringJustification:YES
                                                  reply:([OCMArg invokeBlockWithArgs:@YES,
                                                                                     @"reason",
                                                                                     nil])]);

  __block BOOL gotAuthed = NO;
  __block NSString* gotReason = nil;
  [self.sut authorizeTemporaryAdminModeForUID:501
                       requiringJustification:YES
                                        reply:^(BOOL authed, NSString* reason) {
                                          gotAuthed = authed;
                                          gotReason = reason;
                                        }];

  XCTAssertTrue(gotAuthed);
  XCTAssertEqualObjects(gotReason, @"reason");
}

// Replacing the connection (a GUI registered from another session, as on a fast user switch)
// replaces its owner with it, and the two are read together.
- (void)testReplacingTheNotifierReplacesItsOwner {
  id otherConnection = OCMClassMock([MOLXPCConnection class]);
  id otherProxy = OCMProtocolMock(@protocol(SNTNotifierXPC));
  OCMStub([otherConnection remoteObjectProxy]).andReturn(otherProxy);
  OCMStub([otherConnection synchronousRemoteObjectProxy]).andReturn(otherProxy);
  OCMStub([self.mockConnection synchronousRemoteObjectProxy]).andReturn(self.mockProxy);

  [self.sut setNotifierConnection:otherConnection ownerUID:502];
  XCTAssertEqual(self.sut.notifierConnection, otherConnection);
  XCTAssertEqual(self.sut.notifierOwnerUID, 502u);

  // uid 501 owned the previous connection; it must not be asked on either GUI now.
  OCMReject([self.mockProxy authorizeTemporaryAdminModeRequiringJustification:NO
                                                                        reply:[OCMArg any]]);
  OCMReject([otherProxy authorizeTemporaryAdminModeRequiringJustification:NO reply:[OCMArg any]]);
  __block BOOL gotAuthed = YES;
  [self.sut authorizeTemporaryAdminModeForUID:501
                       requiringJustification:NO
                                        reply:^(BOOL authed, NSString* reason) {
                                          gotAuthed = authed;
                                        }];
  XCTAssertFalse(gotAuthed);
  OCMVerifyAll(self.mockProxy);
  OCMVerifyAll(otherProxy);
}

// An invalidation of a connection that has already been replaced must not drop its successor
// (nor the successor's owner), but must answer the notifications still waiting on the dead
// connection: XPC drops their replies, and a held execution would otherwise stay stopped.
- (void)testStaleInvalidationDoesNotDropTheReplacementNotifier {
  __block void (^firstHandler)(void) = nil;
  id firstConnection = OCMClassMock([MOLXPCConnection class]);
  id firstProxy = OCMProtocolMock(@protocol(SNTNotifierXPC));
  OCMStub([firstConnection remoteObjectProxy]).andReturn(firstProxy);
  OCMStub([firstConnection setInvalidationHandler:[OCMArg checkWithBlock:^BOOL(id handler) {
                             firstHandler = [handler copy];
                             return YES;
                           }]]);
  [self.sut setNotifierConnection:firstConnection ownerUID:501];
  XCTAssertNotNil(firstHandler);

  // One notification is sent to each GUI, and neither GUI answers.
  __block int firstReplies = 0;
  __block BOOL firstAnswer = YES;
  [self.sut addEvent:[[SNTStoredExecutionEvent alloc] init]
          withCustomMessage:nil
                  customURL:nil
      eventDetailButtonText:nil
                configState:nil
                   andReply:^(BOOL authenticated) {
                     firstReplies++;
                     firstAnswer = authenticated;
                   }];
  [self.sut setNotifierConnection:self.mockConnection ownerUID:502];
  __block int secondReplies = 0;
  [self.sut addEvent:[[SNTStoredExecutionEvent alloc] init]
          withCustomMessage:nil
                  customURL:nil
      eventDetailButtonText:nil
                configState:nil
                   andReply:^(BOOL authenticated) {
                     secondReplies++;
                   }];

  firstHandler();

  XCTAssertEqual(self.sut.notifierConnection, self.mockConnection);
  XCTAssertEqual(self.sut.notifierOwnerUID, 502u);
  XCTAssertEqual(firstReplies, 1);
  XCTAssertFalse(firstAnswer);
  XCTAssertEqual(secondReplies, 0);  // still the replacement GUI's to answer
}

// A notifier whose connection hands out a proxy that keeps each notification's reply, so the test
// can answer it later as the GUI would.
- (id)connectionKeepingReply:(__strong NotificationReplyBlock*)reply
         invalidationHandler:(__strong void (^*)(void))handler {
  id connection = OCMClassMock([MOLXPCConnection class]);
  id proxy = OCMProtocolMock(@protocol(SNTNotifierXPC));
  OCMStub([connection remoteObjectProxy]).andReturn(proxy);
  OCMStub([connection setInvalidationHandler:[OCMArg checkWithBlock:^BOOL(id h) {
                        *handler = [h copy];
                        return YES;
                      }]]);
  OCMStub([proxy postBlockNotification:OCMOCK_ANY
                     withCustomMessage:OCMOCK_ANY
                             customURL:OCMOCK_ANY
                 eventDetailButtonText:OCMOCK_ANY
                           configState:OCMOCK_ANY
                              andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation* inv) {
        void (^__unsafe_unretained r)(BOOL);
        [inv getArgument:&r atIndex:7];
        *reply = [r copy];
      });
  return connection;
}

// When the current GUI's connection dies, only the notifications sent over it are answered. A GUI
// that was replaced but is still alive (a fast user switch) keeps its prompt, and its user's
// answer is the one that counts. Whichever answer comes first wins: a reply never runs twice.
- (void)testInvalidationAnswersOnlyItsOwnNotificationsAndEachOnlyOnce {
  NotificationReplyBlock guiAnswerA = nil, guiAnswerB = nil;
  void (^handlerA)(void) = nil, (^handlerB)(void) = nil;
  id connA = [self connectionKeepingReply:&guiAnswerA invalidationHandler:&handlerA];
  id connB = [self connectionKeepingReply:&guiAnswerB invalidationHandler:&handlerB];

  __block int repliesA = 0, repliesB = 0, repliesC = 0;
  __block BOOL answerA = NO, answerC = YES;
  [self.sut setNotifierConnection:connA ownerUID:501];
  [self.sut addEvent:[[SNTStoredExecutionEvent alloc] init]
          withCustomMessage:nil
                  customURL:nil
      eventDetailButtonText:nil
                configState:nil
                   andReply:^(BOOL authenticated) {
                     repliesA++;
                     answerA = authenticated;
                   }];
  [self.sut setNotifierConnection:connB ownerUID:502];
  [self.sut addEvent:[[SNTStoredExecutionEvent alloc] init]
          withCustomMessage:nil
                  customURL:nil
      eventDetailButtonText:nil
                configState:nil
                   andReply:^(BOOL authenticated) {
                     repliesB++;
                   }];
  XCTAssertNotNil(guiAnswerA);
  XCTAssertNotNil(guiAnswerB);

  // B, the current GUI, dies: its own prompt is answered NO, and A's is left open.
  handlerB();
  XCTAssertNil(self.sut.notifierConnection);
  XCTAssertEqual(repliesB, 1);
  XCTAssertEqual(repliesA, 0);

  // With no GUI connected, a new notification is answered NO at once, and A's is still left open.
  [self.sut addEvent:[[SNTStoredExecutionEvent alloc] init]
          withCustomMessage:nil
                  customURL:nil
      eventDetailButtonText:nil
                configState:nil
                   andReply:^(BOOL authenticated) {
                     repliesC++;
                     answerC = authenticated;
                   }];
  XCTAssertEqual(repliesC, 1);
  XCTAssertFalse(answerC);
  XCTAssertEqual(repliesA, 0);

  // A's user approves: that answer is the one that counts.
  guiAnswerA(YES);
  XCTAssertEqual(repliesA, 1);
  XCTAssertTrue(answerA);

  // Answers that arrive after the notification was already answered run nothing.
  guiAnswerB(YES);
  handlerA();
  guiAnswerA(NO);
  XCTAssertEqual(repliesB, 1);
  XCTAssertEqual(repliesA, 1);
  XCTAssertTrue(answerA);
}

@end
