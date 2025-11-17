/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
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
@property santa::RingBuffer<NSMutableDictionary *> *ringbuf;
@property SNTNotificationQueue *sut;
@property id mockConnection;
@property id mockProxy;
@end

@implementation SNTNotificationQueueTest

- (void)setUp {
  auto rbUnique = std::make_unique<santa::RingBuffer<NSMutableDictionary *>>(3);
  self.ringbuf = rbUnique.get();
  self.sut = [[SNTNotificationQueue alloc] initWithRingBuffer:std::move(rbUnique)];

  self.mockConnection = OCMClassMock([MOLXPCConnection class]);
  self.mockProxy = OCMProtocolMock(@protocol(SNTNotifierXPC));

  // Setup mock connection to return mock proxy
  OCMStub([self.mockConnection remoteObjectProxy]).andReturn(self.mockProxy);
  self.sut.notifierConnection = self.mockConnection;
}

- (void)testAddEventBasic {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];
  NSString *customMessage = @"custom msg";
  NSURL *customURL = [NSURL URLWithString:@"https://northpolesec.com"];

  OCMExpect([self.mockProxy postBlockNotification:se
                                withCustomMessage:customMessage
                                        customURL:customURL
                                      configState:OCMOCK_ANY
                                         andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation *inv) {
        // Extract the reply block from the invocation and call it
        void (^__unsafe_unretained replyBlock)(BOOL);
        [inv getArgument:&replyBlock atIndex:6];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  [self.sut addEvent:se
      withCustomMessage:customMessage
              customURL:customURL
            configState:nil
               andReply:^(BOOL) {
                 dispatch_semaphore_signal(sema);
               }];

  XCTAssertSemaTrue(sema, 3, "Reply block not called within expected window");
  OCMVerifyAll(self.mockProxy);
}

- (void)testAddEventNil {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  NSString *customMessage = @"custom msg";
  NSURL *customURL = [NSURL URLWithString:@"https://northpolesec.com"];

  [self.sut addEvent:nil
      withCustomMessage:customMessage
              customURL:customURL
            configState:OCMOCK_ANY
               andReply:^(BOOL val) {
                 XCTAssertFalse(val);
                 dispatch_semaphore_signal(sema);
               }];

  XCTAssertSemaTrue(sema, 3, "Reply block not called within expected window");

  OCMVerify(never(), [self.mockProxy postBlockNotification:OCMOCK_ANY
                                         withCustomMessage:OCMOCK_ANY
                                                 customURL:OCMOCK_ANY
                                               configState:OCMOCK_ANY
                                                  andReply:OCMOCK_ANY]);
}

// This test pre-populates the ring buffer to be full to ensure that when a newly added
// message forcefully dequeues the first item, the reply block is called with FALSE, as
// well as posting messages for everything in the queue.
- (void)testAddEventMulti {
  NSString *customMessage = @"custom msg";
  NSURL *customURL = [NSURL URLWithString:@"https://northpolesec.com"];

  SNTStoredExecutionEvent *se1 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent *se2 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent *se3 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent *se4 = [[SNTStoredExecutionEvent alloc] init];

  XCTestExpectation *reply1Expectation = [self expectationWithDescription:@"Reply 1 called"];
  XCTestExpectation *reply2Expectation = [self expectationWithDescription:@"Reply 2 called"];
  XCTestExpectation *reply3Expectation = [self expectationWithDescription:@"Reply 3 called"];
  XCTestExpectation *reply4Expectation = [self expectationWithDescription:@"Reply 4 called"];

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
  NSMutableDictionary *d1 = [NSMutableDictionary dictionary];
  [d1 setValue:se1 forKey:@"event"];
  [d1 setValue:@"Message 1" forKey:@"message"];
  [d1 setValue:[NSURL URLWithString:@"https://northpolesec.com/1"] forKey:@"url"];
  [d1 setValue:replyBlock1 forKey:@"reply"];

  NSMutableDictionary *d2 = [NSMutableDictionary dictionary];
  [d2 setValue:se2 forKey:@"event"];
  [d2 setValue:@"Message 2" forKey:@"message"];
  [d2 setValue:[NSURL URLWithString:@"https://northpolesec.com/2"] forKey:@"url"];
  [d2 setValue:replyBlock2 forKey:@"reply"];

  NSMutableDictionary *d3 = [NSMutableDictionary dictionary];
  [d3 setValue:se3 forKey:@"event"];
  [d3 setValue:@"Message 3" forKey:@"message"];
  [d3 setValue:[NSURL URLWithString:@"https://northpolesec.com/3"] forKey:@"url"];
  [d3 setValue:replyBlock3 forKey:@"reply"];

  self.ringbuf->Enqueue(d1);
  self.ringbuf->Enqueue(d2);
  self.ringbuf->Enqueue(d3);

  XCTAssertTrue(self.ringbuf->Full());
  XCTAssertFalse(self.ringbuf->Empty());

  // postBlockNotification should never be called for `se1` since it will fall out of the ring
  OCMVerify(never(), [self.mockProxy
                         postBlockNotification:se1
                             withCustomMessage:@"Message 1"
                                     customURL:[NSURL URLWithString:@"https://northpolesec.com/1"]
                                   configState:OCMOCK_ANY
                                      andReply:OCMOCK_ANY]);

  OCMExpect([self.mockProxy
                postBlockNotification:se2
                    withCustomMessage:@"Message 2"
                            customURL:[NSURL URLWithString:@"https://northpolesec.com/2"]
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation *invocation) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [invocation getArgument:&replyBlock atIndex:6];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  OCMExpect([self.mockProxy
                postBlockNotification:se3
                    withCustomMessage:@"Message 3"
                            customURL:[NSURL URLWithString:@"https://northpolesec.com/3"]
                          configState:OCMOCK_ANY
                             andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation *invocation) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [invocation getArgument:&replyBlock atIndex:6];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  OCMExpect([self.mockProxy postBlockNotification:se4
                                withCustomMessage:customMessage
                                        customURL:customURL
                                      configState:OCMOCK_ANY
                                         andReply:OCMOCK_ANY])
      .andDo(^(NSInvocation *inv) {
        void (^__unsafe_unretained replyBlock)(BOOL);
        [inv getArgument:&replyBlock atIndex:6];
        // Note: The replyBlock must be called asynchronously
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
          replyBlock(YES);
        });
      });

  [self.sut addEvent:se4
      withCustomMessage:customMessage
              customURL:customURL
            configState:nil
               andReply:replyBlock4];

  [self waitForExpectationsWithTimeout:4.0 handler:nil];

  XCTAssertFalse(self.ringbuf->Full());
  XCTAssertTrue(self.ringbuf->Empty());

  OCMVerifyAll(self.mockProxy);
}

- (void)testClearAllPendingWithRepliesSerialized {
  SNTStoredExecutionEvent *se1 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent *se2 = [[SNTStoredExecutionEvent alloc] init];
  SNTStoredExecutionEvent *se3 = [[SNTStoredExecutionEvent alloc] init];

  // Setup expectations for reply blocks
  XCTestExpectation *reply1Expectation =
      [self expectationWithDescription:@"Reply 1 called with NO"];
  XCTestExpectation *reply2Expectation =
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
  NSMutableDictionary *d1 = [NSMutableDictionary dictionary];
  [d1 setValue:se1 forKey:@"event"];
  [d1 setValue:@"Message 1" forKey:@"message"];
  [d1 setValue:[NSURL URLWithString:@"https://northpolesec.com/1"] forKey:@"url"];
  [d1 setValue:[replyBlock1 copy] forKey:@"reply"];

  NSMutableDictionary *d2 = [NSMutableDictionary dictionary];
  [d2 setValue:se2 forKey:@"event"];
  [d2 setValue:@"Message 2" forKey:@"message"];
  [d2 setValue:[NSURL URLWithString:@"https://northpolesec.com/2"] forKey:@"url"];
  [d2 setValue:[replyBlock2 copy] forKey:@"reply"];

  // Create dictionary with no reply block
  NSMutableDictionary *d3 = [NSMutableDictionary dictionary];
  [d3 setValue:se3 forKey:@"event"];
  [d3 setValue:@"Message 3" forKey:@"message"];
  [d3 setValue:[NSURL URLWithString:@"https://northpolesec.com/3"] forKey:@"url"];
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
  NSMutableDictionary *d = self.ringbuf->Dequeue().value_or(nil);
  XCTAssertNotNil(d);
  XCTAssertEqualObjects(d, d3);

  XCTAssertTrue(self.ringbuf->Empty());
}

@end
