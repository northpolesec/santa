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

#import <XCTest/XCTest.h>

#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/gui/SNTBinaryMessageWindowController.h"

@interface SNTBinaryMessageWindowControllerTest : XCTestCase
@end

@implementation SNTBinaryMessageWindowControllerTest

- (SNTBinaryMessageWindowController*)controllerForEvent:(SNTStoredExecutionEvent*)event {
  return [[SNTBinaryMessageWindowController alloc] initWithEvent:event
                                                       customMsg:nil
                                                       customURL:nil
                                           eventDetailButtonText:nil
                                                     configState:nil
                                                           reply:nil];
}

- (SNTStoredExecutionEvent*)eventWithHash {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.fileSHA256 = @"abc123";
  se.filePath = @"/tmp/thing";
  se.decision = SNTEventStateBlockUnknown;
  return se;
}

- (void)testMessageHashIsTheBinaryHashForAVerifiedRead {
  XCTAssertEqualObjects([[self controllerForEvent:[self eventWithHash]] messageHash],
                        @"binary:abc123");
}

// A hash read without identity confirmation doesn't identify the running image,
// so it is not used as a silence key.
- (void)testMessageHashIsNilForAnUnverifiedRead {
  SNTStoredExecutionEvent* se = [self eventWithHash];
  se.identityUnverified = YES;
  se.identityVendorMatched = NO;

  XCTAssertNil([[self controllerForEvent:se] messageHash]);
}

- (void)testMessageHashIsUnchangedForAVendorMatchedRead {
  SNTStoredExecutionEvent* se = [self eventWithHash];
  se.identityUnverified = YES;
  se.identityVendorMatched = YES;

  XCTAssertEqualObjects([[self controllerForEvent:se] messageHash], @"binary:abc123");
}

- (void)testMessageHashIsNilWithoutAHash {
  SNTStoredExecutionEvent* se = [self eventWithHash];
  se.fileSHA256 = nil;

  XCTAssertNil([[self controllerForEvent:se] messageHash]);
}

- (SNTStoredExecutionEvent*)unverifiedEventWithPath:(NSString*)path hash:(NSString*)hash {
  SNTStoredExecutionEvent* se = [self eventWithHash];
  se.filePath = path;
  se.fileSHA256 = hash;
  se.identityUnverified = YES;
  se.identityVendorMatched = NO;
  return se;
}

- (void)testUnverifiedBlocksForOnePathCollapseButStayUnsilenceable {
  SNTBinaryMessageWindowController* a =
      [self controllerForEvent:[self unverifiedEventWithPath:@"/tmp/thing" hash:@"aaa"]];
  SNTBinaryMessageWindowController* b =
      [self controllerForEvent:[self unverifiedEventWithPath:@"/tmp/thing" hash:@"bbb"]];

  XCTAssertNotNil([a queueDedupeHash]);
  XCTAssertEqualObjects([a queueDedupeHash], [b queueDedupeHash]);

  XCTAssertNil([a messageHash]);
  XCTAssertNil([b messageHash]);
  XCTAssertNotEqualObjects([a queueDedupeHash], @"binary:aaa");
}

- (void)testUnverifiedBlocksForDifferentPathsDoNotCollapse {
  SNTBinaryMessageWindowController* a =
      [self controllerForEvent:[self unverifiedEventWithPath:@"/tmp/thing" hash:@"aaa"]];
  SNTBinaryMessageWindowController* b =
      [self controllerForEvent:[self unverifiedEventWithPath:@"/tmp/other" hash:@"aaa"]];

  XCTAssertNotEqualObjects([a queueDedupeHash], [b queueDedupeHash]);
}

- (void)testUnverifiedHeldResponsesAreNotDeduped {
  SNTStoredExecutionEvent* se = [self unverifiedEventWithPath:@"/tmp/thing" hash:@"aaa"];
  se.holdAndAsk = YES;

  XCTAssertNil([[self controllerForEvent:se] queueDedupeHash]);
}

- (void)testQueueDedupeHashIsTheSilenceKeyForAVerifiedRead {
  SNTBinaryMessageWindowController* controller = [self controllerForEvent:[self eventWithHash]];
  XCTAssertEqualObjects([controller queueDedupeHash], @"binary:abc123");
}

- (void)testQueueDedupeHashIsNilForAVerifiedReadWithNoHash {
  SNTStoredExecutionEvent* se = [self eventWithHash];
  se.fileSHA256 = nil;

  XCTAssertNil([[self controllerForEvent:se] queueDedupeHash]);
}

@end
