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

#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

@interface StoredEventTest : XCTestCase
@end

@implementation StoredEventTest

- (void)testUniqueID {
  // The base class should throw
  SNTStoredEvent *baseEvent = [[SNTStoredEvent alloc] init];
  XCTAssertThrows([baseEvent uniqueID]);

  // Derived classes should not throw
  SNTStoredExecutionEvent *execEvent = [[SNTStoredExecutionEvent alloc] init];
  execEvent.fileSHA256 = @"foo";
  XCTAssertEqualObjects([execEvent uniqueID], @"foo");

  SNTStoredFileAccessEvent *faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.ruleName = @"MyRule";
  faaEvent.ruleVersion = @"MyVersion";
  faaEvent.accessedPath = @"/not/included";
  faaEvent.process.fileSHA256 = @"bar";
  XCTAssertEqualObjects([faaEvent uniqueID], @"MyRule|MyVersion|bar");
}

- (void)testEncodeDecode {
  SNTStoredExecutionEvent *execEvent = [[SNTStoredExecutionEvent alloc] init];
  execEvent.fileSHA256 = @"foo";

  SNTStoredFileAccessEvent *faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.process.fileSHA256 = @"bar";

  faaEvent.process.parent = [[SNTStoredFileAccessProcess alloc] init];
  faaEvent.process.parent.pid = @(123);

  NSData *archivedExecEvent = [NSKeyedArchiver archivedDataWithRootObject:execEvent
                                                    requiringSecureCoding:YES
                                                                    error:nil];
  NSData *archivedFaaEvent = [NSKeyedArchiver archivedDataWithRootObject:faaEvent
                                                   requiringSecureCoding:YES
                                                                   error:nil];

  XCTAssertNotNil(archivedExecEvent);
  XCTAssertNotNil(archivedFaaEvent);

  SNTStoredEvent *unarchivedExecEvent = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[SNTStoredExecutionEvent class],
                                                      [SNTStoredFileAccessEvent class], nil]
                       fromData:archivedExecEvent
                          error:nil];

  XCTAssertNotNil(unarchivedExecEvent);
  XCTAssertTrue([unarchivedExecEvent isKindOfClass:[SNTStoredExecutionEvent class]]);
  XCTAssertEqualObjects(((SNTStoredExecutionEvent *)unarchivedExecEvent).fileSHA256, @"foo");

  SNTStoredEvent *unarchivedFaaEvent = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[SNTStoredExecutionEvent class],
                                                      [SNTStoredFileAccessEvent class], nil]
                       fromData:archivedFaaEvent
                          error:nil];

  XCTAssertNotNil(unarchivedFaaEvent);
  XCTAssertTrue([unarchivedFaaEvent isKindOfClass:[SNTStoredFileAccessEvent class]]);
  XCTAssertEqualObjects(((SNTStoredFileAccessEvent *)unarchivedFaaEvent).process.fileSHA256,
                        @"bar");
  XCTAssertNotNil(((SNTStoredFileAccessEvent *)unarchivedFaaEvent).process.parent);
  XCTAssertEqualObjects(((SNTStoredFileAccessEvent *)unarchivedFaaEvent).process.parent.pid,
                        @(123));
  XCTAssertNil(((SNTStoredFileAccessEvent *)unarchivedFaaEvent).process.parent.parent);
}

@end
