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
  SNTStoredEvent* baseEvent = [[SNTStoredEvent alloc] init];
  XCTAssertThrows([baseEvent uniqueID]);

  // Derived classes should not throw
  SNTStoredExecutionEvent* execEvent = [[SNTStoredExecutionEvent alloc] init];
  execEvent.fileSHA256 = @"foo";
  XCTAssertEqualObjects([execEvent uniqueID], @"foo");

  SNTStoredFileAccessEvent* faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.ruleName = @"MyRule";
  faaEvent.ruleVersion = @"MyVersion";
  faaEvent.accessedPath = @"/not/included";
  faaEvent.process.fileSHA256 = @"bar";
  XCTAssertEqualObjects([faaEvent uniqueID], @"MyRule|MyVersion|bar");

  // Audit events dedup separately from ordinary executions of the same binary,
  // so an audit-only match isn't merged with a normal allow/block event for the
  // same hash.
  SNTStoredExecutionEvent* auditEvent = [[SNTStoredExecutionEvent alloc] init];
  auditEvent.fileSHA256 = @"foo";
  auditEvent.decision = SNTEventStateAllowBinary;
  auditEvent.auditReturn = YES;
  XCTAssertEqualObjects([auditEvent uniqueID], @"foo:audit");
  XCTAssertNotEqualObjects([auditEvent uniqueID], @"foo");

  // Repeated audits of the same binary share a key -> at most one pending event
  // per binary per sync cycle.
  SNTStoredExecutionEvent* auditEvent2 = [[SNTStoredExecutionEvent alloc] init];
  auditEvent2.fileSHA256 = @"foo";
  auditEvent2.decision = SNTEventStateAllowBinary;
  auditEvent2.auditReturn = YES;
  XCTAssertEqualObjects([auditEvent2 uniqueID], [auditEvent uniqueID]);
}

- (void)testUnactionableEvent {
  // The base class should throw
  SNTStoredEvent* baseEvent = [[SNTStoredEvent alloc] init];
  XCTAssertThrows([baseEvent unactionableEvent]);

  // Spot check allow/block events
  SNTStoredExecutionEvent* execEvent = [[SNTStoredExecutionEvent alloc] init];
  execEvent.decision = SNTEventStateAllowBinary;
  XCTAssertTrue([execEvent unactionableEvent]);
  execEvent.decision = SNTEventStateBlockBinary;
  XCTAssertFalse([execEvent unactionableEvent]);

  // Audit events are allow decisions but are intentionally-collected telemetry,
  // so they are treated as actionable to bypass the storage backoff.
  execEvent.decision = SNTEventStateAllowBinary;
  execEvent.auditReturn = YES;
  XCTAssertFalse([execEvent unactionableEvent]);

  // Spot check audit only/denied events
  SNTStoredFileAccessEvent* faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.decision = FileAccessPolicyDecision::kAllowedAuditOnly;
  XCTAssertTrue([faaEvent unactionableEvent]);
  faaEvent.decision = FileAccessPolicyDecision::kDenied;
  XCTAssertFalse([faaEvent unactionableEvent]);
}

- (void)testEncodeDecode {
  SNTStoredExecutionEvent* execEvent = [[SNTStoredExecutionEvent alloc] init];
  execEvent.fileSHA256 = @"foo";

  SNTStoredFileAccessEvent* faaEvent = [[SNTStoredFileAccessEvent alloc] init];
  faaEvent.process.fileSHA256 = @"bar";

  faaEvent.process.parent = [[SNTStoredFileAccessProcess alloc] init];
  faaEvent.process.parent.pid = @(123);

  NSData* archivedExecEvent = [NSKeyedArchiver archivedDataWithRootObject:execEvent
                                                    requiringSecureCoding:YES
                                                                    error:nil];
  NSData* archivedFaaEvent = [NSKeyedArchiver archivedDataWithRootObject:faaEvent
                                                   requiringSecureCoding:YES
                                                                   error:nil];

  XCTAssertNotNil(archivedExecEvent);
  XCTAssertNotNil(archivedFaaEvent);

  SNTStoredEvent* unarchivedExecEvent = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[SNTStoredExecutionEvent class],
                                                      [SNTStoredFileAccessEvent class], nil]
                       fromData:archivedExecEvent
                          error:nil];

  XCTAssertNotNil(unarchivedExecEvent);
  XCTAssertTrue([unarchivedExecEvent isKindOfClass:[SNTStoredExecutionEvent class]]);
  XCTAssertEqualObjects(((SNTStoredExecutionEvent*)unarchivedExecEvent).fileSHA256, @"foo");

  SNTStoredEvent* unarchivedFaaEvent = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[SNTStoredExecutionEvent class],
                                                      [SNTStoredFileAccessEvent class], nil]
                       fromData:archivedFaaEvent
                          error:nil];

  XCTAssertNotNil(unarchivedFaaEvent);
  XCTAssertTrue([unarchivedFaaEvent isKindOfClass:[SNTStoredFileAccessEvent class]]);
  XCTAssertEqualObjects(((SNTStoredFileAccessEvent*)unarchivedFaaEvent).process.fileSHA256, @"bar");
  XCTAssertNotNil(((SNTStoredFileAccessEvent*)unarchivedFaaEvent).process.parent);
  XCTAssertEqualObjects(((SNTStoredFileAccessEvent*)unarchivedFaaEvent).process.parent.pid, @(123));
  XCTAssertNil(((SNTStoredFileAccessEvent*)unarchivedFaaEvent).process.parent.parent);
}

@end
