/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/santad/DataLayer/SNTEventTable.h"

#include <CommonCrypto/CommonDigest.h>
#import <OCMock/OCMock.h>
#import <Security/Security.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTStoredSignalReport.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#include "Source/common/TestUtils.h"

NSString* GenerateRandomHexStringWithSHA256Length() {
  // Create an array to hold random bytes
  NSMutableData* randomData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];

  // Fill the array with random bytes
  int result = SecRandomCopyBytes(kSecRandomDefault, randomData.length, randomData.mutableBytes);

  if (result != errSecSuccess) {
    XCTFail(@"Error generating random bytes: %d", result);
    return nil;
  }

  // Convert the random bytes to a hex string
  NSMutableString* hexString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (NSInteger i = 0; i < randomData.length; i++) {
    [hexString appendFormat:@"%02x", ((const unsigned char*)randomData.bytes)[i]];
  }

  return hexString;
}

@interface SNTEventTable (Testing)
- (SNTStoredEvent*)eventFromResultSet:(FMResultSet*)rs;
@property NSTimeInterval unactionableEventCacheTimeSeconds;
@property NSTimeInterval blockEventCacheTimeSeconds;
@end

/// This test case actually tests SNTEventTable and SNTStoredEvent.
///
/// Adding/Retrieving events relies on SNTStoredEvent coding to work correctly
/// so if that is broken, these tests will fail.
///
/// Depends on on SNTFileInfo and MOLCodesignChecker (and by extension
/// MOLCertificate) to avoid duplicating code into these tests.
///
@interface SNTEventTableTest : XCTestCase
@property SNTEventTable* sut;
@property FMDatabaseQueue* dbq;
@end

@implementation SNTEventTableTest

- (void)setUp {
  [super setUp];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.sut = [[SNTEventTable alloc] initWithDatabaseQueue:self.dbq];
}

- (SNTStoredExecutionEvent*)createTestEvent {
  SNTFileInfo* binInfo = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/false"];
  MOLCodesignChecker* csInfo = [binInfo codesignCheckerWithError:NULL];
  SNTStoredExecutionEvent* event = [[SNTStoredExecutionEvent alloc] init];
  event.filePath = @"/usr/bin/false";
  event.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  event.signingChain = [csInfo certificates];
  event.executingUser = @"nobody";
  event.loggedInUsers = @[ @"nobody" ];
  event.currentSessions = @[ @"nobody@ttys000", @"nobody@console" ];
  event.decision = SNTEventStateBlockBinary;
  return event;
}

- (SNTStoredFileAccessEvent*)createTestFileAccessEvent {
  SNTFileInfo* binInfo = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/false"];
  MOLCodesignChecker* csInfo = [binInfo codesignCheckerWithError:NULL];
  SNTStoredFileAccessEvent* event = [[SNTStoredFileAccessEvent alloc] init];
  event.ruleName = @"MyTestRule";
  event.ruleVersion = @"MyTestVersion";
  event.accessedPath = @"/this/path/was/accessed";
  event.process.filePath = @"/usr/bin/false";
  event.process.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  event.process.signingChain = [csInfo certificates];
  event.process.executingUser = @"nobody";
  event.process.pid = @(1234);
  event.process.parent = [[SNTStoredProcess alloc] init];
  event.process.parent.pid = @(4567);
  event.decision = FileAccessPolicyDecision::kDenied;
  return event;
}

- (SNTStoredTemporaryMonitorModeEnterAuditEvent*)createTestTemporaryMonitorModeEnterAuditEvent {
  return [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc]
      initWithUUID:@"enter_uuid"
           seconds:123
            reason:SNTTemporaryMonitorModeEnterReasonOnDemand];
}

- (SNTStoredTemporaryMonitorModeLeaveAuditEvent*)createTestTemporaryMonitorModeLeaveAuditEvent {
  return [[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc]
      initWithUUID:@"leave_uuid"
            reason:SNTTemporaryMonitorModeLeaveReasonSessionExpired];
}

- (void)testAddEvent {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
  XCTAssert([self.sut addStoredEvent:[self createTestEvent]]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  XCTAssert([self.sut addStoredEvent:[self createTestFileAccessEvent]]);
  XCTAssertEqual(self.sut.pendingEventsCount, 2);
}

- (void)testUniqueIndexActionable {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // Disable the block backoff so the unique index is what dedups.
  self.sut.blockEventCacheTimeSeconds = 0;

  SNTStoredExecutionEvent* event = [self createTestEvent];
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  // Attempt to add an event with the same file hash succeeds despite
  // non-unique filehash256 column
  event.idx = @(arc4random());
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  // Create a new hash and re-insert
  event.idx = @(arc4random());
  event.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 2);

  // Attempting to add an event with a non-unique idx fails
  event.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertFalse([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 2);

  // Now for FAA Events...
  SNTStoredFileAccessEvent* faaEvent = [self createTestFileAccessEvent];
  XCTAssertTrue([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 3);

  // Attempt to add an event with the same file hash succeeds despite
  // non-unique filehash256 column
  faaEvent.idx = @(arc4random());
  XCTAssertTrue([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 3);

  // Create a new hash and re-insert
  faaEvent.process.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertTrue([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 4);

  // Attempting to add an event with a non-unique idx fails
  faaEvent.process.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertFalse([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 4);
}

- (void)testUniqueIndexUnactionable {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  SNTStoredExecutionEvent* event = [self createTestEvent];
  // Make this an "unactionable" event
  event.decision = SNTEventStateAllowBinary;
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  // Attempt to add an event with the same file hash will fail because
  // no insert will be attempted
  event.idx = @(arc4random());
  XCTAssertFalse([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  // Create a new hash and re-insert
  event.idx = @(arc4random());
  event.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 2);

  // Attempting to add an event with a non-unique idx fails
  event.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertFalse([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 2);

  // Now for FAA Events...
  SNTStoredFileAccessEvent* faaEvent = [self createTestFileAccessEvent];
  // Make this an "unactionable" event
  faaEvent.decision = FileAccessPolicyDecision::kAllowedAuditOnly;
  XCTAssertTrue([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 3);

  // Attempt to add an event with the same file hash will fail because
  // no insert will be attempted
  faaEvent.idx = @(arc4random());
  XCTAssertFalse([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 3);

  // Create a new hash and re-insert
  faaEvent.process.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertTrue([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 4);

  // Attempting to add an event with a non-unique idx fails
  faaEvent.process.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  XCTAssertFalse([self.sut addStoredEvent:faaEvent]);
  XCTAssertEqual(self.sut.pendingEventsCount, 4);
}

- (void)testBackoff {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // Set the backoff time to 3 seconds
  self.sut.unactionableEventCacheTimeSeconds = 3;

  SNTStoredExecutionEvent* event = [self createTestEvent];
  // Make this an "unactionable" event
  event.decision = SNTEventStateAllowBinary;
  NSNumber* origId = event.idx;
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  // Attempt to add an event with the same file hash will fail because
  // no insert will be attempted
  event.idx = @(arc4random());
  XCTAssertFalse([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  // Delete everything
  [self.sut deleteEventsWithIds:@[ origId ]];
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // Attempt to reinsert an unactionable event before the backoff time
  // This should still fail, even though it wouldn't conflict in the DB
  event.idx = @(arc4random());
  XCTAssertFalse([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // Sleep for the backoff time
  SleepMS(3000);

  // Now re-add the stored event, all should be well
  event.idx = @(arc4random());
  XCTAssertTrue([self.sut addStoredEvent:event]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
}

- (void)testBlockBackoff {
  // Longer than any uptime, so a binary with no backoff yet is stored even right after boot.
  self.sut.blockEventCacheTimeSeconds = 100.0 * 365 * 24 * 60 * 60;

  SNTStoredExecutionEvent* block = [self createTestEvent];
  XCTAssertTrue([self.sut addStoredEvent:block]);

  // Drain the table as an upload does. A repeat block of the same binary is not stored, or every
  // sync would upload another copy.
  [self.sut deleteEventsWithIds:@[ block.idx ]];
  block.idx = @(arc4random());
  XCTAssertFalse([self.sut addStoredEvent:block]);
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // A new decision for the binary has a window of its own. For example, BLOCK_UNKNOWN after the
  // binary's block rule is removed is what starts an approval in Workshop.
  block.decision = SNTEventStateBlockUnknown;
  XCTAssertTrue([self.sut addStoredEvent:block]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  [self.sut deleteEventsWithIds:@[ block.idx ]];
  block.idx = @(arc4random());
  XCTAssertFalse([self.sut addStoredEvent:block]);
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // A bundle's related events are not blocks, so they are not throttled.
  SNTStoredExecutionEvent* related = [self createTestEvent];
  related.fileSHA256 = block.fileSHA256;
  related.decision = SNTEventStateBundleBinary;
  XCTAssertTrue([self.sut addStoredEvent:related]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  [self.sut deleteEventsWithIds:@[ related.idx ]];

  // Allows and blocks of the same binary share a uniqueID but not a backoff, so the binary's blocks
  // above do not hide its allow.
  SNTStoredExecutionEvent* allow = [self createTestEvent];
  allow.fileSHA256 = block.fileSHA256;
  allow.decision = SNTEventStateAllowBinary;
  XCTAssertTrue([self.sut addStoredEvent:allow]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  [self.sut deleteEventsWithIds:@[ allow.idx ]];

  // A block that conflicts with a pending row of the same binary writes nothing, so it does not
  // start its window: once that row is uploaded, the next block is stored.
  SNTStoredExecutionEvent* pendingAllow = [self createTestEvent];
  pendingAllow.decision = SNTEventStateAllowBinary;
  XCTAssertTrue([self.sut addStoredEvent:pendingAllow]);
  SNTStoredExecutionEvent* blockAfterAllow = [self createTestEvent];
  blockAfterAllow.fileSHA256 = pendingAllow.fileSHA256;
  XCTAssertTrue([self.sut addStoredEvent:blockAfterAllow]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  [self.sut deleteEventsWithIds:@[ pendingAllow.idx ]];
  blockAfterAllow.idx = @(arc4random());
  XCTAssertTrue([self.sut addStoredEvent:blockAfterAllow]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  SNTStoredExecutionEvent* stored = [self.sut pendingEvents].firstObject;
  XCTAssertEqual(stored.decision, SNTEventStateBlockBinary);

  // The backoff ends after its window.
  self.sut.blockEventCacheTimeSeconds = 1;
  SleepMS(1100);
  [self.sut deleteEventsWithIds:@[ blockAfterAllow.idx ]];
  block.idx = @(arc4random());
  XCTAssertTrue([self.sut addStoredEvent:block]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
}

- (void)testStoreBundleHashedEvent {
  // A row that is still waiting is updated in place.
  SNTStoredExecutionEvent* waiting = [self createTestEvent];
  XCTAssertTrue([self.sut addStoredEvent:waiting]);
  waiting.fileBundleHash = @"bundlehash";
  [self.sut storeBundleHashedEvent:waiting];
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  SNTStoredExecutionEvent* stored = [self.sut pendingEvents].firstObject;
  XCTAssertEqualObjects(stored.idx, waiting.idx);
  XCTAssertEqualObjects(stored.fileBundleHash, @"bundlehash");

  // The update starts the hashed window: once the row is uploaded, a repeat hashed copy (another
  // block window for the same binary) is not stored.
  [self.sut deleteEventsWithIds:@[ waiting.idx ]];
  waiting.idx = @(arc4random());
  [self.sut storeBundleHashedEvent:waiting];
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // A row that a sync already uploaded is stored again with its bundle hash, so the hashed event
  // still reaches the server.
  SNTStoredExecutionEvent* synced = [self createTestEvent];
  XCTAssertTrue([self.sut addStoredEvent:synced]);
  [self.sut deleteEventsWithIds:@[ synced.idx ]];
  synced.fileBundleHash = @"bundlehash";
  [self.sut storeBundleHashedEvent:synced];
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  XCTAssertEqualObjects([[self.sut pendingEvents].firstObject fileBundleHash], @"bundlehash");

  // A repeat hashed copy within the window is not.
  [self.sut deleteEventsWithIds:@[ synced.idx ]];
  synced.idx = @(arc4random());
  [self.sut storeBundleHashedEvent:synced];
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  // The update only changes the row of the same binary.
  SNTStoredExecutionEvent* other = [self createTestEvent];
  XCTAssertTrue([self.sut addStoredEvent:other]);
  SNTStoredExecutionEvent* wrongBinary = [self createTestEvent];
  wrongBinary.idx = other.idx;
  wrongBinary.fileBundleHash = @"bundlehash";
  [self.sut storeBundleHashedEvent:wrongBinary];
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
  XCTAssertNil([[self.sut pendingEvents].firstObject fileBundleHash]);
}

- (void)testRetrieveExecutionEvent {
  SNTStoredExecutionEvent* event = [self createTestEvent];
  [self.sut addStoredEvent:event];

  SNTStoredExecutionEvent* storedEvent = [self.sut pendingEvents].firstObject;
  XCTAssertNotNil(storedEvent);
  XCTAssertEqualObjects(event.filePath, storedEvent.filePath);
  XCTAssertEqualObjects(event.signingChain, storedEvent.signingChain);
  XCTAssertEqualObjects(event.loggedInUsers, storedEvent.loggedInUsers);
  XCTAssertEqualObjects(event.occurrenceDate, storedEvent.occurrenceDate);
  XCTAssertEqual(event.decision, storedEvent.decision);
}

- (void)testRetrieveFAAEvent {
  SNTStoredFileAccessEvent* event = [self createTestFileAccessEvent];
  [self.sut addStoredEvent:event];

  SNTStoredFileAccessEvent* storedEvent = [self.sut pendingEvents].firstObject;
  XCTAssertNotNil(storedEvent);
  XCTAssertEqualObjects(event.ruleName, storedEvent.ruleName);
  XCTAssertEqualObjects(event.ruleVersion, storedEvent.ruleVersion);
  XCTAssertEqualObjects(event.accessedPath, storedEvent.accessedPath);
  XCTAssertEqualObjects(event.process.filePath, storedEvent.process.filePath);
  XCTAssertEqualObjects(event.process.fileSHA256, storedEvent.process.fileSHA256);
  XCTAssertEqualObjects(event.process.signingChain, storedEvent.process.signingChain);
  XCTAssertEqualObjects(event.process.executingUser, storedEvent.process.executingUser);
  XCTAssertEqualObjects(event.process.pid, storedEvent.process.pid);
  XCTAssertEqualObjects(event.process.parent.pid, storedEvent.process.parent.pid);
  XCTAssertEqualObjects(event.occurrenceDate, storedEvent.occurrenceDate);
}

- (void)testRetrieveTemporaryMonitorModeEnterAuditEvent {
  SNTStoredTemporaryMonitorModeEnterAuditEvent* event =
      [self createTestTemporaryMonitorModeEnterAuditEvent];
  [self.sut addStoredEvent:event];

  SNTStoredFileAccessEvent* storedEvent = [self.sut pendingEvents].firstObject;
  XCTAssertNotNil(storedEvent);
  XCTAssertTrue([storedEvent isKindOfClass:[SNTStoredTemporaryMonitorModeEnterAuditEvent class]]);

  SNTStoredTemporaryMonitorModeEnterAuditEvent* tmmEnter =
      (SNTStoredTemporaryMonitorModeEnterAuditEvent*)storedEvent;
  XCTAssertEqualObjects(tmmEnter.uuid, @"enter_uuid");
  XCTAssertEqual(tmmEnter.reason, SNTTemporaryMonitorModeEnterReasonOnDemand);
  XCTAssertEqual(tmmEnter.seconds, 123);
}

- (void)testRetrieveTemporaryMonitorModeLeaveAuditEvent {
  SNTStoredTemporaryMonitorModeLeaveAuditEvent* event =
      [self createTestTemporaryMonitorModeLeaveAuditEvent];
  [self.sut addStoredEvent:event];

  SNTStoredFileAccessEvent* storedEvent = [self.sut pendingEvents].firstObject;
  XCTAssertNotNil(storedEvent);
  XCTAssertTrue([storedEvent isKindOfClass:[SNTStoredTemporaryMonitorModeAuditEvent class]]);

  SNTStoredTemporaryMonitorModeLeaveAuditEvent* tmmLeave =
      (SNTStoredTemporaryMonitorModeLeaveAuditEvent*)storedEvent;
  XCTAssertEqualObjects(tmmLeave.uuid, @"leave_uuid");
  XCTAssertEqual(tmmLeave.reason, SNTTemporaryMonitorModeLeaveReasonSessionExpired);
}

- (void)testDeleteEventsWithIds {
  // Add 50 exec and faa events to the database
  for (int i = 0; i < 50; ++i) {
    SNTStoredEvent* newEvent =
        (i % 2 == 0) ? [self createTestEvent] : [self createTestFileAccessEvent];
    [self.sut addStoredEvent:newEvent];
  }

  // Fetch those events (so we have the IDs)
  NSArray* pendingEvents = [self.sut pendingEvents];

  // Ensure enough events were added and retrieved
  XCTAssertEqual(self.sut.pendingEventsCount, 50);
  XCTAssertEqual(self.sut.pendingEventsCount, pendingEvents.count);

  // Collect the IDs
  NSMutableArray* eventIds = [NSMutableArray array];
  for (SNTStoredEvent* event in pendingEvents) {
    [eventIds addObject:event.idx];
  }

  // Now delete them
  [self.sut deleteEventsWithIds:eventIds];

  // Check they were deleted
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
}

- (void)testDeleteCorruptEvent {
  [self.dbq inDatabase:^(FMDatabase* db) {
    [db executeUpdate:@"INSERT INTO events (filesha256) VALUES ('deadbeef')"];
  }];

  NSArray* events = [self.sut pendingEvents];
  if (events.count > 0) {
    XCTFail("Received bad event");
  }

  [self.dbq inDatabase:^(FMDatabase* db) {
    FMResultSet* rs = [db executeQuery:@"SELECT * FROM events WHERE filesha256='deadbeef'"];
    if ([rs next]) {
      XCTFail("Bad event was not deleted.");
    }
    [rs close];
  }];
}

- (NSData*)dataFromFixture:(NSString*)file {
  NSString* path = [[NSBundle bundleForClass:[self class]] pathForResource:file ofType:nil];
  XCTAssertNotNil(path, @"failed to load testdata: %@", file);
  return [NSData dataWithContentsOfFile:path];
}

- (SNTStoredSignalReport*)createTestSignalReport {
  uint8_t bytes[8];
  arc4random_buf(bytes, sizeof(bytes));
  return [[SNTStoredSignalReport alloc] initWithReportData:[NSData dataWithBytes:bytes
                                                                          length:sizeof(bytes)]];
}

- (SNTStoredSignalReport*)createTestSignalReportNamed:(NSString*)name {
  SNTStoredSignalReport* report = [self createTestSignalReport];
  report.name = name;
  return report;
}

- (void)testAddAndRetrieveSignalReports {
  XCTAssertEqual([self.sut pendingSignalReports].count, 0);

  SNTStoredSignalReport* r1 = [self createTestSignalReport];
  SNTStoredSignalReport* r2 = [self createTestSignalReport];
  NSArray<SNTStoredSignalReport*>* reports = @[ r1, r2 ];
  XCTAssertEqual([self.sut addStoredSignalReports:reports].count, 2);

  NSArray<SNTStoredSignalReport*>* pending = [self.sut pendingSignalReports];
  XCTAssertEqual(pending.count, 2);

  // Round-trip: the stored bytes survive intact.
  NSMutableSet<NSData*>* gotData = [NSMutableSet set];
  for (SNTStoredSignalReport* r in pending) {
    [gotData addObject:r.reportData];
  }
  XCTAssertTrue([gotData containsObject:r1.reportData]);
  XCTAssertTrue([gotData containsObject:r2.reportData]);
}

- (void)testDeleteSignalReportsWithIds {
  SNTStoredSignalReport* r1 = [self createTestSignalReport];
  SNTStoredSignalReport* r2 = [self createTestSignalReport];
  NSArray<SNTStoredSignalReport*>* reports = @[ r1, r2 ];
  XCTAssertEqual([self.sut addStoredSignalReports:reports].count, 2);
  XCTAssertEqual([self.sut pendingSignalReports].count, 2);

  [self.sut deleteSignalReportsWithIds:@[ r1.idx ]];
  NSArray<SNTStoredSignalReport*>* pending = [self.sut pendingSignalReports];
  XCTAssertEqual(pending.count, 1);
  XCTAssertEqualObjects(pending.firstObject.reportData, r2.reportData);

  [self.sut deleteSignalReportsWithIds:@[ r2.idx ]];
  XCTAssertEqual([self.sut pendingSignalReports].count, 0);
}

- (void)testSignalReportDedupByName {
  // Two reports for the same signal in one batch: only the first is stored.
  SNTStoredSignalReport* a1 = [self createTestSignalReportNamed:@"SIG-1"];
  SNTStoredSignalReport* a2 = [self createTestSignalReportNamed:@"SIG-1"];
  NSArray<SNTStoredSignalReport*>* dupBatch = @[ a1, a2 ];
  NSArray<SNTStoredSignalReport*>* stored = [self.sut addStoredSignalReports:dupBatch];
  XCTAssertEqual(stored.count, 1);
  XCTAssertEqualObjects(stored.firstObject.reportData, a1.reportData);
  XCTAssertEqual([self.sut pendingSignalReports].count, 1);

  // A different signal name is stored.
  XCTAssertEqual(
      [self.sut addStoredSignalReports:@[ [self createTestSignalReportNamed:@"SIG-2"] ]].count, 1);
  XCTAssertEqual([self.sut pendingSignalReports].count, 2);

  // The same signal again within the window is dropped, independent of the DB row's lifetime
  // (the dedup window outlives the row, so deleting/uploading the first does not reset it).
  [self.sut deleteSignalReportsWithIds:@[ a1.idx ]];
  XCTAssertEqual(
      [self.sut addStoredSignalReports:@[ [self createTestSignalReportNamed:@"SIG-1"] ]].count, 0);
}

- (void)testEventFromResultSet {
  // Attempt to unarchive data. The first is an SNTStoredEvent which is no longer valid
  // and it should fail. The second is a valid event and should succeed.
  FMResultSet* rs = [[FMResultSet alloc] init];
  id mockResultSet = OCMPartialMock(rs);

  NSData* oldStoredEventData = [self dataFromFixture:@"old_sntstoredevent_archive.plist"];
  OCMExpect([mockResultSet dataNoCopyForColumn:@"eventdata"]).andReturn(oldStoredEventData);

  NSData* newStoredExecEventData =
      [self dataFromFixture:@"new_sntstoredexecutionevent_archive.plist"];
  OCMExpect([mockResultSet dataNoCopyForColumn:@"eventdata"]).andReturn(newStoredExecEventData);

  // This fixture's process is archived under the pre-rename class name, so decoding
  // it exercises the SNTStoredProcess unarchiver alias (the persisted-upgrade path).
  NSData* newStoredFileAccessEventData =
      [self dataFromFixture:@"sntstoredfileaccessevent_archive.plist"];
  OCMExpect([mockResultSet dataNoCopyForColumn:@"eventdata"])
      .andReturn(newStoredFileAccessEventData);

  XCTAssertNil([self.sut eventFromResultSet:mockResultSet]);
  XCTAssertNotNil([self.sut eventFromResultSet:mockResultSet]);
  XCTAssertNotNil([self.sut eventFromResultSet:mockResultSet]);
}

@end
