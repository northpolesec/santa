/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import "Source/santad/DataLayer/SNTEventTable.h"

#include <CommonCrypto/CommonDigest.h>
#import <OCMock/OCMock.h>
#import <Security/Security.h>
#import <XCTest/XCTest.h>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTStoredExecutionEvent.h"

NSString *GenerateRandomHexStringWithSHA256Length() {
  // Create an array to hold random bytes
  NSMutableData *randomData = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];

  // Fill the array with random bytes
  int result = SecRandomCopyBytes(kSecRandomDefault, randomData.length, randomData.mutableBytes);

  if (result != errSecSuccess) {
    XCTFail(@"Error generating random bytes: %d", result);
    return nil;
  }

  // Convert the random bytes to a hex string
  NSMutableString *hexString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (NSInteger i = 0; i < randomData.length; i++) {
    [hexString appendFormat:@"%02x", ((const unsigned char *)randomData.bytes)[i]];
  }

  return hexString;
}

@interface SNTEventTable (Testing)
- (SNTStoredEvent *)eventFromResultSet:(FMResultSet *)rs;
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
@property SNTEventTable *sut;
@property FMDatabaseQueue *dbq;
@end

@implementation SNTEventTableTest

- (void)setUp {
  [super setUp];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.sut = [[SNTEventTable alloc] initWithDatabaseQueue:self.dbq];
}

- (SNTStoredExecutionEvent *)createTestEvent {
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:@"/usr/bin/false"];
  MOLCodesignChecker *csInfo = [binInfo codesignCheckerWithError:NULL];
  SNTStoredExecutionEvent *event = [[SNTStoredExecutionEvent alloc] init];
  event.idx = @(arc4random());
  event.filePath = @"/usr/bin/false";
  event.fileSHA256 = GenerateRandomHexStringWithSHA256Length();
  event.signingChain = [csInfo certificates];
  event.executingUser = @"nobody";
  event.loggedInUsers = @[ @"nobody" ];
  event.currentSessions = @[ @"nobody@ttys000", @"nobody@console" ];
  event.occurrenceDate = [NSDate date];
  event.decision = SNTEventStateAllowBinary;
  return event;
}

- (void)testAddEvent {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
  XCTAssert([self.sut addStoredEvent:[self createTestEvent]]);
  XCTAssertEqual(self.sut.pendingEventsCount, 1);
}

- (void)testUniqueIndex {
  XCTAssertEqual(self.sut.pendingEventsCount, 0);

  SNTStoredExecutionEvent *event = [self createTestEvent];
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
}

- (void)testRetrieveEvent {
  SNTStoredExecutionEvent *event = [self createTestEvent];
  [self.sut addStoredEvent:event];

  SNTStoredExecutionEvent *storedEvent = [self.sut pendingEvents].firstObject;
  XCTAssertNotNil(storedEvent);
  XCTAssertEqualObjects(event.filePath, storedEvent.filePath);
  XCTAssertEqualObjects(event.signingChain, storedEvent.signingChain);
  XCTAssertEqualObjects(event.loggedInUsers, storedEvent.loggedInUsers);
  XCTAssertEqualObjects(event.occurrenceDate, storedEvent.occurrenceDate);
  XCTAssertEqual(event.decision, storedEvent.decision);
}

- (void)testDeleteEventWithId {
  SNTStoredEvent *newEvent = [self createTestEvent];
  [self.sut addStoredEvent:newEvent];
  XCTAssertEqual(self.sut.pendingEventsCount, 1);

  [self.sut deleteEventWithId:newEvent.idx];
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
}

- (void)testDeleteEventsWithIds {
  // Add 50 events to the database
  for (int i = 0; i < 50; ++i) {
    SNTStoredEvent *newEvent = [self createTestEvent];
    [self.sut addStoredEvent:newEvent];
  }

  // Fetch those events (so we have the IDs)
  NSArray *pendingEvents = [self.sut pendingEvents];

  // Ensure enough events were added and retrieved
  XCTAssertEqual(self.sut.pendingEventsCount, 50);
  XCTAssertEqual(self.sut.pendingEventsCount, pendingEvents.count);

  // Collect the IDs
  NSMutableArray *eventIds = [NSMutableArray array];
  for (SNTStoredEvent *event in pendingEvents) {
    [eventIds addObject:event.idx];
  }

  // Now delete them
  [self.sut deleteEventsWithIds:eventIds];

  // Check they were deleted
  XCTAssertEqual(self.sut.pendingEventsCount, 0);
}

- (void)testDeleteCorruptEvent {
  [self.dbq inDatabase:^(FMDatabase *db) {
    [db executeUpdate:@"INSERT INTO events (filesha256) VALUES ('deadbeef')"];
  }];

  NSArray *events = [self.sut pendingEvents];
  if (events.count > 0) {
    XCTFail("Received bad event");
  }

  [self.dbq inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM events WHERE filesha256='deadbeef'"];
    if ([rs next]) {
      XCTFail("Bad event was not deleted.");
    }
    [rs close];
  }];
}

- (NSData *)dataFromFixture:(NSString *)file {
  NSString *path = [[NSBundle bundleForClass:[self class]] pathForResource:file ofType:nil];
  XCTAssertNotNil(path, @"failed to load testdata: %@", file);
  return [NSData dataWithContentsOfFile:path];
}

- (void)testEventFromResultSet {
  // Attempt to unarchive data. The first is an SNTStoredEvent which is no longer valid
  // and it should fail. The second is a valid event and should succeed.
  FMResultSet *rs = [[FMResultSet alloc] init];
  id mockResultSet = OCMPartialMock(rs);

  NSData *oldStoredEventData = [self dataFromFixture:@"old_sntstoredevent_archive.plist"];
  OCMExpect([mockResultSet dataForColumn:@"eventdata"]).andReturn(oldStoredEventData);

  NSData *newStoredExecEventData =
      [self dataFromFixture:@"new_sntstoredexecutionevent_archive.plist"];
  OCMExpect([mockResultSet dataForColumn:@"eventdata"]).andReturn(newStoredExecEventData);

  XCTAssertNil([self.sut eventFromResultSet:mockResultSet]);
  XCTAssertNotNil([self.sut eventFromResultSet:mockResultSet]);
}

@end
