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

#include <memory>

#import "Source/common/MOLCertificate.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"
#import "Source/common/SNTStoredSignalReport.h"
#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#include "Source/common/SantaCache.h"
#include "Source/common/String.h"

static const uint32_t kEventTableCurrentVersion = 6;
// 4 hour cache
static const NSTimeInterval kUnactionableEventCacheTimeSeconds = (60 * 60 * 4);
// Deduplicate repeated firings of the same signal to at most one per name per 10 minutes.
static const NSTimeInterval kSignalReportDedupWindowSeconds = (60 * 10);

@interface SNTEventTable ()
// This property is only set once, safe to be nonatomic
@property(nonatomic) NSTimeInterval unactionableEventCacheTimeSeconds;
@end

@implementation SNTEventTable {
  std::unique_ptr<SantaCache<std::string, NSDate*>> _storeBackoff;
  std::unique_ptr<SantaCache<std::string, NSDate*>> _signalReportBackoff;
}

- (uint32_t)currentSupportedVersion {
  return kEventTableCurrentVersion;
}

- (uint32_t)initializeDatabase:(FMDatabase*)db fromVersion:(uint32_t)version {
  _storeBackoff = std::make_unique<SantaCache<std::string, NSDate*>>(2048);
  _signalReportBackoff = std::make_unique<SantaCache<std::string, NSDate*>>(2048);
  self.unactionableEventCacheTimeSeconds = kUnactionableEventCacheTimeSeconds;

  int newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'events' ("
                      @"'idx' INTEGER PRIMARY KEY AUTOINCREMENT,"
                      @"'filesha256' TEXT NOT NULL,"
                      @"'eventdata' BLOB);"];
    [db executeUpdate:@"CREATE INDEX filesha256 ON events (filesha256);"];
    newVersion = 1;
  }

  if (version < 2) {
    // We no longer attempt to migrate data that may have been in the event table from v1.
    [db executeUpdate:@"DELETE FROM events;"];
    newVersion = 2;
  }

  if (version < 3) {
    // Clean-up: Disable AUTOINCREMENT on idx column
    [db executeUpdate:@"CREATE TABLE 'events_tmp' ("
                      @"'idx' INTEGER PRIMARY KEY,"
                      @"'filesha256' TEXT NOT NULL,"
                      @"'eventdata' BLOB);"];
    [db executeUpdate:@"INSERT INTO events_tmp SELECT * FROM events"];
    [db executeUpdate:@"DROP TABLE events"];
    [db executeUpdate:@"ALTER TABLE events_tmp RENAME TO events"];
    newVersion = 3;
  }

  if (version < 4) {
    // Add a unique index on the filesha256 column. This will be used to
    // deduplicate similar events between event uploads. Before adding the
    // unique index, first remove rows with duplicate filesha256 values.
    [db executeUpdate:@"DELETE FROM events "
                      @"WHERE idx NOT IN ("
                      @"  SELECT MIN(idx)"
                      @"  FROM events"
                      @"  GROUP BY filesha256"
                      @");"];
    [db executeUpdate:@"CREATE UNIQUE INDEX filesha256 ON events (filesha256);"];
    newVersion = 4;
  }

  if (version < 5) {
    // Rename the filesha256 column to uniqueid because different stored event types
    // contain different content for determining uniqueness.
    [db executeUpdate:@"DROP INDEX filesha256"];
    [db executeUpdate:@"ALTER TABLE events RENAME COLUMN filesha256 TO uniqueid"];
    [db executeUpdate:@"CREATE UNIQUE INDEX uniqueid ON events (uniqueid)"];
    newVersion = 5;
  }

  if (version < 6) {
    // Signal reports produced by Sleigh signal scans, pending upload to the sync server.
    // Repeated firings of the same signal are deduplicated per-name within a time window
    // (kSignalReportDedupWindowSeconds) before they reach this table; see addStoredSignalReports:.
    [db executeUpdate:@"CREATE TABLE 'signal_reports' ("
                      @"'idx' INTEGER PRIMARY KEY,"
                      @"'report_data' BLOB NOT NULL);"];
    newVersion = 6;
  }

  return newVersion;
}

#pragma mark Loading / Storing

- (BOOL)addStoredEvent:(SNTStoredEvent*)event {
  return [self addStoredEvents:@[ event ]];
}

- (BOOL)isValidStoredEvent:(SNTStoredEvent*)event {
  if ([event isKindOfClass:[SNTStoredExecutionEvent class]]) {
    SNTStoredExecutionEvent* se = (SNTStoredExecutionEvent*)event;
    return se.idx && [[se uniqueID] length] && se.filePath.length && se.occurrenceDate &&
           se.decision;
  } else if ([event isKindOfClass:[SNTStoredFileAccessEvent class]]) {
    SNTStoredFileAccessEvent* se = (SNTStoredFileAccessEvent*)event;
    return se.idx && se.ruleVersion.length && se.ruleName.length && se.accessedPath.length &&
           se.process.filePath.length && [[se uniqueID] length];
  } else if ([event isKindOfClass:[SNTStoredTemporaryMonitorModeAuditEvent class]]) {
    SNTStoredTemporaryMonitorModeAuditEvent* se = (SNTStoredTemporaryMonitorModeAuditEvent*)event;
    return se.uuid != nil;
  } else {
    return NO;
  }
}

- (BOOL)addStoredEvents:(NSArray<SNTStoredEvent*>*)events {
  NSMutableDictionary* eventsData = [NSMutableDictionary dictionaryWithCapacity:events.count];
  for (SNTStoredEvent* event in events) {
    if (![self isValidStoredEvent:event]) {
      continue;
    }

    if ([event unactionableEvent] && [self backoffForPrimaryHash:[event uniqueID]]) {
      continue;
    }

    NSData* eventData = [NSKeyedArchiver archivedDataWithRootObject:event
                                              requiringSecureCoding:YES
                                                              error:nil];
    if (eventData) {
      eventsData[eventData] = event;
    }
  }

  __block BOOL success = NO;
  [self inTransaction:^(FMDatabase* db, BOOL* rollback) {
    [eventsData
        enumerateKeysAndObjectsUsingBlock:^(NSData* eventData, SNTStoredEvent* event, BOOL* stop) {
          success = [db executeUpdate:@"INSERT INTO 'events' (idx, uniqueid, eventdata) "
                                      @"VALUES (?, ?, ?) "
                                      @"ON CONFLICT(uniqueid) DO NOTHING",
                                      event.idx, [event uniqueID], eventData];
          if (!success) *stop = YES;
        }];
  }];

  return success;
}

- (BOOL)backoffForPrimaryHash:(NSString*)hash {
  NSDate* backoff = _storeBackoff->get(santa::NSStringToUTF8String(hash));
  NSDate* now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) <
      self.unactionableEventCacheTimeSeconds) {
    return YES;
  } else {
    _storeBackoff->set(santa::NSStringToUTF8String(hash), now);
    return NO;
  }
}

#pragma mark Querying/Retreiving

- (NSUInteger)pendingEventsCount {
  __block NSUInteger eventsPending = 0;
  [self inDatabase:^(FMDatabase* db) {
    eventsPending = [db intForQuery:@"SELECT COUNT(*) FROM events"];
  }];
  return eventsPending;
}

- (NSArray*)pendingEvents {
  NSMutableArray* pendingEvents = [[NSMutableArray alloc] init];

  [self inDatabase:^(FMDatabase* db) {
    FMResultSet* rs = [db executeQuery:@"SELECT * FROM events"];

    while ([rs next]) {
      id obj = [self eventFromResultSet:rs];
      if (obj) {
        [pendingEvents addObject:obj];
      } else {
        [db executeUpdate:@"DELETE FROM events WHERE idx=?", [rs objectForColumn:@"idx"]];
      }
    }

    [rs close];
  }];

  return pendingEvents;
}

- (SNTStoredEvent*)eventFromResultSet:(FMResultSet*)rs {
  NSData* eventData = [rs dataNoCopyForColumn:@"eventdata"];
  if (!eventData) return nil;

  static NSSet* allowedClasses =
      [NSSet setWithObjects:[SNTStoredExecutionEvent class], [SNTStoredFileAccessEvent class],
                            [SNTStoredTemporaryMonitorModeAuditEvent class],
                            [SNTStoredTemporaryMonitorModeEnterAuditEvent class],
                            [SNTStoredTemporaryMonitorModeLeaveAuditEvent class], nil];
  NSError* err;
  SNTStoredEvent* event = [NSKeyedUnarchiver unarchivedObjectOfClasses:allowedClasses
                                                              fromData:eventData
                                                                 error:&err];

  if (event && !err && [self isValidStoredEvent:event]) {
    return event;
  } else {
    LOGW(@"Unable to unarchive stored event: %@", err);
    return nil;
  }
}

#pragma mark Deleting

- (void)deleteEventWithId:(NSNumber*)index {
  [self inDatabase:^(FMDatabase* db) {
    [db executeUpdate:@"DELETE FROM events WHERE idx=?", index];
  }];
}

- (void)deleteEventsWithIds:(NSArray*)indexes {
  [self inDatabase:^(FMDatabase* db) {
    for (NSNumber* index in indexes) {
      [db executeUpdate:@"DELETE FROM events WHERE idx=?", index];
    }
  }];
}

#pragma mark Signal reports

- (NSArray<SNTStoredSignalReport*>*)addStoredSignalReports:
    (NSArray<SNTStoredSignalReport*>*)reports {
  NSMutableArray<SNTStoredSignalReport*>* stored = [NSMutableArray array];
  [self inTransaction:^(FMDatabase* db, BOOL* rollback) {
    for (SNTStoredSignalReport* report in reports) {
      if (![report isKindOfClass:[SNTStoredSignalReport class]] || report.reportData.length == 0) {
        continue;
      }
      // Deduplicate: skip a report whose signal already fired within the dedup window. A
      // misconfigured signal can match on every event, and uploading thousands of identical
      // reports adds server load without adding value.
      if (report.name.length && [self backoffForSignalName:report.name]) {
        continue;
      }
      if (![db executeUpdate:@"INSERT INTO 'signal_reports' (idx, report_data) VALUES (?, ?) "
                             @"ON CONFLICT(idx) DO NOTHING",
                             report.idx, report.reportData]) {
        *rollback = YES;
        [stored removeAllObjects];
        return;
      }
      // ON CONFLICT skips silently and still reports success, so only treat the report as stored
      // if a row was actually inserted. Capture the assigned rowid so the immediate upload path
      // (which deletes by idx after a successful upload) has it.
      if ([db changes] > 0) {
        report.idx = @([db lastInsertRowId]);
        [stored addObject:report];
      }
    }
  }];
  return stored;
}

// Returns YES if a signal with this name fired within the dedup window (and should be dropped).
// Otherwise records the current time as its last-stored time and returns NO.
- (BOOL)backoffForSignalName:(NSString*)name {
  NSDate* backoff = _signalReportBackoff->get(santa::NSStringToUTF8String(name));
  NSDate* now = [NSDate date];
  if (([now timeIntervalSince1970] - [backoff timeIntervalSince1970]) <
      kSignalReportDedupWindowSeconds) {
    return YES;
  }
  _signalReportBackoff->set(santa::NSStringToUTF8String(name), now);
  return NO;
}

- (NSArray<SNTStoredSignalReport*>*)pendingSignalReports {
  NSMutableArray<SNTStoredSignalReport*>* reports = [NSMutableArray array];
  [self inDatabase:^(FMDatabase* db) {
    FMResultSet* rs = [db executeQuery:@"SELECT idx, report_data FROM signal_reports"];
    while ([rs next]) {
      SNTStoredSignalReport* report =
          [[SNTStoredSignalReport alloc] initWithReportData:[rs dataForColumnIndex:1]];
      if (report) {
        report.idx = @([rs longLongIntForColumnIndex:0]);
        [reports addObject:report];
      } else {
        [db executeUpdate:@"DELETE FROM signal_reports WHERE idx=?",
                          @([rs longLongIntForColumnIndex:0])];
      }
    }
    [rs close];
  }];
  return reports;
}

- (void)deleteSignalReportsWithIds:(NSArray*)indexes {
  [self inDatabase:^(FMDatabase* db) {
    for (NSNumber* index in indexes) {
      [db executeUpdate:@"DELETE FROM signal_reports WHERE idx=?", index];
    }
  }];
}

@end
