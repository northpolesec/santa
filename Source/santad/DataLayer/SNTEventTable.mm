/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santad/DataLayer/SNTEventTable.h"

#import "Source/common/MOLCertificate.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTStoredFileAccessEvent.h"

static const uint32_t kEventTableCurrentVersion = 5;

@implementation SNTEventTable

- (uint32_t)currentSupportedVersion {
  return kEventTableCurrentVersion;
}

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
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
    [db executeUpdate:@"ALTER TABLE events RENAME COLUMN filesha256 TO uniqueid"];
    [db executeUpdate:@"DROP INDEX filesha256"];
    [db executeUpdate:@"CREATE UNIQUE INDEX uniqueid ON events (uniqueid)"];
    newVersion = 4;
  }

  return newVersion;
}

#pragma mark Loading / Storing

- (BOOL)addStoredEvent:(SNTStoredEvent *)event {
  return [self addStoredEvents:@[ event ]];
}

- (BOOL)isValidStoredEvent:(SNTStoredEvent *)event {
  if ([event isKindOfClass:[SNTStoredExecutionEvent class]]) {
    SNTStoredExecutionEvent *se = (SNTStoredExecutionEvent *)event;
    return se.idx && [[se uniqueID] length] && se.filePath.length && se.occurrenceDate &&
           se.decision;
  } else if ([event isKindOfClass:[SNTStoredFileAccessEvent class]]) {
    SNTStoredFileAccessEvent *se = (SNTStoredFileAccessEvent *)event;
    return se.idx && se.ruleVersion.length && se.ruleName.length && se.accessedPath.length &&
           se.process.filePath.length && [[se uniqueID] length];
  } else {
    return NO;
  }
}

- (BOOL)addStoredEvents:(NSArray<SNTStoredEvent *> *)events {
  NSMutableDictionary *eventsData = [NSMutableDictionary dictionaryWithCapacity:events.count];
  for (SNTStoredEvent *event in events) {
    if (![self isValidStoredEvent:event]) {
      continue;
    }

    NSData *eventData = [NSKeyedArchiver archivedDataWithRootObject:event
                                              requiringSecureCoding:YES
                                                              error:nil];
    if (eventData) {
      eventsData[eventData] = event;
    }
  }

  __block BOOL success = NO;
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    [eventsData
        enumerateKeysAndObjectsUsingBlock:^(NSData *eventData, SNTStoredEvent *event, BOOL *stop) {
          success = [db executeUpdate:@"INSERT INTO 'events' (idx, uniqueid, eventdata) "
                                      @"VALUES (?, ?, ?) "
                                      @"ON CONFLICT(uniqueid) DO NOTHING",
                                      event.idx, [event uniqueID], eventData];
          if (!success) *stop = YES;
        }];
  }];

  return success;
}

#pragma mark Querying/Retreiving

- (NSUInteger)pendingEventsCount {
  __block NSUInteger eventsPending = 0;
  [self inDatabase:^(FMDatabase *db) {
    eventsPending = [db intForQuery:@"SELECT COUNT(*) FROM events"];
  }];
  return eventsPending;
}

- (NSArray *)pendingEvents {
  NSMutableArray *pendingEvents = [[NSMutableArray alloc] init];

  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM events"];

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

- (SNTStoredEvent *)eventFromResultSet:(FMResultSet *)rs {
  NSData *eventData = [rs dataForColumn:@"eventdata"];
  if (!eventData) return nil;

  NSError *err;
  SNTStoredEvent *event = [NSKeyedUnarchiver
      unarchivedObjectOfClasses:[NSSet setWithObjects:[SNTStoredExecutionEvent class],
                                                      [SNTStoredFileAccessEvent class], nil]
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

- (void)deleteEventWithId:(NSNumber *)index {
  [self inDatabase:^(FMDatabase *db) {
    [db executeUpdate:@"DELETE FROM events WHERE idx=?", index];
  }];
}

- (void)deleteEventsWithIds:(NSArray *)indexes {
  [self inDatabase:^(FMDatabase *db) {
    for (NSNumber *index in indexes) {
      [db executeUpdate:@"DELETE FROM events WHERE idx=?", index];
    }
  }];
}

@end
