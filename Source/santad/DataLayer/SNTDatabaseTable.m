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

#import "Source/santad/DataLayer/SNTDatabaseTable.h"

#include <sqlite3.h>
#include <stdint.h>

#import "Source/common/SNTLogging.h"

@interface SNTDatabaseTable ()
@property FMDatabaseQueue *dbQ;
@end

@implementation SNTDatabaseTable

- (instancetype)initWithDatabaseQueue:(FMDatabaseQueue *)db {
  if (!db) return nil;

  self = [super init];
  if (self) {
    __block BOOL bail = NO;

    [db inDatabase:^(FMDatabase *db) {
      if (![db goodConnection]) {
        if ([db lastErrorCode] == SQLITE_LOCKED) {
          LOGW(@"The database '%@' is locked by another process. Aborting.", [db databasePath]);
          [db close];
          bail = YES;
          return;
        }
        [self closeDeleteReopenDatabase:db];
      } else if ([db userVersion] > [self currentSupportedVersion]) {
        LOGW(@"Database version newer than supported. Deleting.");
        [self closeDeleteReopenDatabase:db];
      }
    }];

    if (bail) return nil;

    _dbQ = db;
    [self updateTableSchema];
  }
  return self;
}

- (instancetype)init {
  [self doesNotRecognizeSelector:_cmd];
  return nil;
}

- (void)closeDeleteReopenDatabase:(FMDatabase *)db {
  [db close];
  [[NSFileManager defaultManager] removeItemAtPath:[db databasePath] error:NULL];
  [db open];
}

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (uint32_t)currentSupportedVersion {
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

- (uint32_t)currentVersion {
  __block uint32_t curVersion = 0;
  [self.dbQ inDatabase:^(FMDatabase *db) {
    curVersion = [db userVersion];
  }];

  return curVersion;
}

/// Called at the end of initialization to ensure the table in the
/// database exists and uses the latest schema.
- (void)updateTableSchema {
  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    uint32_t currentVersion = [db userVersion];
    uint32_t newVersion = [self initializeDatabase:db fromVersion:currentVersion];
    if (newVersion < 1) return;

    LOGI(@"Updated %@ from version %d to %d", [self className], currentVersion, newVersion);

    [db setUserVersion:newVersion];
  }];

  // Vacuum the database to cleanup after version upgrades.
  [self vacuum];
}

- (void)inDatabase:(void (^)(FMDatabase *db))block {
  [self.dbQ inDatabase:block];
}

- (void)inTransaction:(void (^)(FMDatabase *db, BOOL *rollback))block {
  [self.dbQ inTransaction:block];
}

- (void)vacuum {
  [self.dbQ inDatabase:^(FMDatabase *db) {
    [db executeUpdate:@"VACUUM"];
  }];
}

@end
