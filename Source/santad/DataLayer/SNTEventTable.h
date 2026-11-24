/// Copyright 2015 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#import "Source/santad/DataLayer/SNTDatabaseTable.h"

@class SNTNotificationMessage;
@class SNTStoredEvent;
@class SNTStoredExecutionEvent;
@class SNTStoredSignalReport;

///
/// Responsible for managing the event table.
///
@interface SNTEventTable : SNTDatabaseTable

///
///  Add event to the database.
///
///  @param event the event to store.
///  @return YES if event was successfully stored.
///
- (BOOL)addStoredEvent:(SNTStoredEvent*)event;

///
///  Add events to the database.
///
///  @param events the events to store.
///  @return YES if events were successfully stored.
///
- (BOOL)addStoredEvents:(NSArray<SNTStoredEvent*>*)events;

///
///  Retrieves all events in the database
///
///  @return NSArray of SNTStoredEvent's
///
- (NSArray*)pendingEvents;

///
///  Retrieves number of events in database without fetching every event.
///
///  @return Number of events in database.
///
- (NSUInteger)pendingEventsCount;

///
///  Store the bundle flow's bundle-hashed copy of a block event. It updates the waiting row of the
///  same event in place. If that row is gone, for example because a sync uploaded it, the copy is
///  stored again, at most once per binary per block backoff window.
///
///  @param event the event, with its bundle hash set.
///
- (void)storeBundleHashedEvent:(SNTStoredExecutionEvent*)event;

///
///  Delete multiple events from the database with an array of IDs.
///
///  @param indexes an array of event IDs.
///
- (void)deleteEventsWithIds:(NSArray*)indexes;

#pragma mark Signal reports

///
///  Add signal reports (produced by a Sleigh signal scan) to the database, pending upload.
///  Repeated firings of the same signal are deduplicated to at most one per signal name per
///  dedup window, so a misconfigured signal cannot flood the server with identical reports.
///
///  @return the subset of `reports` that were actually stored (i.e. not deduplicated), so the
///  caller can upload exactly what was persisted.
///
- (NSArray<SNTStoredSignalReport*>*)addStoredSignalReports:
    (NSArray<SNTStoredSignalReport*>*)reports;

///
///  Retrieves all pending signal reports in the database.
///
- (NSArray<SNTStoredSignalReport*>*)pendingSignalReports;

///
///  Delete multiple signal reports from the database with an array of IDs.
///
- (void)deleteSignalReportsWithIds:(NSArray*)indexes;

@end
