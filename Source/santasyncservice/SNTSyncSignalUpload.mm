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

#import "Source/santasyncservice/SNTSyncSignalUpload.h"

#include <climits>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTXPCControlInterface.h"
#include "Source/common/String.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"
#include "google/protobuf/arena.h"
#include "syncv2/v2.pb.h"

using santa::NSStringToUTF8String;

namespace pbv2 = ::santa::sync::v2;

@interface SNTSyncSignalUpload ()
/// Upload the given signal reports. On success, removes them from the database.
- (BOOL)uploadSignalReports:(NSArray<SNTStoredSignalReport*>*)reports;
@end

@implementation SNTSyncSignalUpload

- (NSURL*)stageURL {
  NSString* stageName = [@"signalupload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block BOOL success = YES;
  [[self.daemonConn remoteObjectProxy]
      databaseSignalReportsPending:^(NSArray<SNTStoredSignalReport*>* reports) {
        if (reports.count) {
          success = [self uploadSignalReports:reports];
        }
        dispatch_semaphore_signal(sema);
      }];
  if (dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER) != 0) {
    return NO;
  }
  return success;
}

- (BOOL)uploadSignalReports:(NSArray<SNTStoredSignalReport*>*)reports {
  if (!reports.count) {
    return YES;
  }

  google::protobuf::Arena arena;
  auto req = google::protobuf::Arena::Create<pbv2::SignalUploadRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));

  // Reports that should be removed from the DB once the upload succeeds. Includes any that
  // fail to parse — corrupt rows are dropped rather than retried forever.
  NSMutableArray<NSNumber*>* idsToRemove = [NSMutableArray arrayWithCapacity:reports.count];
  for (SNTStoredSignalReport* report in reports) {
    [idsToRemove addObject:report.idx];

    // The stored bytes are a santa.telemetry.v1.SignalReport, which is wire-compatible with
    // santa.sync.v2.SignalReport (identical field numbers and types), so they parse directly.
    pbv2::SignalReport* r = req->add_signal_reports();
    if (report.reportData.length > INT_MAX) {
      // ParseFromArray takes an int length; avoid a silent 64->32 bit truncation.
      SLOGE(@"Signal report too large (%lu bytes); dropping",
            (unsigned long)report.reportData.length);
      req->mutable_signal_reports()->RemoveLast();
    } else if (!r->ParseFromArray(report.reportData.bytes, (int)report.reportData.length)) {
      SLOGE(@"Failed to parse stored signal report; dropping");
      req->mutable_signal_reports()->RemoveLast();
    }
  }

  pbv2::SignalUploadResponse response;
  NSError* err = [self performRequest:[self requestWithMessage:req]
                          intoMessage:&response
                              timeout:30];
  if (err) {
    SLOGE(@"Failed to upload signal reports: %@", err);
    return NO;
  }

  SLOGI(@"Uploaded %lu signal report(s)", (unsigned long)reports.count);
  [[self.daemonConn remoteObjectProxy] databaseRemoveSignalReportsWithIDs:idsToRemove];
  return YES;
}

@end
