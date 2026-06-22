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

#import <Foundation/Foundation.h>

#import "Source/common/SNTStoredSignalReport.h"
#import "Source/santasyncservice/SNTSyncStage.h"

/// Uploads pending signal reports to the sync server's signalupload handler.
/// Only supported in sync v2.
@interface SNTSyncSignalUpload : SNTSyncStage

/// Upload the given signal reports. On success, removes them from the database.
- (BOOL)uploadSignalReports:(NSArray<SNTStoredSignalReport*>*)reports;

@end
