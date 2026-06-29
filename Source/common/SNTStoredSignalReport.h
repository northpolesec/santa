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

/// A signal report produced by a Sleigh signal scan, stored in the events
/// database (signal_reports table) pending upload to the sync server.
/// `reportData` is a serialized santa.telemetry.v1.SignalReport proto (which is
/// wire-compatible with santa.sync.v2.SignalReport).
@interface SNTStoredSignalReport : NSObject <NSSecureCoding>

/// An index for this report, randomly generated during initialization.
@property(nonnull) NSNumber* idx;

/// The fired signal's name (santa.common.v1.Signal.name). Used to deduplicate repeated firings
/// of the same signal. May be nil for reports reconstructed from the database (where it is not
/// needed).
@property(nullable, copy) NSString* name;

@property(nonnull, copy) NSData* reportData;

- (nullable instancetype)initWithReportData:(nonnull NSData*)reportData;

@end
