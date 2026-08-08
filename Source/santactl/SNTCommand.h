/// Copyright 2017 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#include <cstdint>
#include <optional>

@class MOLXPCConnection;

@protocol SNTCommandProtocol <NSObject>

///
///  @return YES if command requires root.
///
+ (BOOL)requiresRoot;

///
///  @return YES if command requires connection to santad.
///
+ (BOOL)requiresDaemonConn;

///
///  A small summary of the command, to be printed with the list of available commands
///
+ (NSString*)shortHelpText;

///
///  A longer description of the command when the user runs <tt>santactl help x</tt>
///
+ (NSString*)longHelpText;

@optional

///
///  YES if the command should be hidden from usage text.
///
+ (BOOL)isHidden;

///
///  Additional names that should resolve to the command.
///
+ (NSSet<NSString*>*)aliases;

@end

@protocol SNTCommandRunProtocol <NSObject>

///
///  Called when the user is running the command
///  @param arguments an array of arguments passed in
///  @param daemonConn connection to santad. Will be nil if connection failed or
///      if @c requiresDaemonConn is @c NO
///
///  @note This method (or one of the methods it calls) is responsible for calling exit().
///
+ (void)runWithArguments:(NSArray*)arguments daemonConnection:(MOLXPCConnection*)daemonConn;

@end

///
///  What a duration string with no unit suffix means. `SNTDurationUnitNone`
///  makes a bare integer invalid.
///
typedef NS_ENUM(NSInteger, SNTDurationUnit) {
  SNTDurationUnitNone = 0,
  SNTDurationUnitSeconds,
  SNTDurationUnitMinutes,
  SNTDurationUnitHours,
  SNTDurationUnitDays,
};

@interface SNTCommand : NSObject <SNTCommandRunProtocol>

@property(nonatomic, readonly) MOLXPCConnection* daemonConn;

///  Designated initializer
- (instancetype)initWithDaemonConnection:(MOLXPCConnection*)daemonConn;

- (void)runWithArguments:(NSArray*)arguments;

- (void)printErrorUsageAndExit:(NSString*)error;

///
///  Parse a duration string into whole seconds. Accepts an optionally-signed
///  integer followed by a single unit suffix: 's', 'm', 'h' or 'd'. With no
///  suffix, `defaultUnit` decides; if that is `SNTDurationUnitNone`, a bare
///  integer is invalid.
///
///  The only failure mode is a syntax error, which includes a value the scanner
///  could not read faithfully or that the result cannot represent. Zero and
///  negative values parse successfully — whether they are *acceptable* is the
///  caller's constraint to enforce, along with any granularity or bounds
///  requirement.
///
///  Returns std::nullopt on a syntax error, populating `error` with
///  `SNTErrorCodeInvalidDuration` when `error` is non-NULL.
///
+ (std::optional<int64_t>)parseTimeInterval:(NSString*)duration
                                defaultUnit:(SNTDurationUnit)defaultUnit
                                      error:(NSError**)error;
@end
