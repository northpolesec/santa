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

#ifndef SANTA_SANTAD_SNTBELIEVABLECLOCK_H
#define SANTA_SANTAD_SNTBELIEVABLECLOCK_H

#import <Foundation/Foundation.h>

@class SNTConfigurator;

///
///  The minimum believable current time: the system wall clock, floored by a
///  saved reading carried forward with mach continuous time. The floor only
///  ever rises, so a backwards clock change cannot re-open a closed
///  policy_for_range() window or push out a pending timed kill.
///
///  The reading is {Wall, MachContinuous, BootSessionUUID} under the state file
///  key `ClockReading`, written at daemon start and rewritten every 10 minutes.
///  One from an earlier boot session has no live mach timeline, so its wall
///  value floors alone, and only while within 30 days of the system clock.
///
@interface SNTBelievableClock : NSObject

///
///  Reads the reading a previous daemon left and writes this start's own, so
///  construct it once, before anything asks the time.
///
- (instancetype)initWithConfigurator:(SNTConfigurator*)configurator;

- (instancetype)init NS_UNAVAILABLE;

///
///  The minimum believable time now. Every answer raises the floor, so nothing
///  a clock change does can make a later answer smaller than an earlier one.
///  Writes nothing: the reading is the timer's business.
///
- (NSDate*)now;

///
///  Runs after every reading refresh, and so once every 10 minutes, with the
///  clock's lock released, which is what makes it safe for the handler to ask
///  this clock for the time or to block on a queue that will. Safe to leave nil.
///
@property(copy) void (^refreshHandler)(void);

@end

#endif  // SANTA_SANTAD_SNTBELIEVABLECLOCK_H
