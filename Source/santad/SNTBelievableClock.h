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
///  saved reading carried forward with mach continuous time. Setting the system
///  clock backwards therefore cannot re-open a closed policy_for_range() window
///  or push out a pending timed kill, because the floor only ever rises.
///
///  The reading is {Wall, MachContinuous, BootSessionUUID} under the state file
///  key `ClockReading`: a wall time and the mach continuous value read at the
///  same instant. Mach continuous time counts across sleep and restarts at
///  boot, so elapsed time since the reading is exactly what a rolled-back wall
///  clock cannot fake. It is written at daemon start and rewritten every 10
///  minutes by a timer on the uptime clock, which no change to the wall clock
///  can delay. The timer, not execution traffic, is what bounds how stale the
///  reading and the refreshHandler below can get: an idle machine keeps both
///  current. It pauses while the machine sleeps, which costs nothing, since a
///  sleeping machine runs no executions and its wall-clock timers fire on wake.
///
///  A reading from an earlier boot session (its saved UUID is not the current
///  one) cannot be carried forward at all, since its mach value belongs to a
///  timeline that no longer exists; its wall value is the floor by itself until
///  this daemon start's own reading replaces it, and only while it is within 30
///  days of the system clock. Nothing vouches for such a reading, so one further
///  ahead than that is discarded and logged rather than believed forever.
///
///  Forward jumps are believed, and stick: a wall clock that jumps ahead raises
///  the floor, and moving it back afterwards does not lower it again. That is
///  the same rule stated once, not a special case. Within a boot session mach
///  continuous time vouches for the distance, so there the stickiness has no
///  bound; the 30 days above is the bound on inheriting one across a reboot.
///
@interface SNTBelievableClock : NSObject

///
///  Constructing the clock is what reads the reading a previous daemon left and
///  writes this start's own, so it is done once, before anything asks the time.
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
///  clock's lock released. That is what makes it safe for the handler to ask
///  this clock for the time, or to block on a queue that will: @synchronized is
///  recursive, so the same thread asking again would not have deadlocked either
///  way, but a handler that waits on another thread to answer would have. Safe
///  to leave nil.
///
@property(copy) void (^refreshHandler)(void);

@end

#endif  // SANTA_SANTAD_SNTBELIEVABLECLOCK_H
