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

#import "Source/santad/SNTBelievableClock.h"

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <mach/mach_time.h>

#include <algorithm>
#include <cmath>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/SystemResources.h"

// Fields of the persisted reading.
static NSString* const kReadingWallKey = @"Wall";
static NSString* const kReadingMachKey = @"MachContinuous";
static NSString* const kReadingBootSessionUUIDKey = @"BootSessionUUID";

// How often the reading is rewritten, and so the whole of what the floor can be
// behind: a restart, or a rolled-back deadline, is at most this far out of date.
static const NSTimeInterval kRefreshInterval = 600;

// The timer is allowed to run this fraction of its interval late, which is what
// lets the OS coalesce a ten minute timer with other wakeups.
static const uint64_t kLeewayDivisor = 10;

// How far ahead of the system clock a reading from an earlier boot session may
// be and still be believed. Nothing vouches for one, so without a ceiling a
// single bad clock leaves a floor years ahead that every later reboot preserves.
static const NSTimeInterval kMaxCrossBootLead = 30 * 24 * 60 * 60;

namespace {

// A wall time and the mach continuous value read at the same instant. Kept
// together because that pairing is the whole content of a reading: either value
// on its own says nothing.
struct Reading {
  NSTimeInterval wall;
  uint64_t mach;
};

// Seconds of mach continuous time between two readings, which counts across
// sleep. A `later` that is not later cannot happen within one boot session, so a
// pair claiming it is corrupt and carries nothing forward.
NSTimeInterval SecondsBetweenMach(uint64_t earlier, uint64_t later) {
  if (later <= earlier) {
    return 0;
  }
  return (NSTimeInterval)MachTimeToNanos(later - earlier) / NSEC_PER_SEC;
}

}  // namespace

@interface SNTBelievableClock ()
@property SNTConfigurator* configurator;
/// The three host readings this class is built on. Replaced wholesale by tests,
/// which have no other way to move a clock.
@property(copy) NSDate* (^wallClock)(void);
@property(copy) uint64_t (^machContinuous)(void);
@property(copy) NSString* (^bootSessionUUID)(void);

- (instancetype)initWithConfigurator:(SNTConfigurator*)configurator
                     refreshInterval:(NSTimeInterval)refreshInterval
                           wallClock:(NSDate* (^)(void))wallClock
                      machContinuous:(uint64_t (^)(void))machContinuous
                     bootSessionUUID:(NSString* (^)(void))bootSessionUUID NS_DESIGNATED_INITIALIZER;
@end

@implementation SNTBelievableClock {
  /// The floor as it stands in memory, always from this boot session. Every
  /// answer this clock gives becomes the new floor, which is what makes the
  /// floor a high-water mark. Only ever touched under @synchronized(self).
  Reading _floor;

  dispatch_queue_t _tickQueue;
  dispatch_source_t _tickTimer;
}

- (instancetype)initWithConfigurator:(SNTConfigurator*)configurator {
  return [self initWithConfigurator:configurator
      refreshInterval:kRefreshInterval
      wallClock:^NSDate* {
        return [NSDate date];
      }
      machContinuous:^uint64_t {
        return mach_continuous_time();
      }
      bootSessionUUID:^NSString* {
        return [SNTSystemInfo bootSessionUUID];
      }];
}

- (instancetype)initWithConfigurator:(SNTConfigurator*)configurator
                     refreshInterval:(NSTimeInterval)refreshInterval
                           wallClock:(NSDate* (^)(void))wallClock
                      machContinuous:(uint64_t (^)(void))machContinuous
                     bootSessionUUID:(NSString* (^)(void))bootSessionUUID {
  self = [super init];
  if (self) {
    _configurator = configurator;
    _wallClock = wallClock;
    _machContinuous = machContinuous;
    _bootSessionUUID = bootSessionUUID;

    // The reading on disk is the only memory of time a daemon start has, so it
    // is read before this start's own reading overwrites it.
    Reading reading;
    @synchronized(self) {
      reading = [self believableNowFromSavedReadingSynchronized];
      [self raiseFloorSynchronizedTo:reading];
    }
    [self persistReading:reading];

    [self startTickTimerWithInterval:refreshInterval];
  }
  return self;
}

- (void)dealloc {
  // The event handler holds only a weak reference, so nothing kept this object
  // alive on the timer's behalf; the source itself still has to be stopped.
  if (_tickTimer) {
    dispatch_source_cancel(_tickTimer);
  }
}

- (NSDate*)now {
  Reading reading;

  @synchronized(self) {
    reading = [self believableNowSynchronized];
    [self raiseFloorSynchronizedTo:reading];
  }

  return [NSDate dateWithTimeIntervalSince1970:reading.wall];
}

#pragma mark Private methods

/// The periodic refresh. This is what keeps the reading, and the refreshHandler,
/// on a cadence that owes nothing to how many executions the machine happens to
/// see: on an idle machine nothing else would ask this clock for the time.
- (void)tick {
  Reading reading;
  void (^handler)(void) = nil;

  @synchronized(self) {
    reading = [self believableNowSynchronized];
    [self raiseFloorSynchronizedTo:reading];
    handler = self.refreshHandler;
  }

  // Both run unlocked: the write is disk I/O and the handler may re-enter.
  [self persistReading:reading];
  if (handler) {
    handler();
  }
}

- (void)startTickTimerWithInterval:(NSTimeInterval)interval {
  _tickQueue = dispatch_queue_create("com.northpolesec.santa.daemon.believable_clock",
                                     DISPATCH_QUEUE_SERIAL);
  _tickTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _tickQueue);

  __weak SNTBelievableClock* weakSelf = self;
  dispatch_source_set_event_handler(_tickTimer, ^{
    [weakSelf tick];
  });

  // DISPATCH_TIME_NOW schedules on the uptime clock, so no change to the wall
  // clock can move a tick. It stops while the machine sleeps, which costs nothing.
  uint64_t nanos = (uint64_t)(interval * NSEC_PER_SEC);
  dispatch_source_set_timer(_tickTimer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)nanos), nanos,
                            nanos / kLeewayDivisor);
  dispatch_resume(_tickTimer);
}

/// Writes a reading out as the one a later daemon start picks up. Takes the
/// reading by value and holds no lock, so the state file write is never on the
/// path of a thread waiting to be told the time.
- (void)persistReading:(Reading)reading {
  if (![self.configurator persistClockReading:@{
        kReadingWallKey : @(reading.wall),
        kReadingMachKey : @(reading.mach),
        // Empty rather than absent when the boot session can't be read: the
        // reading stays well-formed, and matches no boot session on the way
        // back in, so it is never carried forward.
        kReadingBootSessionUUIDKey : self.bootSessionUUID() ?: @"",
      }]) {
    LOGE(@"Unable to persist the clock reading; a daemon restart will not recover this time");
  }
}

#pragma mark Private methods, all under @synchronized(self)

/// The minimum believable time now, paired with the mach reading it was measured
/// against: the system wall clock, floored by the in-memory floor carried
/// forward to that same mach reading.
- (Reading)believableNowSynchronized {
  uint64_t mach = self.machContinuous();
  return {.wall = std::max(self.wallClock().timeIntervalSince1970,
                           _floor.wall + SecondsBetweenMach(_floor.mach, mach)),
          .mach = mach};
}

/// The minimum believable time from the reading a previous daemon left on disk.
/// One whose boot session is not the current one carries no elapsed time: its
/// mach value belongs to a timeline that ended at the reboot, so only its wall
/// value is left, and only if it is close enough to the system clock.
- (Reading)believableNowFromSavedReadingSynchronized {
  uint64_t mach = self.machContinuous();
  NSTimeInterval wall = self.wallClock().timeIntervalSince1970;
  Reading systemClock = {.wall = wall, .mach = mach};

  // The state file is on disk, so every field is validated rather than trusted;
  // an unusable reading is the same answer a missing one gives.
  NSDictionary* reading = [self.configurator savedClockReading];
  if (![reading isKindOfClass:[NSDictionary class]] ||
      ![reading[kReadingWallKey] isKindOfClass:[NSNumber class]] ||
      ![reading[kReadingMachKey] isKindOfClass:[NSNumber class]] ||
      ![reading[kReadingBootSessionUUIDKey] isKindOfClass:[NSString class]]) {
    return systemClock;
  }

  // A plist real round-trips both infinities and NaN, and neither can be compared
  // its way out of a max(). A wall value that is not finite is no reading at all.
  NSTimeInterval savedWall = [reading[kReadingWallKey] doubleValue];
  if (!std::isfinite(savedWall)) {
    LOGW(@"Discarding a saved clock reading: its wall time is not a finite number");
    return systemClock;
  }

  // A nil current UUID compares equal to nothing, which lands here: no
  // projection, which is the safe direction.
  if (![reading[kReadingBootSessionUUIDKey] isEqualToString:self.bootSessionUUID()]) {
    if (savedWall - wall > kMaxCrossBootLead) {
      LOGW(@"Discarding a saved clock reading from an earlier boot session: %@ is more than %g "
           @"days ahead of the system clock (%@)",
           [NSDate dateWithTimeIntervalSince1970:savedWall], kMaxCrossBootLead / (24 * 60 * 60),
           [NSDate dateWithTimeIntervalSince1970:wall]);
      return systemClock;
    }
    return {.wall = std::max(wall, savedWall), .mach = mach};
  }

  uint64_t savedMach = [reading[kReadingMachKey] unsignedLongLongValue];
  return {.wall = std::max(wall, savedWall + SecondsBetweenMach(savedMach, mach)), .mach = mach};
}

/// Moves the floor to `reading`, whose wall value is by construction never below
/// the floor it replaces: that is what a wall clock moved backwards runs into,
/// and what makes a wall clock moved forwards stick. The mach value is the one
/// that wall value was measured against, so nothing elapsed is lost here.
- (void)raiseFloorSynchronizedTo:(Reading)reading {
  _floor = reading;
}

@end
