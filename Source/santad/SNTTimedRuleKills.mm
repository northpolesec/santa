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

#import "Source/santad/SNTTimedRuleKills.h"

#import <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <signal.h>
#include <sys/param.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#include "Source/common/SystemResources.h"
#include "Source/common/Timer.h"
#include "Source/common/cel/PolicyForRangeFunction.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/KillingMachine.h"
#import "Source/santad/SNTBelievableClock.h"
#import "Source/santad/SNTNotificationQueue.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"

// Fields of a persisted entry.
static NSString* const kEntryRuleTypeKey = @"RuleType";
static NSString* const kEntryIdentifierKey = @"Identifier";
static NSString* const kEntryCELHashKey = @"CELHash";
static NSString* const kEntryDeadlineKey = @"Deadline";
static NSString* const kEntryNotifyAtKey = @"NotifyAt";
static NSString* const kEntryNotifiedKey = @"Notified";
static NSString* const kEntryWindowDaysKey = @"WindowDays";
static NSString* const kEntryWindowStartKey = @"WindowStart";
static NSString* const kEntryWindowEndKey = @"WindowEnd";
static NSString* const kEntryWindowZoneKey = @"WindowZone";
static NSString* const kEntryMachDeadlineKey = @"MachDeadline";
static NSString* const kEntryBootSessionUUIDKey = @"BootSessionUUID";

// A timer can fire marginally early; anything due within this window is treated
// as due now rather than re-arming for a fraction of a second.
static const NSTimeInterval kDueTolerance = 0.25;

// How long a matched process has to exit after SIGTERM before it is SIGKILLed.
static const NSTimeInterval kTermGrace = 5.0;

// How far ahead a mach deadline may point. The pair is arithmetic on a tick
// count, and a deadline centuries out would wrap it; a deadline past this is
// beyond anything a pending kill means, so it carries no pair at all and its
// wall instant governs alone.
static const NSTimeInterval kMaxMachDeadlineLead = 10 * 365 * 24 * 60 * 60;

/// One pending kill: the rule it came from, when it fires, whether the user has
/// already been warned, and the shape of the window the deadline came from (nil
/// for a window that does not recur).
@interface SNTTimedRuleKillEntry : NSObject
@property SNTRuleType ruleType;
@property(copy) NSString* identifier;
@property(copy) NSString* celHash;
@property NSDate* deadline;
@property NSDate* notifyAt;
@property BOOL notified;
@property(copy) NSArray<NSNumber*>* windowDays;
@property(copy) NSString* windowStart;
@property(copy) NSString* windowEnd;
@property(copy) NSString* windowZone;
/// The same deadline on the mach continuous clock, and the boot session that
/// reading belongs to. Zero and nil together when there is no pair, which leaves
/// the wall deadline above to govern on its own.
@property uint64_t machDeadline;
@property(copy) NSString* bootSessionUUID;

/// Deserializes a persisted entry, or nil when it isn't one: the state file is
/// on disk, so every field is validated rather than trusted.
+ (instancetype)entryFromDictionary:(NSDictionary*)dict;

@property(readonly) NSDictionary* dictionaryRepresentation;

/// Opaque map key: rule type, identifier and CEL hash. Never parsed back.
@property(readonly) NSString* key;
@end

namespace {

// Only the rule types KillingMachine can match against a running process. A
// BINARY or CERTIFICATE rule would mean hashing the executable of every process
// at the deadline.
bool SupportedRuleType(SNTRuleType ruleType) {
  return ruleType == SNTRuleTypeSigningID || ruleType == SNTRuleTypeTeamID ||
         ruleType == SNTRuleTypeCDHash;
}

// The persisted window shape, checked rather than trusted, because the state
// file is on disk: a day list must be an array of whole numbers 0 (Sunday)
// through 6 (Saturday), each time a 24-hour "HH:MM", and the zone a string
// policy_for_range()'s own resolver accepts. That is exactly what
// policy_for_range() accepts, and so exactly what a window can be rebuilt from.
// Anything else reads as no shape at all, which is the same answer a missing key
// gives: the entry still loads and still holds its deadline, it just has no
// window for a restart to re-check.
//
// Only the plist type checks are written here: a plist real round-trips where an
// integer was written, and 2.5 is no day of the week. What counts as a day and
// what counts as an HH:MM is asked of policy_for_range()'s own validators, the
// same way the zone is asked of its resolver, so all three answers come from the
// code the re-check will use.
NSArray<NSNumber*>* WindowDaysFromValue(id value) {
  if (![value isKindOfClass:[NSArray class]]) {
    return nil;
  }
  std::vector<int64_t> days;
  days.reserve([value count]);
  for (NSNumber* day in value) {
    if (![day isKindOfClass:[NSNumber class]] || (double)day.integerValue != day.doubleValue) {
      return nil;
    }
    days.push_back(day.integerValue);
  }
  return santa::cel::ValidateDays(days).ok() ? value : nil;
}

NSString* WindowTimeFromValue(id value) {
  NSString* time = [value isKindOfClass:[NSString class]] ? value : nil;
  if (!time.length) {
    return nil;
  }
  return santa::cel::ParseHourMinute(time.UTF8String) ? time : nil;
}

// The zone is checked by asking the resolver the re-check will use, rather than
// by matching its grammar here: a zone this daemon cannot resolve is one the
// window cannot be rebuilt in, whatever it looks like. That includes a name the
// host's zoneinfo no longer carries, so an entry can lose its shape between
// writing and loading. Nil then, which the caller reads as no shape: the window
// cannot be asked, so a past-due deadline is a kill.
NSString* WindowZoneFromValue(id value) {
  NSString* zone = [value isKindOfClass:[NSString class]] ? value : nil;
  if (!zone.length) {
    return nil;
  }
  return santa::cel::ResolveTimeZone(zone.UTF8String).ok() ? zone : nil;
}

// The mach half of a deadline, checked rather than trusted like everything else
// the state file holds: a tick count is a positive whole number, and a plist
// real round-trips both infinities and NaN, neither of which converts to one.
// Anything else reads as no mach deadline, which is the same answer a missing key
// gives, and the entry's wall deadline governs alone.
uint64_t MachDeadlineFromValue(id value) {
  if (![value isKindOfClass:[NSNumber class]]) {
    return 0;
  }
  double asDouble = [value doubleValue];
  if (!std::isfinite(asDouble) || asDouble <= 0) {
    return 0;
  }
  return [value unsignedLongLongValue];
}

// Identifiers that fetch exactly the rule an entry came from: one field set, so
// the rule table's type precedence never picks a different rule type.
struct RuleIdentifiers IdentifiersForEntry(SNTTimedRuleKillEntry* entry) {
  switch (entry.ruleType) {
    case SNTRuleTypeCDHash: return {.cdhash = entry.identifier};
    case SNTRuleTypeSigningID: return {.signingID = entry.identifier};
    case SNTRuleTypeTeamID: return {.teamID = entry.identifier};
    default: return {};
  }
}

// What to call a process in the warning window: the file name of its
// executable, which is what the user sees in the Dock, falling back to the (16
// character) accounting name. Nil when neither can be read.
NSString* DisplayNameForPid(pid_t pid) {
  char path[PROC_PIDPATHINFO_MAXSIZE] = {};
  if (proc_pidpath(pid, path, sizeof(path)) > 0) {
    return [@(path) lastPathComponent];
  }

  char name[2 * MAXCOMLEN] = {};
  if (proc_name(pid, name, sizeof(name)) > 0) {
    return @(name);
  }

  return nil;
}

// The kill is delivered to the process group of every match, with SIGKILL as
// the nominal signal; the term-then-kill path sends SIGTERM and SIGKILL itself
// and ignores this field.
SNTKillRequest* KillRequestForEntry(SNTTimedRuleKillEntry* entry) {
  NSString* uuid = [[NSUUID UUID] UUIDString];

  switch (entry.ruleType) {
    case SNTRuleTypeCDHash:
      return [[SNTKillRequestCDHash alloc] initWithUUID:uuid
                                                 cdHash:entry.identifier
                                                 signal:SIGKILL
                                    targetProcessGroups:YES];
    case SNTRuleTypeSigningID:
      return [[SNTKillRequestSigningID alloc] initWithUUID:uuid
                                                 signingID:entry.identifier
                                                    signal:SIGKILL
                                       targetProcessGroups:YES];
    case SNTRuleTypeTeamID:
      return [[SNTKillRequestTeamID alloc] initWithUUID:uuid
                                                 teamID:entry.identifier
                                                 signal:SIGKILL
                                    targetProcessGroups:YES];
    default: return nil;
  }
}

}  // namespace

@implementation SNTTimedRuleKillEntry

+ (instancetype)entryFromDictionary:(NSDictionary*)dict {
  if (![dict isKindOfClass:[NSDictionary class]] ||
      ![dict[kEntryRuleTypeKey] isKindOfClass:[NSNumber class]] ||
      ![dict[kEntryIdentifierKey] isKindOfClass:[NSString class]] ||
      ![dict[kEntryCELHashKey] isKindOfClass:[NSString class]] ||
      ![dict[kEntryDeadlineKey] isKindOfClass:[NSNumber class]] ||
      ![dict[kEntryNotifyAtKey] isKindOfClass:[NSNumber class]]) {
    return nil;
  }

  SNTRuleType ruleType = static_cast<SNTRuleType>([dict[kEntryRuleTypeKey] integerValue]);
  NSString* identifier = dict[kEntryIdentifierKey];
  NSString* celHash = dict[kEntryCELHashKey];
  // A plist real round-trips both infinities and NaN, and neither is an instant.
  // A NaN deadline is the worst of them: it answers false to every "has this
  // come due" question and leaves the countdown arming for zero seconds, firing
  // and re-arming for zero forever. An appointment that cannot be compared is no
  // appointment, so the record is dropped, which the caller logs.
  NSTimeInterval deadline = [dict[kEntryDeadlineKey] doubleValue];
  NSTimeInterval notifyAt = [dict[kEntryNotifyAtKey] doubleValue];
  if (!SupportedRuleType(ruleType) || !identifier.length || !celHash.length ||
      !std::isfinite(deadline) || !std::isfinite(notifyAt)) {
    return nil;
  }

  SNTTimedRuleKillEntry* entry = [[SNTTimedRuleKillEntry alloc] init];
  entry.ruleType = ruleType;
  entry.identifier = identifier;
  entry.celHash = celHash;
  entry.deadline = [NSDate dateWithTimeIntervalSince1970:deadline];
  entry.notifyAt = [NSDate dateWithTimeIntervalSince1970:notifyAt];
  // The one optional field: absent on entries written before the warning window
  // existed, so a missing key is a valid NO rather than a reason to drop the
  // entry. Guarded like every other field, though, so a non-NSNumber value on
  // disk can't reach -boolValue and crash-loop the daemon at startup.
  id notified = dict[kEntryNotifiedKey];
  entry.notified = [notified isKindOfClass:[NSNumber class]] && [notified boolValue];
  // Absent on an entry whose window does not recur, so a missing key is the
  // normal case rather than a reason to drop the entry. A shape is only usable
  // whole, so a partial one, like an unreadable one, is no shape.
  NSArray<NSNumber*>* windowDays = WindowDaysFromValue(dict[kEntryWindowDaysKey]);
  NSString* windowStart = WindowTimeFromValue(dict[kEntryWindowStartKey]);
  NSString* windowEnd = WindowTimeFromValue(dict[kEntryWindowEndKey]);
  NSString* windowZone = WindowZoneFromValue(dict[kEntryWindowZoneKey]);
  if (windowDays.count && windowStart.length && windowEnd.length && windowZone.length) {
    entry.windowDays = windowDays;
    entry.windowStart = windowStart;
    entry.windowEnd = windowEnd;
    entry.windowZone = windowZone;
  }
  // Also absent on an entry written before there was a mach deadline to write.
  // A tick count says nothing without the boot session it was read in, so like
  // the window shape this is taken whole or not at all.
  uint64_t machDeadline = MachDeadlineFromValue(dict[kEntryMachDeadlineKey]);
  NSString* bootSessionUUID = [dict[kEntryBootSessionUUIDKey] isKindOfClass:[NSString class]]
                                  ? dict[kEntryBootSessionUUIDKey]
                                  : nil;
  if (machDeadline && bootSessionUUID.length) {
    entry.machDeadline = machDeadline;
    entry.bootSessionUUID = bootSessionUUID;
  }
  return entry;
}

- (NSDictionary*)dictionaryRepresentation {
  NSMutableDictionary* dict = [@{
    kEntryRuleTypeKey : @(self.ruleType),
    kEntryIdentifierKey : self.identifier,
    kEntryCELHashKey : self.celHash,
    kEntryDeadlineKey : @(self.deadline.timeIntervalSince1970),
    kEntryNotifyAtKey : @(self.notifyAt.timeIntervalSince1970),
    kEntryNotifiedKey : @(self.notified),
  } mutableCopy];

  if (self.windowDays.count && self.windowStart.length && self.windowEnd.length &&
      self.windowZone.length) {
    dict[kEntryWindowDaysKey] = self.windowDays;
    dict[kEntryWindowStartKey] = self.windowStart;
    dict[kEntryWindowEndKey] = self.windowEnd;
    dict[kEntryWindowZoneKey] = self.windowZone;
  }
  if (self.machDeadline && self.bootSessionUUID.length) {
    dict[kEntryMachDeadlineKey] = @(self.machDeadline);
    dict[kEntryBootSessionUUIDKey] = self.bootSessionUUID;
  }
  return dict;
}

- (NSString*)key {
  return
      [NSString stringWithFormat:@"%ld|%@|%@", (long)self.ruleType, self.identifier, self.celHash];
}

@end

@interface SNTTimedRuleKills ()
@property SNTNotificationQueue* notifierQueue;
@property SNTRuleTable* ruleTable;
@property SNTConfigurator* configurator;
@property SNTBelievableClock* clock;
@property dispatch_queue_t queue;
/// Entries keyed by rule type, identifier and CEL hash, so repeated execs under
/// the same rule share one entry. Only ever touched on `queue`.
@property NSMutableDictionary<NSString*, SNTTimedRuleKillEntry*>* entries;
/// The interval the countdown was last armed for, in seconds, or zero when it
/// was stopped. Written on every pass over the entries, so a test can see a
/// countdown that was armed before the system clock moved being corrected.
@property uint32_t armedTimerSeconds;
/// Test seam for the one call with no safe form to exercise against real
/// processes: one kill pass over every request that has come due, answering with
/// one response each. Never set in production, where the real kill runs instead.
@property(copy) NSArray<SNTKillResponse*>* (^killBlock)
    (NSArray<SNTKillRequest*>* requests, NSTimeInterval grace);
/// Test seam paired with killBlock: the pid of something the rule covers that
/// is running, or nil for nothing running. Nothing a test runs can be made to
/// match a rule, so the match is the part that is faked; naming the pid and
/// deciding on the warning window are the production path either way. Never set
/// in production.
@property(copy) NSNumber* (^matchBlock)(SNTKillRequest* request);

- (void)onDeadlineTimer;
- (void)onClockRefresh;
@end

namespace {

// Timer<T> is a CRTP mixin, so the fire hook has to be a C++ type. This shim is
// that type and nothing more: it holds a weak reference to the component and
// hands the fire straight back to it.
class DeadlineTimer : public santa::Timer<DeadlineTimer> {
 public:
  explicit DeadlineTimer(SNTTimedRuleKills* owner)
      // No clamping: the interval is a distance to the next deadline, not a
      // configured period. The label only appears in the clamp warning, which
      // this range makes unreachable.
      : santa::Timer<DeadlineTimer>(0, std::numeric_limits<uint32_t>::max(),
                                    santa::Timer<DeadlineTimer>::OnStart::kWaitOneCycle,
                                    "TimedRuleKills",
                                    santa::Timer<DeadlineTimer>::RescheduleMode::kTrailingEdge),
        owner_(owner) {}

  bool OnTimer() {
    [owner_ onDeadlineTimer];
    // Never self-rescheduled: the component re-arms from its own queue once it
    // knows the next deadline, which the interval this fired on does not.
    return false;
  }

 private:
  __weak SNTTimedRuleKills* owner_;
};

}  // namespace

@implementation SNTTimedRuleKills {
  std::shared_ptr<DeadlineTimer> _timer;
}

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                         configurator:(SNTConfigurator*)configurator
                                clock:(SNTBelievableClock*)clock {
  self = [super init];
  if (self) {
    _notifierQueue = notifierQueue;
    _ruleTable = ruleTable;
    _configurator = configurator;
    _clock = clock;
    _entries = [NSMutableDictionary dictionary];
    _queue = dispatch_queue_create("com.northpolesec.santa.daemon.timed_rule_kills",
                                   DISPATCH_QUEUE_SERIAL);
    _timer = std::make_shared<DeadlineTimer>(self);

    // The clock's refresh runs on the uptime clock, which no change to the wall
    // clock can delay, so hanging the due question off it is what bounds how
    // late a moved clock can be noticed. Weakly captured: this object owns the
    // clock, and a strong reference from a block the clock holds would be a
    // cycle neither of them could break.
    __weak SNTTimedRuleKills* weakSelf = self;
    clock.refreshHandler = ^{
      [weakSelf onClockRefresh];
    };
  }
  return self;
}

+ (NSString*)celHashForExpression:(NSString*)celExpr {
  if (!celExpr.length) {
    return nil;
  }

  NSData* text = [celExpr dataUsingEncoding:NSUTF8StringEncoding];
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(text.bytes, (CC_LONG)text.length, digest);

  NSMutableString* hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
  for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
    [hex appendFormat:@"%02x", digest[i]];
  }
  return hex;
}

- (void)resumeFromSavedState {
  dispatch_async(self.queue, ^{
    NSArray<NSDictionary*>* saved = [self.configurator savedTimedRuleKills];
    // Counted apart: a record that would not deserialize says the state file is
    // damaged, while a duplicate key that lost the earlier-deadline contest is a
    // well-formed record that simply has a better twin. Both are dropped, and
    // only the first is a reason to look at the file.
    NSUInteger unusable = 0;
    NSUInteger superseded = 0;

    for (NSDictionary* dict in saved) {
      SNTTimedRuleKillEntry* entry = [SNTTimedRuleKillEntry entryFromDictionary:dict];
      if (!entry) {
        unusable++;
        continue;
      }

      // Earlier deadline wins here as it does at record time, so a duplicated
      // key on disk can never extend a pending kill. Counted on both sides of
      // the contest: the loser is dropped whether it is the record just read or
      // the one already held.
      SNTTimedRuleKillEntry* existing = self.entries[entry.key];
      if (existing && [existing.deadline compare:entry.deadline] != NSOrderedDescending) {
        superseded++;
        continue;
      }
      if (existing) {
        superseded++;
      }
      self.entries[entry.key] = entry;
    }

    NSUInteger dropped = unusable + superseded;
    if (self.entries.count || dropped) {
      LOGI(@"Restored %lu pending timed rule kill(s)%@", (unsigned long)self.entries.count,
           dropped ? [NSString stringWithFormat:@", dropping %lu unusable and %lu superseded "
                                                @"record(s)",
                                                (unsigned long)unusable, (unsigned long)superseded]
                   : @"");
    }
    if (dropped) {
      [self persistSerialized];
    }

    // Anything already due runs now; the rest arms the timer.
    [self processDueEntriesSerialized];
  });
}

- (void)recordKillForRuleType:(SNTRuleType)ruleType
                   identifier:(NSString*)identifier
                      celHash:(NSString*)celHash
                     deadline:(NSDate*)deadline
                     notifyAt:(NSDate*)notifyAt
                   windowDays:(NSArray<NSNumber*>*)windowDays
                  windowStart:(NSString*)windowStart
                    windowEnd:(NSString*)windowEnd
                   windowZone:(NSString*)windowZone {
  if (!identifier.length || !celHash.length || !deadline || !notifyAt) {
    // Any of the four can be the missing one, and a missing identifier is the
    // commonest case, so name them all rather than logging the one field that
    // may itself be absent.
    LOGW(@"Ignoring incomplete timed rule kill (identifier: %@, celHash: %@, deadline: %@, "
         @"notifyAt: %@)",
         identifier, celHash, deadline, notifyAt);
    return;
  }

  if (!SupportedRuleType(ruleType)) {
    LOGW(@"Ignoring timed rule kill for unsupported rule type %ld (%@); only SIGNINGID, TEAMID "
         @"and CDHASH rules can be matched against a running process",
         (long)ruleType, identifier);
    return;
  }

  dispatch_async(self.queue, ^{
    SNTTimedRuleKillEntry* entry = [[SNTTimedRuleKillEntry alloc] init];
    entry.ruleType = ruleType;
    entry.identifier = identifier;
    entry.celHash = celHash;
    entry.deadline = deadline;
    entry.notifyAt = notifyAt;
    // A window shape is only usable whole, so a partial one is no shape. The
    // zone is part of the whole: "09:00" names no instant without it.
    if (windowDays.count && windowStart.length && windowEnd.length && windowZone.length) {
      entry.windowDays = windowDays;
      entry.windowStart = windowStart;
      entry.windowEnd = windowEnd;
      entry.windowZone = windowZone;
    }

    SNTTimedRuleKillEntry* existing = self.entries[entry.key];
    if (existing) {
      if ([existing.deadline compare:deadline] != NSOrderedDescending) {
        // The pending deadline is the earlier one; it governs everything the
        // rule covers, including this execution. Nothing changed, so nothing is
        // written: this is the common case of a binary executing repeatedly
        // inside its window.
        return;
      }
      LOGD(@"Timed rule kill for %@ moved earlier: %@ -> %@", identifier, existing.deadline,
           deadline);
    }

    // Read here rather than above, so the common case of a binary executing
    // repeatedly inside its window reads no clocks at all.
    [self captureMachDeadlineForEntry:entry from:[self.clock now]];

    self.entries[entry.key] = entry;
    LOGI(@"Recorded timed rule kill for %@: quitting at %@, warning at %@", identifier, deadline,
         notifyAt);

    [self persistSerialized];
    [self rescheduleTimerSerialized];
  });
}

- (void)onDeadlineTimer {
  // Runs on the Timer's queue. The work moves to our own queue: the kill blocks
  // it for the term-then-kill grace period, and the entries are only touched
  // there.
  dispatch_async(self.queue, ^{
    [self processDueEntriesSerialized];
  });
}

- (void)onClockRefresh {
  // Runs on the clock's tick, with the clock's lock released. The same question
  // the countdown timer asks, on a cadence a moved wall clock cannot delay: an
  // entry whose mach deadline has arrived is quit here, and the countdown, which
  // runs on the wall clock, is re-armed from the believable one on the way
  // through. Enqueued rather than run here, both because the entries are only
  // touched on our own queue and because a kill would otherwise hold the clock's
  // tick for the grace period.
  dispatch_async(self.queue, ^{
    [self processDueEntriesSerialized];
  });
}

#pragma mark Private methods, all on self.queue

/// Runs everything that has come due, then arms the timer for the next event.
///
/// Kills go first and warnings second, both measured against the one `now` this
/// pass started with. That ordering is the guarantee that a warning never
/// delays a kill: the process snapshot behind a warning is the slow part, and
/// no kill is waiting on it by the time it is taken. It also means an entry
/// whose deadline has arrived is gone before the warning pass sees it, so
/// nothing is warned about a kill that is already happening. A clock that jumped
/// forward over both moments therefore quits what the rule covers without
/// warning first, which is the only honest answer left once the deadline is
/// behind us.
///
/// Every due entry is gathered before any of them is killed, so the quits share
/// one grace period rather than taking one each: deadlines that land together
/// are one pass over the machine's processes, not one apiece.
- (void)processDueEntriesSerialized {
  NSDate* now = [self.clock now];
  uint64_t machNow = mach_continuous_time();
  NSString* bootSession = [SNTSystemInfo bootSessionUUID];
  BOOL changed = NO;

  NSMutableArray<SNTTimedRuleKillEntry*>* due = [NSMutableArray array];
  for (NSString* key in self.entries.allKeys) {
    SNTTimedRuleKillEntry* entry = self.entries[key];
    if (![self entryIsDue:entry now:now machNow:machNow bootSession:bootSession]) {
      continue;
    }
    // Whichever way this entry goes from here it does not stay as it was.
    changed = YES;

    // The rule first: one that no longer governs has no kill coming, and there
    // is no window left to reschedule into either.
    if (![self ruleStillGovernsSerialized:entry]) {
      [self.entries removeObjectForKey:key];
      continue;
    }

    // Then the window, before any process is looked at: a deadline reached
    // inside an occurrence that is standing again moves rather than fires.
    if ([self rescheduleForOpenWindowSerialized:entry now:now]) {
      continue;
    }

    [self.entries removeObjectForKey:key];
    [due addObject:entry];
  }

  if (due.count) {
    [self killEntriesSerialized:due];
  }

  for (NSString* key in self.entries.allKeys) {
    SNTTimedRuleKillEntry* entry = self.entries[key];
    if (entry.notified || [entry.notifyAt timeIntervalSinceDate:now] > kDueTolerance) {
      continue;
    }

    // The same re-check the deadline makes, a lead window earlier. A rule that
    // no longer governs has no kill coming, so there is nothing to warn about
    // and no reason to hold the entry until its deadline.
    if (![self ruleStillGovernsSerialized:entry]) {
      [self.entries removeObjectForKey:key];
      changed = YES;
      continue;
    }

    [self notifyForEntrySerialized:entry];
    // Marked whether or not a window went up. This is the one warning pass for
    // this (rule, deadline): the user is warned once, or not at all when there
    // was nothing to warn about, and persisting the flag is what carries that
    // across a restart. It is also what keeps the timer from re-arming on a
    // notify time that has already passed.
    entry.notified = YES;
    changed = YES;
  }

  if (changed) {
    [self persistSerialized];
  }
  [self rescheduleTimerSerialized];
}

/// Whether the rule an entry came from still exists with the text its deadline
/// was computed from. A rule that is gone, or whose text changed, cancels the
/// pending kill: the next allowed exec under the new text records a fresh entry.
///
/// Checked at the warning as well as at the deadline, so a rule withdrawn during
/// the lead window neither warns about a quit that will not happen nor leaves a
/// dead entry sitting until its deadline.
- (BOOL)ruleStillGovernsSerialized:(SNTTimedRuleKillEntry*)entry {
  SNTRule* rule = [self.ruleTable executionRuleForIdentifiers:IdentifiersForEntry(entry)];
  if (!rule) {
    LOGI(@"Timed rule kill for %@ cancelled: the rule is gone", entry.identifier);
    return NO;
  }
  if (![[SNTTimedRuleKills celHashForExpression:rule.celExpr] isEqualToString:entry.celHash]) {
    LOGI(@"Timed rule kill for %@ cancelled: the rule's expression changed", entry.identifier);
    return NO;
  }
  return YES;
}

/// Whether an entry has come due. Two clocks answer that: the wall instant it
/// was recorded for, read from the believable clock, and the mach continuous
/// instant captured alongside it. Whichever arrives first fires the kill, so a
/// system clock moved backwards cannot hold a deadline open, and a daemon that
/// restarts inside the same boot session picks up an instant nothing could have
/// moved rather than one the wall clock could.
///
/// A pair from an earlier boot session says nothing at all: its tick count
/// belongs to a counter that restarted, so the wall instant is left to govern
/// alone. Everything the rule covered died with that reboot anyway.
- (BOOL)entryIsDue:(SNTTimedRuleKillEntry*)entry
               now:(NSDate*)now
           machNow:(uint64_t)machNow
       bootSession:(NSString*)bootSession {
  if ([entry.deadline timeIntervalSinceDate:now] <= kDueTolerance) {
    return YES;
  }
  if (!entry.machDeadline || !bootSession.length ||
      ![entry.bootSessionUUID isEqualToString:bootSession]) {
    return NO;
  }
  return entry.machDeadline <=
         AddNanosecondsToMachTime((uint64_t)(kDueTolerance * NSEC_PER_SEC), machNow);
}

/// Pairs an entry's wall deadline with the mach continuous instant it falls on
/// and the boot session that instant belongs to. Called wherever a deadline is
/// set, since the pair only ever describes the deadline it was taken with.
///
/// A machine whose boot session cannot be read, or a deadline further out than a
/// tick count can carry, stores no pair, which leaves the wall instant governing
/// alone.
- (void)captureMachDeadlineForEntry:(SNTTimedRuleKillEntry*)entry from:(NSDate*)now {
  NSString* bootSession = [SNTSystemInfo bootSessionUUID];
  NSTimeInterval remaining = [entry.deadline timeIntervalSinceDate:now];
  // Asked as a negated "within range" so that a NaN, which compares false
  // against everything, reads as out of range rather than into the arithmetic.
  if (!bootSession.length || !(remaining <= kMaxMachDeadlineLead)) {
    entry.machDeadline = 0;
    entry.bootSessionUUID = nil;
    return;
  }

  entry.machDeadline = AddNanosecondsToMachTime((uint64_t)(std::max(0.0, remaining) * NSEC_PER_SEC),
                                                mach_continuous_time());
  entry.bootSessionUUID = bootSession;
}

/// The window re-check, asked of every entry on every pass through the kill
/// path. An entry whose recurring window is standing open right now is not
/// killed: its deadline moves to the end of the occurrence in progress, keeping
/// the lead its warning was recorded with, and the warning is owed again because
/// this is a different deadline.
///
/// Asked on every pass rather than only at daemon start, because a machine that
/// slept through a deadline wakes inside a later occurrence just as a daemon that
/// was down comes back inside one. At a deadline that arrives on time the instant
/// is the end of the occurrence, and a window holds from its start up to but not
/// including its end, so that case reads as closed and the kill goes ahead.
///
/// Answers NO for an entry with no window, a window that is closed, a window
/// whose zone no longer resolves, a window the math refuses, and an open window
/// whose end is not later than the deadline being replaced: all five mean the
/// deadline stands. The caller persists and re-arms the timer either way.
- (BOOL)rescheduleForOpenWindowSerialized:(SNTTimedRuleKillEntry*)entry now:(NSDate*)now {
  if (!entry.windowDays.count || !entry.windowStart.length || !entry.windowEnd.length ||
      !entry.windowZone.length) {
    return NO;
  }

  // The zone the rule named, resolved again here rather than carried resolved: a
  // stored "local" is whatever this host is set to now, which is what a local
  // rule means. A zone that no longer resolves leaves the deadline standing, the
  // same answer a missing shape gives.
  absl::StatusOr<absl::TimeZone> zone = santa::cel::ResolveTimeZone(entry.windowZone.UTF8String);
  if (!zone.ok()) {
    LOGW(@"Unable to resolve the window zone '%@' for %@; quitting what the rule covers",
         entry.windowZone, entry.identifier);
    return NO;
  }

  std::vector<int64_t> days;
  days.reserve(entry.windowDays.count);
  for (NSNumber* day in entry.windowDays) {
    days.push_back(day.longLongValue);
  }

  // The same math the rule was evaluated with, at the believable time and in the
  // zone the rule named, so a re-check and the evaluation that recorded the entry
  // cannot disagree about where the window is.
  absl::StatusOr<santa::cel::WindowEval> window = santa::cel::EvalDaysHHMMWindow(
      days, entry.windowStart.UTF8String, entry.windowEnd.UTF8String,
      absl::UnixEpoch() + absl::Seconds(now.timeIntervalSince1970), *zone);
  if (!window.ok()) {
    LOGW(@"Unable to re-check the window for %@ (%s); quitting what the rule covers",
         entry.identifier, std::string(window.status().message()).c_str());
    return NO;
  }
  if (!window->in_range) {
    return NO;
  }

  NSDate* deadline = [NSDate
      dateWithTimeIntervalSince1970:absl::ToDoubleSeconds(window->window_end - absl::UnixEpoch())];

  // Only an occurrence ending later than the deadline being replaced is a
  // reschedule. The two can name the same instant: the due tolerance treats an
  // entry as due in the fraction of a second before its deadline, and a window
  // still holds there, so this is the on-time fire arriving a hair early. Moving
  // the deadline to where it already is would reset the warning and put up a
  // second window for a kill that is happening now.
  if ([deadline timeIntervalSinceDate:entry.deadline] <= 0) {
    return NO;
  }

  NSTimeInterval lead = [entry.deadline timeIntervalSinceDate:entry.notifyAt];

  LOGI(@"Timed rule kill for %@ deferred: its window is open again until %@, nothing quit",
       entry.identifier, deadline);

  entry.deadline = deadline;
  entry.notifyAt = [deadline dateByAddingTimeInterval:-lead];
  entry.notified = NO;
  [self captureMachDeadlineForEntry:entry from:now];
  return YES;
}

/// The kill at a deadline: one pass for every entry that has come due, sharing
/// the grace period between the SIGTERMs and the SIGKILLs. The rule and the
/// window have already been re-checked for each of them.
- (void)killEntriesSerialized:(NSArray<SNTTimedRuleKillEntry*>*)entries {
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  NSMutableArray<SNTTimedRuleKillEntry*>* requested = [NSMutableArray array];
  for (SNTTimedRuleKillEntry* entry in entries) {
    SNTKillRequest* request = KillRequestForEntry(entry);
    if (!request) {
      LOGW(@"Unable to build a kill request for %@; nothing killed", entry.identifier);
      continue;
    }
    [requests addObject:request];
    [requested addObject:entry];
  }

  if (!requests.count) {
    return;
  }

  NSArray<SNTKillResponse*>* responses =
      self.killBlock ? self.killBlock(requests, kTermGrace)
                     : santa::KillingMachineTermThenKill(requests, kTermGrace);

  // One response per request, in order.
  for (NSUInteger index = 0; index < requested.count && index < responses.count; index++) {
    // killedProcesses holds one result per delivery across both passes, so a
    // process that survived SIGTERM appears twice. It is a count of deliveries,
    // not of processes. "Of its own" is the honest qualifier: when two entries in
    // one pass cover the same process group, the group is signaled once and that
    // delivery is reported against whichever of them signaled it, so the other
    // can report none while its processes were quit all the same.
    LOGI(@"Timed rule kill fired for %@: %lu signal delivery result(s) of its own, error: %ld",
         requested[index].identifier, (unsigned long)responses[index].killedProcesses.count,
         (long)responses[index].error);
  }
}

/// The warning shortly before a deadline: find something the rule covers that
/// is running, name it, and hand the warning window to the GUI. Signals
/// nothing. The caller has already confirmed the rule still governs.
- (void)notifyForEntrySerialized:(SNTTimedRuleKillEntry*)entry {
  // Asked first because it is the cheap question: with no GUI to warn, there is
  // no reason to walk every process on the machine looking for a name for it.
  id<SNTNotifierXPC> proxy = self.notifierQueue.notifierConnection.remoteObjectProxy;
  if (!proxy) {
    LOGD(@"No GUI connection; skipping timed rule kill banner for %@", entry.identifier);
    return;
  }

  SNTKillRequest* request = KillRequestForEntry(entry);
  if (!request) {
    LOGW(@"Unable to build a kill request for %@; nothing to warn about", entry.identifier);
    return;
  }

  std::optional<pid_t> pid;
  if (self.matchBlock) {
    NSNumber* matched = self.matchBlock(request);
    if (matched) {
      pid = matched.intValue;
    }
  } else {
    pid = santa::KillingMachineAnyMatch(request);
  }

  if (!pid) {
    // Nothing the rule covers is running, so there is nothing to warn about.
    LOGD(@"No running process matches %@; skipping timed rule kill banner", entry.identifier);
    return;
  }

  // The rule's own identifier is the fallback for a process that matched but
  // can't be named, which is mostly what one that exited in between looks like.
  NSString* app = DisplayNameForPid(*pid);
  if (!app.length) {
    app = entry.identifier;
  }

  LOGI(@"Sending timed rule kill banner for %@ (%@), quitting at %@", app, entry.identifier,
       entry.deadline);
  [proxy postTimedRuleKillNotificationForApplication:app deadline:entry.deadline];
}

/// Writes the current entry set, or clears the key when there are none. Callers
/// only reach here when the set actually changed.
- (void)persistSerialized {
  NSMutableArray<NSDictionary*>* serialized = [NSMutableArray array];
  for (SNTTimedRuleKillEntry* entry in self.entries.allValues) {
    [serialized addObject:entry.dictionaryRepresentation];
  }

  if (![self.configurator persistTimedRuleKills:(serialized.count ? serialized : nil)]) {
    // The in-memory set still governs this daemon's lifetime; only a restart
    // before the next successful write loses the pending kills.
    LOGE(@"Unable to persist %lu pending timed rule kill(s)", (unsigned long)serialized.count);
  }
}

/// Arms the one-shot timer for the earliest event across all entries, which is
/// the earliest of every deadline and every warning still owed, or stops it
/// when there are none. The distance to that event is measured on the believable
/// clock; the countdown itself is Timer.h's, which runs on wall time, so a
/// machine asleep at the deadline runs the kill on wake.
///
/// Every pass re-arms it, including the ones the clock's refresh brings, and that
/// is what corrects a countdown started before the wall clock moved: the distance
/// is re-measured on a clock that only ever rises, so a rolled-back countdown is
/// shortened back to the truth and can never be lengthened.
- (void)rescheduleTimerSerialized {
  NSDate* next = nil;
  for (SNTTimedRuleKillEntry* entry in self.entries.allValues) {
    if (!next || [entry.deadline compare:next] == NSOrderedAscending) {
      next = entry.deadline;
    }
    if (!entry.notified && [entry.notifyAt compare:next] == NSOrderedAscending) {
      next = entry.notifyAt;
    }
  }

  if (!next) {
    self.armedTimerSeconds = 0;
    _timer->StopTimerAsync();
    return;
  }

  // Round up: firing a whole second early would find nothing due and re-arm.
  NSTimeInterval remaining = [next timeIntervalSinceDate:[self.clock now]];
  uint32_t seconds = 0;
  if (remaining > 0) {
    seconds = static_cast<uint32_t>(
        std::min(std::ceil(remaining), static_cast<double>(std::numeric_limits<uint32_t>::max())));
  }
  self.armedTimerSeconds = seconds;
  _timer->StartTimerWithIntervalAsync(seconds);
}

@end
