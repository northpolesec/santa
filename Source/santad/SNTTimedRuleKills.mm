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

#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>
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

#include "Source/common/AccountLookup.h"
#include "Source/common/AuditUtilities.h"
#include "Source/common/CSOpsHelper.h"
#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTRuleTimeWindow.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTTimedRuleKillDetails.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#import "Source/common/SigningIDHelpers.h"
#include "Source/common/String.h"
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
static NSString* const kEntryRuleIDKey = @"RuleID";
static NSString* const kEntryDeadlineKey = @"Deadline";
static NSString* const kEntryNotifyAtKey = @"NotifyAt";
static NSString* const kEntryNotifiedKey = @"Notified";
static NSString* const kEntryWindowDaysKey = @"WindowDays";
static NSString* const kEntryWindowStartKey = @"WindowStart";
static NSString* const kEntryWindowEndKey = @"WindowEnd";
static NSString* const kEntryWindowZoneKey = @"WindowZone";
static NSString* const kEntryMachDeadlineKey = @"MachDeadline";
static NSString* const kEntryBootSessionUUIDKey = @"BootSessionUUID";
static NSString* const kEntryProcessesKey = @"Processes";
static NSString* const kProcessPidKey = @"Pid";
static NSString* const kProcessPidversionKey = @"Pidversion";

// A timer can fire marginally early; anything due within this window is treated
// as due now rather than re-arming for a fraction of a second.
static const NSTimeInterval kDueTolerance = 0.25;

// How long a recorded process has to exit after SIGTERM before it is SIGKILLed.
static const NSTimeInterval kTermGrace = 5.0;

// How far ahead a mach deadline may point: the pair is arithmetic on a tick
// count, and one further out than this carries no pair at all.
static const NSTimeInterval kMaxMachDeadlineLead = 10 * 365 * 24 * 60 * 60;

/// One pending kill: the rule it came from, when it fires, whether the user has
/// already been warned, the shape of the window the deadline came from (nil for
/// a window that does not recur), and the executions recorded under it.
@interface SNTTimedRuleKillEntry : NSObject
@property SNTRuleType ruleType;
@property(copy) NSString* identifier;
@property int64_t ruleId;
@property NSDate* deadline;
@property NSDate* notifyAt;
@property BOOL notified;
@property(copy) NSArray<NSNumber*>* windowDays;
@property(copy) NSString* windowStart;
@property(copy) NSString* windowEnd;
@property(copy) NSString* windowZone;
/// The boot the mach deadline and the process list belong to: always the current
/// one on an entry in memory, set at load and at record. On disk it says which
/// boot those two fields were read in. `machDeadline` is zero when there is none,
/// which leaves the wall deadline above to govern on its own.
@property(copy) NSString* bootSessionUUID;
@property uint64_t machDeadline;
/// The (pid, pidversion) pairs of every execution recorded under the rule, each
/// `@{Pid, Pidversion}`. Never nil on an entry that exists.
@property NSMutableArray<NSDictionary*>* processes;

/// Deserializes a persisted entry, or nil when it isn't one: the state file is
/// on disk, so every field is validated rather than trusted.
+ (instancetype)entryFromDictionary:(NSDictionary*)dict;

@property(readonly) NSDictionary* dictionaryRepresentation;

/// Opaque map key: rule type, identifier and rule id. Never parsed back.
@property(readonly) NSString* key;
@end

namespace {

// Every execution rule type. The kill is by recorded process, so no type needs a
// matcher; this rejects a non-execution type read off state or a decision.
bool SupportedRuleType(SNTRuleType ruleType) {
  return ruleType == SNTRuleTypeCDHash || ruleType == SNTRuleTypeBinary ||
         ruleType == SNTRuleTypeSigningID || ruleType == SNTRuleTypeCertificate ||
         ruleType == SNTRuleTypeTeamID;
}

// The persisted window shape, checked rather than trusted because the state file
// is on disk: days 0 (Sunday) through 6 (Saturday), 24-hour "HH:MM" times, and a
// non-empty zone string, the deterministic parts of what policy_for_range()
// accepts. Anything else reads as no shape at all, so the entry keeps its
// deadline but has no window for a restart to re-check.
NSArray<NSNumber*>* WindowDaysFromValue(id value) {
  if (![value isKindOfClass:[NSArray class]]) {
    return nil;
  }
  for (NSNumber* day in value) {
    if (![day isKindOfClass:[NSNumber class]] || (double)day.integerValue != day.doubleValue ||
        day.integerValue < 0 || day.integerValue > 6) {
      return nil;
    }
  }
  return value;
}

NSString* WindowTimeFromValue(id value) {
  NSString* time = [value isKindOfClass:[NSString class]] ? value : nil;
  if (!time.length) {
    return nil;
  }
  return santa::cel::ParseHourMinute(time.UTF8String) ? time : nil;
}

// Any non-empty string, deliberately not resolved here. Whether the zone
// resolves is asked at the re-check instead, because the answer can change
// between loads: a zone the host's loader refuses today, or refuses just once,
// would otherwise drop the shape at load and the next write would put that drop
// on disk for good. An unresolvable zone at the re-check leaves the deadline
// standing, which is a kill; the shape survives to be asked again.
NSString* WindowZoneFromValue(id value) {
  NSString* zone = [value isKindOfClass:[NSString class]] ? value : nil;
  return zone.length ? zone : nil;
}

// The mach half of a deadline, checked rather than trusted like everything else
// the state file holds: a tick count is a positive whole number, and a plist
// real round-trips both infinities and NaN, neither of which converts to one.
// Anything else reads as no mach deadline, and the wall deadline governs alone.
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

// A positive whole number read off the state file, at most `max`, or nullopt.
// Gated through the double like the mach deadline above, so a plist real that
// round-tripped an infinity, a NaN, a fraction or a value past the type never
// reaches the integer conversion, whose result for those is platform-defined.
std::optional<int64_t> PositiveIntegerFromValue(id value, int64_t max) {
  if (![value isKindOfClass:[NSNumber class]]) {
    return std::nullopt;
  }
  double asDouble = [value doubleValue];
  if (!std::isfinite(asDouble) || asDouble <= 0 || asDouble != std::floor(asDouble) ||
      asDouble > static_cast<double>(max)) {
    return std::nullopt;
  }
  // (double)INT64_MAX rounds up to 2^63, so an id at the top of its type passes
  // the bound above and is checked exactly here.
  int64_t asInt = [value longLongValue];
  return (asInt > 0 && asInt <= max) ? std::optional<int64_t>(asInt) : std::nullopt;
}

// The recorded processes, checked rather than trusted like everything else the
// state file holds. A bad element is dropped and the rest of the list loads.
// Always a mutable array, so the entry can append without a nil check.
NSMutableArray<NSDictionary*>* ProcessesFromValue(id value) {
  NSMutableArray<NSDictionary*>* out = [NSMutableArray array];
  if (![value isKindOfClass:[NSArray class]]) {
    return out;
  }
  for (id element in value) {
    if (![element isKindOfClass:[NSDictionary class]]) {
      continue;
    }
    std::optional<int64_t> pid =
        PositiveIntegerFromValue(element[kProcessPidKey], std::numeric_limits<int>::max());
    std::optional<int64_t> pidversion =
        PositiveIntegerFromValue(element[kProcessPidversionKey], std::numeric_limits<int>::max());
    if (!pid || !pidversion) {
      continue;
    }
    [out addObject:@{
      kProcessPidKey : @(static_cast<int>(*pid)),
      kProcessPidversionKey : @(static_cast<int>(*pidversion))
    }];
  }
  return out;
}

// The opaque map key: rule type, identifier and rule id. One builder, so the
// entry's own key and a lookup made before the entry exists cannot disagree.
NSString* EntryKey(SNTRuleType ruleType, NSString* identifier, int64_t ruleId) {
  return [NSString stringWithFormat:@"%ld|%@|%lld", (long)ruleType, identifier, (long long)ruleId];
}

// Identifiers that fetch exactly the rule an entry came from: one field set, so
// the rule table's type precedence never picks a different rule type.
struct RuleIdentifiers IdentifiersForEntry(SNTTimedRuleKillEntry* entry) {
  switch (entry.ruleType) {
    case SNTRuleTypeCDHash: return {.cdhash = entry.identifier};
    case SNTRuleTypeBinary: return {.binarySHA256 = entry.identifier};
    case SNTRuleTypeSigningID: return {.signingID = entry.identifier};
    case SNTRuleTypeCertificate: return {.certificateSHA256 = entry.identifier};
    case SNTRuleTypeTeamID: return {.teamID = entry.identifier};
    default: return {};
  }
}

// What to call a process in the warning banner: the file name of its
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

// Fills the warning details from the recorded process. Identity comes from the
// kernel through csops, and Publisher alone from a signature check that must
// pass, as in the block dialog; that check validates only the identity
// components of the running code and takes milliseconds, unlike a static check
// with default flags. Every process read is re-checked against the audit token,
// so a pid gone or recycled mid-collection yields nil rather than describing a
// stranger, and the caller can try another pair.
static SNTTimedRuleKillDetails* DetailsForEntry(SNTTimedRuleKillEntry* entry,
                                                const audit_token_t& token,
                                                const santa::KillEnv& env) {
  SNTTimedRuleKillDetails* details = [[SNTTimedRuleKillDetails alloc] init];
  details.deadline = entry.deadline;
  details.ruleType = entry.ruleType;
  details.application = entry.identifier;

  if (entry.windowDays && entry.windowStart && entry.windowEnd && entry.windowZone) {
    SNTRuleTimeWindow* window = [[SNTRuleTimeWindow alloc] init];
    window.days = entry.windowDays;
    window.startOfDay = entry.windowStart;
    window.endOfDay = entry.windowEnd;
    window.zoneName = entry.windowZone;
    details.timeWindow = window;
  }

  pid_t pid = santa::Pid(token);

  NSString* path;
  char pathBuf[PROC_PIDPATHINFO_MAXSIZE] = {};
  if (proc_pidpath(pid, pathBuf, sizeof(pathBuf)) > 0) {
    path = @(pathBuf);
  }
  NSString* application = path.lastPathComponent;
  if (!application.length) application = DisplayNameForPid(pid);

  NSString* user;
  NSNumber* ppid;
  NSString* parentName;
  struct proc_bsdinfo bsdInfo;
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdInfo, sizeof(bsdInfo)) == sizeof(bsdInfo)) {
    if (auto name = santa::account::UsernameForUID(bsdInfo.pbi_uid)) {
      user = @(name->c_str());
    }
    ppid = @(bsdInfo.pbi_ppid);
    parentName = DisplayNameForPid((pid_t)bsdInfo.pbi_ppid);
  }

  std::optional<std::string> signingID = santa::CSOpsGetSigningID(pid, env.csops_func);
  std::optional<std::string> teamID = santa::CSOpsGetTeamID(pid, env.csops_func);
  std::optional<uint32_t> flags = santa::CSOpsStatusFlags(pid, env.csops_func);
  std::optional<std::string> cdhash = santa::CSOpsGetCDHash(pid, env.csops_func);

  NSString* publisher;
  MOLCodesignChecker* csc = [[MOLCodesignChecker alloc] initWithPID:pid];
  if (csc) {
    publisher = Publisher(csc.certificates, csc.teamID);
  }

  audit_token_t after;
  if (!env.token_for_pid(pid, &after) || santa::Pidversion(after) != santa::Pidversion(token)) {
    LOGD(@"Pid %d is gone or was recycled while collecting timed rule kill details for %@", pid,
         entry.identifier);
    return nil;
  }

  if (application.length) details.application = application;
  details.path = path;
  details.user = user;
  details.ppid = ppid;
  details.parentName = parentName;
  details.signingID = FormatSigningID(santa::OptionalStringToNSString(signingID),
                                      santa::OptionalStringToNSString(teamID),
                                      flags.has_value() && (*flags & CS_PLATFORM_BINARY) != 0);
  details.cdhash = santa::OptionalStringToNSString(cdhash);
  details.publisher = publisher;
  return details;
}

}  // namespace

@implementation SNTTimedRuleKillEntry

+ (instancetype)entryFromDictionary:(NSDictionary*)dict {
  if (![dict isKindOfClass:[NSDictionary class]] ||
      ![dict[kEntryRuleTypeKey] isKindOfClass:[NSNumber class]] ||
      ![dict[kEntryIdentifierKey] isKindOfClass:[NSString class]] ||
      ![dict[kEntryDeadlineKey] isKindOfClass:[NSNumber class]] ||
      ![dict[kEntryNotifyAtKey] isKindOfClass:[NSNumber class]]) {
    return nil;
  }

  SNTRuleType ruleType = static_cast<SNTRuleType>([dict[kEntryRuleTypeKey] integerValue]);
  NSString* identifier = dict[kEntryIdentifierKey];
  std::optional<int64_t> ruleId =
      PositiveIntegerFromValue(dict[kEntryRuleIDKey], std::numeric_limits<int64_t>::max());
  // A plist real round-trips both infinities and NaN, and neither is an instant.
  // A NaN deadline is the worst of them: it answers false to every "has this
  // come due" question and leaves the countdown arming for zero seconds, firing
  // and re-arming for zero forever. An appointment that cannot be compared is no
  // appointment, so the record is dropped.
  NSTimeInterval deadline = [dict[kEntryDeadlineKey] doubleValue];
  NSTimeInterval notifyAt = [dict[kEntryNotifyAtKey] doubleValue];
  if (!SupportedRuleType(ruleType) || !identifier.length || !ruleId || !std::isfinite(deadline) ||
      !std::isfinite(notifyAt)) {
    return nil;
  }

  SNTTimedRuleKillEntry* entry = [[SNTTimedRuleKillEntry alloc] init];
  entry.ruleType = ruleType;
  entry.identifier = identifier;
  entry.ruleId = *ruleId;
  entry.deadline = [NSDate dateWithTimeIntervalSince1970:deadline];
  entry.notifyAt = [NSDate dateWithTimeIntervalSince1970:notifyAt];
  // Guarded like every other field: a non-NSNumber value on disk must not reach
  // -boolValue and crash-loop the daemon at startup.
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
  // The stored stamp says which boot the mach deadline and the process list
  // belong to. Pidversions and mach ticks both restart at reboot, so under
  // another boot's stamp both are meaningless: dropped, and the wall schedule
  // governs alone. The entry itself is stamped with this boot, which anything
  // recorded on it is.
  NSString* currentBoot = [SNTSystemInfo bootSessionUUID];
  NSString* storedBoot = [dict[kEntryBootSessionUUIDKey] isKindOfClass:[NSString class]]
                             ? dict[kEntryBootSessionUUIDKey]
                             : nil;
  entry.processes = [NSMutableArray array];
  if (currentBoot.length) {
    entry.bootSessionUUID = currentBoot;
    if ([storedBoot isEqualToString:currentBoot]) {
      entry.machDeadline = MachDeadlineFromValue(dict[kEntryMachDeadlineKey]);
      entry.processes = ProcessesFromValue(dict[kEntryProcessesKey]);
    }
  }
  return entry;
}

- (NSDictionary*)dictionaryRepresentation {
  NSMutableDictionary* dict = [@{
    kEntryRuleTypeKey : @(self.ruleType),
    kEntryIdentifierKey : self.identifier,
    kEntryRuleIDKey : @(self.ruleId),
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
  if (self.bootSessionUUID.length) {
    dict[kEntryBootSessionUUIDKey] = self.bootSessionUUID;
  }
  if (self.machDeadline) {
    dict[kEntryMachDeadlineKey] = @(self.machDeadline);
  }
  if (self.processes.count) {
    dict[kEntryProcessesKey] = [self.processes copy];
  }
  return dict;
}

- (NSString*)key {
  return EntryKey(self.ruleType, self.identifier, self.ruleId);
}

@end

@interface SNTTimedRuleKills ()
@property SNTNotificationQueue* notifierQueue;
@property SNTRuleTable* ruleTable;
@property SNTConfigurator* configurator;
@property SNTBelievableClock* clock;
@property dispatch_queue_t queue;
/// Entries keyed by rule type, identifier and rule id, so repeated execs under
/// the same rule share one entry. Only ever touched on `queue`.
@property NSMutableDictionary<NSString*, SNTTimedRuleKillEntry*>* entries;
/// The interval the countdown was last armed for, in seconds, or zero when it
/// was stopped. Written on every pass over the entries, so a test can see a
/// countdown that was armed before the system clock moved being corrected.
@property uint32_t armedTimerSeconds;

- (void)onDeadlineTimer;
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
  /// The syscalls every kill and every process lookup here go through.
  santa::KillEnv _killEnv;
}

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                         configurator:(SNTConfigurator*)configurator
                                clock:(SNTBelievableClock*)clock
                              killEnv:(santa::KillEnv)killEnv {
  self = [super init];
  if (self) {
    _killEnv = std::move(killEnv);
    _notifierQueue = notifierQueue;
    _ruleTable = ruleTable;
    _configurator = configurator;
    _clock = clock;
    _entries = [NSMutableDictionary dictionary];
    _queue = dispatch_queue_create("com.northpolesec.santa.daemon.timed_rule_kills",
                                   DISPATCH_QUEUE_SERIAL);
    _timer = std::make_shared<DeadlineTimer>(self);

    // The clock's tick asks the same due question the countdown does, on a
    // cadence a moved wall clock cannot delay. Weak: this object owns the clock.
    __weak SNTTimedRuleKills* weakSelf = self;
    clock.refreshHandler = ^{
      [weakSelf onDeadlineTimer];
    };
  }
  return self;
}

- (void)resumeFromSavedState {
  dispatch_async(self.queue, ^{
    NSArray<NSDictionary*>* saved = [self.configurator savedTimedRuleKills];
    NSUInteger dropped = 0;

    for (NSDictionary* dict in saved) {
      SNTTimedRuleKillEntry* entry = [SNTTimedRuleKillEntry entryFromDictionary:dict];
      if (!entry) {
        dropped++;
        continue;
      }

      // Earlier deadline wins here as it does at record time, so a duplicated
      // key on disk can never extend a pending kill.
      SNTTimedRuleKillEntry* existing = self.entries[entry.key];
      if (existing && [existing.deadline compare:entry.deadline] != NSOrderedDescending) {
        dropped++;
        continue;
      }
      self.entries[entry.key] = entry;
    }

    if (self.entries.count || dropped) {
      LOGI(@"Restored %lu pending timed rule kill(s)%@", (unsigned long)self.entries.count,
           dropped ? [NSString stringWithFormat:@", dropping %lu unusable record(s)",
                                                (unsigned long)dropped]
                   : @"");
    }
    if (dropped) {
      [self persistSerialized];
    }

    // Anything already due runs now; the rest arms the timer.
    [self processDueEntriesSerialized];
  });
}

- (void)recordKillForDecision:(SNTCachedDecision*)cd process:(audit_token_t)token {
  NSDate* deadline = cd.timedRuleKillDeadline;
  if (!deadline) {
    return;
  }

  // Read here, on the caller's thread; the block below captures values only.
  SNTRuleType ruleType = cd.timedRuleKillRuleType;
  NSString* identifier = cd.timedRuleKillIdentifier;
  int64_t ruleId = cd.ruleId;
  NSDate* notifyAt = cd.timedRuleKillNotifyAt;
  NSArray<NSNumber*>* windowDays = cd.timedRuleKillWindowDays;
  NSString* windowStart = cd.timedRuleKillWindowStart;
  NSString* windowEnd = cd.timedRuleKillWindowEnd;
  NSString* windowZone = cd.timedRuleKillWindowZone;

  if (!identifier.length || !notifyAt) {
    LOGW(@"Ignoring incomplete timed rule kill for %@", identifier);
    return;
  }
  if (ruleId <= 0) {
    LOGW(@"Ignoring timed rule kill for %@: no server-assigned rule id (%lld); the feature "
         @"requires CELv2 rules from a v2 sync server",
         identifier, (long long)ruleId);
    return;
  }
  if (!SupportedRuleType(ruleType)) {
    LOGW(@"Ignoring timed rule kill for unsupported rule type %ld (%@)", (long)ruleType,
         identifier);
    return;
  }
  NSString* bootSession = [SNTSystemInfo bootSessionUUID];
  if (!bootSession.length) {
    LOGW(@"Ignoring timed rule kill for %@: the boot session UUID is unreadable, so nothing "
         @"recorded here could ever be quit",
         identifier);
    return;
  }

  pid_t pid = santa::Pid(token);
  int pidversion = santa::Pidversion(token);

  dispatch_async(self.queue, ^{
    NSString* key = EntryKey(ruleType, identifier, ruleId);
    SNTTimedRuleKillEntry* entry = self.entries[key];
    BOOL created = !entry;
    if (created) {
      entry = [[SNTTimedRuleKillEntry alloc] init];
      entry.ruleType = ruleType;
      entry.identifier = identifier;
      entry.ruleId = ruleId;
      entry.processes = [NSMutableArray array];
      self.entries[key] = entry;
    }

    // A new entry takes the captured schedule. An existing one takes it only
    // when the captured deadline is earlier, since the earlier deadline governs
    // everything the rule covers. The process list is untouched either way.
    BOOL scheduleReplaced = created || [deadline compare:entry.deadline] == NSOrderedAscending;
    if (scheduleReplaced) {
      if (!created) {
        LOGD(@"Timed rule kill for %@ moved earlier: %@ -> %@", identifier, entry.deadline,
             deadline);
      }
      entry.deadline = deadline;
      entry.notifyAt = notifyAt;
      entry.notified = NO;
      // A window shape is only usable whole, so a partial one is no shape.
      BOOL whole = windowDays.count && windowStart.length && windowEnd.length && windowZone.length;
      entry.windowDays = whole ? windowDays : nil;
      entry.windowStart = whole ? windowStart : nil;
      entry.windowEnd = whole ? windowEnd : nil;
      entry.windowZone = whole ? windowZone : nil;
    }

    // Every entry carries this boot's stamp. The mach half is anchored once:
    // captured when the entry has none (created, or loaded without a usable one)
    // or when the deadline just moved, and otherwise left alone so a later clock
    // move cannot push it out.
    entry.bootSessionUUID = bootSession;
    if (!entry.machDeadline || scheduleReplaced) {
      [self captureMachDeadlineForEntry:entry from:[self.clock now]];
    }

    [entry.processes addObject:@{kProcessPidKey : @(pid), kProcessPidversionKey : @(pidversion)}];
    [self pruneDeadProcessesFromEntry:entry];

    if (created) {
      LOGI(@"Recorded timed rule kill for %@: quitting at %@, warning at %@", identifier, deadline,
           notifyAt);
    } else {
      LOGD(@"Recorded execution under timed rule kill for %@ (pid %d, pidversion %d)", identifier,
           pid, pidversion);
    }

    [self persistSerialized];
    // An append does not change the next warning or deadline. Re-arming the
    // relative timer here would add queue traffic and reset its firing instant.
    if (scheduleReplaced) {
      [self rescheduleTimerSerialized];
    }
  });
}

- (void)onDeadlineTimer {
  // Called from the countdown's queue and from the clock's tick. The work is
  // enqueued rather than run here: the entries are only touched on our own
  // queue, and a kill would hold the caller for the grace period.
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
/// forward over both moments therefore quits the rule's recorded executions
/// without warning first, which is the only honest answer left once the deadline
/// is behind us.
///
/// Due entries are gathered and killed in one pass, sharing one grace period.
/// An entry whose window is standing open again is not one of them: it goes back
/// with a later deadline instead.
- (void)processDueEntriesSerialized {
  [self processDueEntriesSerializedAsOf:[self.clock now]];
}

/// The pass itself, split from the clock read above so a test can run one at an
/// instant of its choosing, including the fraction of a second before a deadline
/// that a marginally early timer fires in.
- (void)processDueEntriesSerializedAsOf:(NSDate*)now {
  uint64_t machNow = mach_continuous_time();
  NSString* bootSession = [SNTSystemInfo bootSessionUUID];
  BOOL changed = NO;

  NSMutableArray<SNTTimedRuleKillEntry*>* due = [NSMutableArray array];
  for (NSString* key in self.entries.allKeys) {
    SNTTimedRuleKillEntry* entry = self.entries[key];
    if (![self entryIsDue:entry now:now machNow:machNow bootSession:bootSession]) {
      continue;
    }

    // A deadline is spent once, whether or not anything is killed, and whichever
    // way this entry goes from here it does not stay as it was.
    [self.entries removeObjectForKey:key];
    changed = YES;

    // The rule first: one that no longer governs has no kill coming, and there
    // is no window left to reschedule into either.
    if (![self ruleStillGovernsSerialized:entry]) {
      continue;
    }

    // Then the window, before any process is looked at: a deadline reached
    // inside an occurrence that is standing again is an appointment moved rather
    // than a kill, so the entry goes back under its new deadline.
    if ([self rescheduleForOpenWindowSerialized:entry now:now]) {
      self.entries[key] = entry;
      continue;
    }

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

    // The same two re-checks the deadline makes, a lead window earlier. A rule
    // that no longer governs has no kill coming, so there is nothing to warn
    // about and no reason to hold the entry until its deadline.
    if (![self ruleStillGovernsSerialized:entry]) {
      [self.entries removeObjectForKey:key];
      changed = YES;
      continue;
    }

    // Then the window, asked at the deadline just as the kill path asks it: an
    // occurrence standing there moves the deadline rather than quitting
    // anything, so a banner would promise a quit that will not happen.
    if ([self rescheduleForOpenWindowSerialized:entry now:now]) {
      changed = YES;
      continue;
    }

    [self notifyForEntrySerialized:entry];
    // Marked whether or not a banner went out. This is the one warning pass for
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

/// Whether the rule an entry came from still exists under the id its deadline
/// was recorded for. A rule that is gone, or whose id changed, cancels the
/// pending kill: the next allowed exec under the new rule records a fresh entry.
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
  if (rule.ruleId != entry.ruleId) {
    LOGI(@"Timed rule kill for %@ cancelled: the rule changed (rule id %lld -> %lld)",
         entry.identifier, (long long)entry.ruleId, (long long)rule.ruleId);
    return NO;
  }
  return YES;
}

/// Whether an entry has come due. Two clocks answer that, the believable wall
/// instant and the mach continuous instant captured alongside it, and whichever
/// arrives first fires. A pair from an earlier boot session is ignored.
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

/// Pairs an entry's wall deadline with the mach continuous instant it falls on.
/// A host whose boot session cannot be read, or a deadline further out than a
/// tick count carries, stores no mach deadline and the wall deadline governs
/// alone. The boot the instant belongs to is the entry's stamp.
- (void)captureMachDeadlineForEntry:(SNTTimedRuleKillEntry*)entry from:(NSDate*)now {
  NSTimeInterval remaining = [entry.deadline timeIntervalSinceDate:now];
  // Asked as a negated "within range" so that a NaN, which compares false
  // against everything, reads as out of range rather than into the arithmetic.
  if (![SNTSystemInfo bootSessionUUID].length || !(remaining <= kMaxMachDeadlineLead)) {
    entry.machDeadline = 0;
    return;
  }

  entry.machDeadline = AddNanosecondsToMachTime((uint64_t)(std::max(0.0, remaining) * NSEC_PER_SEC),
                                                mach_continuous_time());
}

/// Drops every recorded pair whose token lookup fails or whose pidversion no
/// longer matches. Called only at record, for the entry recorded into, since
/// only that entry grows; the warning and the kill skip a dead pair themselves.
- (void)pruneDeadProcessesFromEntry:(SNTTimedRuleKillEntry*)entry {
  NSMutableArray<NSDictionary*>* live = [NSMutableArray arrayWithCapacity:entry.processes.count];
  for (NSDictionary* proc in entry.processes) {
    audit_token_t token;
    if (_killEnv.token_for_pid([proc[kProcessPidKey] intValue], &token) &&
        santa::Pidversion(token) == [proc[kProcessPidversionKey] intValue]) {
      [live addObject:proc];
    }
  }
  entry.processes = live;
}

/// The window re-check, asked of every entry on every pass: at its deadline, and
/// again at the warning that leads it. An entry whose recurring window is
/// standing open at its deadline is not killed: its deadline moves to the end of
/// the occurrence standing there, with a fresh warning lead, and the warning is
/// owed again because this is a different deadline.
///
/// Asked on every pass rather than only at daemon start, because a machine that
/// slept through a deadline wakes inside a later occurrence just as a daemon that
/// was down comes back inside one.
///
/// Asked at the deadline, not at `now`, whenever the deadline is still ahead: a
/// timer can fire marginally early, and the occurrence that ends at the deadline
/// is still standing in those last fractions of a second. Asking at the deadline
/// itself reads what holds once it arrives, so a window that closes there is
/// closed and kills, and one that runs on (a back-to-back occurrence, or a
/// 24-hour window) moves the appointment instead. The warning pass reads the same
/// instant for the same reason: its `now` is a lead short of a deadline that has
/// not arrived.
///
/// Answers NO for an entry with no window, a window that is closed, and a window
/// the math refuses, including a zone that no longer resolves: all three mean the
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
    LOGW(@"Unable to resolve the window zone '%@' for %@; quitting the rule's recorded executions",
         entry.windowZone, entry.identifier);
    return NO;
  }

  std::vector<int64_t> days;
  days.reserve(entry.windowDays.count);
  for (NSNumber* day in entry.windowDays) {
    days.push_back(day.longLongValue);
  }

  // The same math the rule was evaluated with, in the zone the rule named, so a
  // re-check and the evaluation that recorded the entry cannot disagree about
  // where the window is. Asked at the deadline rather than at the believable
  // `now` when the timer got here first.
  NSDate* asked = [now laterDate:entry.deadline];
  absl::StatusOr<santa::cel::WindowEval> window = santa::cel::EvalDaysHHMMWindow(
      days, entry.windowStart.UTF8String, entry.windowEnd.UTF8String,
      absl::UnixEpoch() + absl::Seconds(asked.timeIntervalSince1970), *zone);
  if (!window.ok()) {
    LOGW(@"Unable to re-check the window for %@ (%s); quitting the rule's recorded executions",
         entry.identifier, std::string(window.status().message()).c_str());
    return NO;
  }
  if (!window->in_range) {
    return NO;
  }

  // Always later than the deadline being replaced: the window was asked at an
  // instant at or after it and holds up to but not including its own end.
  NSDate* deadline = [NSDate
      dateWithTimeIntervalSince1970:absl::ToDoubleSeconds(window->window_end - absl::UnixEpoch())];

  // The lead the new occurrence's own length earns, not the one the old deadline
  // carried: an exec recorded within a lead of its window's close has a notify
  // time clamped to the exec, and re-deriving from that would carry the clamp
  // into every later occurrence.
  NSTimeInterval lead = absl::ToDoubleSeconds(santa::cel::NotificationLead(window->window_length));

  LOGI(@"Timed rule kill for %@ deferred: its window is open again until %@, nothing quit",
       entry.identifier, deadline);

  entry.deadline = deadline;
  // Against the real `now`: a warning already owed by the time the new deadline
  // is set goes out on this pass rather than being dated in the past.
  entry.notifyAt = [now laterDate:[deadline dateByAddingTimeInterval:-lead]];
  entry.notified = NO;
  [self captureMachDeadlineForEntry:entry from:now];
  return YES;
}

/// The kill at a deadline: one running-process request per recorded pair of every
/// due entry, all sent in one pass so they share the grace period. The rule and
/// the window have already been re-checked; a dead pair fails its lookup inside
/// the KillingMachine, so the entries are not pruned first. One summary per
/// entry at info, one line per request at debug carrying the uuid every
/// KillingMachine outcome logs.
- (void)killEntriesSerialized:(NSArray<SNTTimedRuleKillEntry*>*)entries {
  NSString* bootSession = [SNTSystemInfo bootSessionUUID];
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray array];
  for (SNTTimedRuleKillEntry* entry in entries) {
    LOGI(@"Timed rule kill firing for %@: %lu recorded process(es)", entry.identifier,
         (unsigned long)entry.processes.count);
    for (NSDictionary* proc in entry.processes) {
      NSString* uuid = [[NSUUID UUID] UUIDString];
      SNTKillRequestRunningProcess* request =
          [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                         pid:[proc[kProcessPidKey] intValue]
                                                  pidversion:[proc[kProcessPidversionKey] intValue]
                                             bootSessionUUID:bootSession
                                                      signal:SIGKILL
                                         targetProcessGroups:YES];
      if (!request) {
        // Only when the boot session reads empty at fire time; the pair itself
        // passed validation. Rare enough to be worth a line when it happens.
        LOGW(@"Timed rule kill for %@ could not build request %@ for pid %@, pidversion %@",
             entry.identifier, uuid, proc[kProcessPidKey], proc[kProcessPidversionKey]);
        continue;
      }
      LOGD(@"Timed rule kill target for %@: pid %@, pidversion %@ (request %@)", entry.identifier,
           proc[kProcessPidKey], proc[kProcessPidversionKey], uuid);
      [requests addObject:request];
    }
  }

  // An empty list is a call that does nothing.
  santa::KillingMachineTermThenKill(requests, kTermGrace, _killEnv);
}

/// The warning shortly before a deadline: name the first recorded process still
/// running and hand the banner to the GUI. Signals nothing and changes nothing on
/// the entry. A pair whose lookup fails is skipped, and one whose process exits
/// while its details are read yields nil and the next is tried. The caller has
/// already confirmed the rule still governs.
- (void)notifyForEntrySerialized:(SNTTimedRuleKillEntry*)entry {
  // Asked first because it is the cheap question: with no GUI to warn, there is
  // no reason to read any process.
  id<SNTNotifierXPC> proxy = self.notifierQueue.notifierConnection.remoteObjectProxy;
  if (!proxy) {
    LOGD(@"No GUI connection; skipping timed rule kill banner for %@", entry.identifier);
    return;
  }

  for (NSDictionary* proc in entry.processes) {
    audit_token_t token;
    if (!_killEnv.token_for_pid([proc[kProcessPidKey] intValue], &token) ||
        santa::Pidversion(token) != [proc[kProcessPidversionKey] intValue]) {
      continue;
    }
    SNTTimedRuleKillDetails* details = DetailsForEntry(entry, token, _killEnv);
    if (!details) {
      continue;
    }
    LOGI(@"Sending timed rule kill banner for %@ (%@), quitting at %@", details.application,
         entry.identifier, entry.deadline);
    [proxy postTimedRuleKillNotification:details];
    return;
  }

  LOGD(@"No running recorded process for %@; skipping timed rule kill banner", entry.identifier);
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
/// clock; the countdown itself is Timer.h's, which schedules on wall time, so a
/// machine asleep at the deadline runs the kill on wake.
///
/// Every pass re-arms it, so a countdown started before the wall clock moved is
/// re-measured on a clock that only rises: shortened back, never lengthened.
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
