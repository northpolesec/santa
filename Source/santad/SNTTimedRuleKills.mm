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
#include <signal.h>
#include <sys/param.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <optional>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTXPCNotifierInterface.h"
#include "Source/common/String.h"
#include "Source/common/Timer.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/KillingMachine.h"
#import "Source/santad/SNTNotificationQueue.h"

// Fields of a persisted entry.
static NSString* const kEntryRuleTypeKey = @"RuleType";
static NSString* const kEntryIdentifierKey = @"Identifier";
static NSString* const kEntryCELHashKey = @"CELHash";
static NSString* const kEntryDeadlineKey = @"Deadline";
static NSString* const kEntryNotifyAtKey = @"NotifyAt";
static NSString* const kEntryNotifiedKey = @"Notified";

// A timer can fire marginally early; anything due within this window is treated
// as due now rather than re-arming for a fraction of a second.
static const NSTimeInterval kDueTolerance = 0.25;

// How long a matched process has to exit after SIGTERM before it is SIGKILLed.
static const NSTimeInterval kTermGrace = 5.0;

/// One pending kill: the rule it came from, when it fires, and whether the user
/// has already been warned.
@interface SNTTimedRuleKillEntry : NSObject
@property SNTRuleType ruleType;
@property(copy) NSString* identifier;
@property(copy) NSString* celHash;
@property NSDate* deadline;
@property NSDate* notifyAt;
@property BOOL notified;

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

// The kill is delivered to the process group of every match, with SIGKILL as
// the nominal signal; the term-then-kill path sends SIGTERM and SIGKILL itself
// and ignores this field. Never nil for an entry that exists: every write site
// gates on SupportedRuleType, so only the switch needs the default arm.
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
  if (!SupportedRuleType(ruleType) || !identifier.length || !celHash.length) {
    return nil;
  }

  SNTTimedRuleKillEntry* entry = [[SNTTimedRuleKillEntry alloc] init];
  entry.ruleType = ruleType;
  entry.identifier = identifier;
  entry.celHash = celHash;
  entry.deadline = [NSDate dateWithTimeIntervalSince1970:[dict[kEntryDeadlineKey] doubleValue]];
  entry.notifyAt = [NSDate dateWithTimeIntervalSince1970:[dict[kEntryNotifyAtKey] doubleValue]];
  // Guarded like every other field: a non-NSNumber value on disk must not reach
  // -boolValue and crash-loop the daemon at startup.
  id notified = dict[kEntryNotifiedKey];
  entry.notified = [notified isKindOfClass:[NSNumber class]] && [notified boolValue];
  return entry;
}

- (NSDictionary*)dictionaryRepresentation {
  return @{
    kEntryRuleTypeKey : @(self.ruleType),
    kEntryIdentifierKey : self.identifier,
    kEntryCELHashKey : self.celHash,
    kEntryDeadlineKey : @(self.deadline.timeIntervalSince1970),
    kEntryNotifyAtKey : @(self.notifyAt.timeIntervalSince1970),
    kEntryNotifiedKey : @(self.notified),
  };
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
@property dispatch_queue_t queue;
/// Entries keyed by rule type, identifier and CEL hash, so repeated execs under
/// the same rule share one entry. Only ever touched on `queue`.
@property NSMutableDictionary<NSString*, SNTTimedRuleKillEntry*>* entries;

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
  /// The syscalls every kill and every match here go through.
  santa::KillEnv _killEnv;
}

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                         configurator:(SNTConfigurator*)configurator
                              killEnv:(santa::KillEnv)killEnv {
  self = [super init];
  if (self) {
    _killEnv = std::move(killEnv);
    _notifierQueue = notifierQueue;
    _ruleTable = ruleTable;
    _configurator = configurator;
    _entries = [NSMutableDictionary dictionary];
    _queue = dispatch_queue_create("com.northpolesec.santa.daemon.timed_rule_kills",
                                   DISPATCH_QUEUE_SERIAL);
    _timer = std::make_shared<DeadlineTimer>(self);
  }
  return self;
}

+ (NSString*)celHashForExpression:(NSString*)celExpr {
  if (!celExpr.length) {
    return nil;
  }

  NSData* text = [celExpr dataUsingEncoding:NSUTF8StringEncoding];
  uint8_t digest[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(text.bytes, (CC_LONG)text.length, digest);
  return santa::StringToNSString(santa::BufToHexString(digest, sizeof(digest)));
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

- (void)recordKillForRuleType:(SNTRuleType)ruleType
                   identifier:(NSString*)identifier
                      celHash:(NSString*)celHash
                     deadline:(NSDate*)deadline
                     notifyAt:(NSDate*)notifyAt {
  if (!identifier.length || !celHash.length || !deadline || !notifyAt) {
    LOGW(@"Ignoring incomplete timed rule kill for %@", identifier);
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

#pragma mark Private methods, all on self.queue

/// Runs everything that has come due, then arms the timer for the next event.
///
/// Kills go first and warnings second, both measured against the one `now` this
/// pass started with. That ordering is the guarantee that a warning never
/// delays a kill: the process snapshot behind a warning is the slow part, and
/// no kill is waiting on it by the time it is taken. It also means an entry
/// whose deadline has arrived is gone before the warning pass sees it, so
/// nothing is warned about a kill that is already happening.
///
/// Due entries are gathered and killed in one pass, sharing one grace period.
- (void)processDueEntriesSerialized {
  NSDate* now = [NSDate date];
  BOOL changed = NO;

  NSMutableArray<SNTTimedRuleKillEntry*>* due = [NSMutableArray array];
  for (NSString* key in self.entries.allKeys) {
    SNTTimedRuleKillEntry* entry = self.entries[key];
    if ([entry.deadline timeIntervalSinceDate:now] > kDueTolerance) {
      continue;
    }

    // A deadline is spent once, whether or not anything is killed.
    [self.entries removeObjectForKey:key];
    changed = YES;

    // A rule that no longer governs has no kill coming.
    if (![self ruleStillGovernsSerialized:entry]) {
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

    // The same re-check the deadline makes, a lead window earlier. A rule that
    // no longer governs has no kill coming, so there is nothing to warn about
    // and no reason to hold the entry until its deadline.
    if (![self ruleStillGovernsSerialized:entry]) {
      [self.entries removeObjectForKey:key];
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

/// The kill at a deadline: one pass over every due entry, sharing the grace
/// period. Rules have already been re-checked.
- (void)killEntriesSerialized:(NSArray<SNTTimedRuleKillEntry*>*)entries {
  NSMutableArray<SNTKillRequest*>* requests = [NSMutableArray arrayWithCapacity:entries.count];
  for (SNTTimedRuleKillEntry* entry in entries) {
    [requests addObject:KillRequestForEntry(entry)];
  }

  NSArray<SNTKillResponse*>* responses =
      santa::KillingMachineTermThenKill(requests, kTermGrace, _killEnv);

  // One response per request, in order, so `entries` indexes them.
  // killedProcesses counts one record per matched process per pass, not one per
  // delivery: the members of a group shared with another entry report under
  // every entry that matched them, and a survivor of SIGTERM appears once per
  // pass.
  for (NSUInteger index = 0; index < responses.count; index++) {
    LOGI(@"Timed rule kill fired for %@: %lu matched process result(s), error: %ld",
         entries[index].identifier, (unsigned long)responses[index].killedProcesses.count,
         (long)responses[index].error);
  }
}

/// The warning shortly before a deadline: find something the rule covers that
/// is running, name it, and hand the banner to the GUI. Signals nothing. The
/// caller has already confirmed the rule still governs.
- (void)notifyForEntrySerialized:(SNTTimedRuleKillEntry*)entry {
  // Asked first because it is the cheap question: with no GUI to warn, there is
  // no reason to walk every process on the machine looking for a name for it.
  id<SNTNotifierXPC> proxy = self.notifierQueue.notifierConnection.remoteObjectProxy;
  if (!proxy) {
    LOGD(@"No GUI connection; skipping timed rule kill banner for %@", entry.identifier);
    return;
  }

  std::optional<pid_t> pid = santa::KillingMachineAnyMatch(KillRequestForEntry(entry), _killEnv);
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
/// when there are none. Timer.h schedules on wall time, so a machine asleep at
/// the deadline runs the kill on wake.
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
    _timer->StopTimerAsync();
    return;
  }

  // Round up: firing a whole second early would find nothing due and re-arm.
  NSTimeInterval remaining = next.timeIntervalSinceNow;
  uint32_t seconds = 0;
  if (remaining > 0) {
    seconds = static_cast<uint32_t>(
        std::min(std::ceil(remaining), static_cast<double>(std::numeric_limits<uint32_t>::max())));
  }
  _timer->StartTimerWithIntervalAsync(seconds);
}

@end
