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

#ifndef SANTA_SANTAD_SNTTIMEDRULEKILLS_H
#define SANTA_SANTAD_SNTTIMEDRULEKILLS_H

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"

@class SNTBelievableClock;
@class SNTConfigurator;
@class SNTNotificationQueue;
@class SNTRuleTable;

///
///  Owns the kills asked for by CEL rules using policy_for_range(...,
///  should_kill=true): one entry per rule, a timer for the next event across
///  them, the warning window shortly before a deadline, and the kill itself at
///  the deadline.
///
///  Nothing running is touched except at a recorded deadline. A rule arriving,
///  a window opening, or a window closing never kills anything by itself.
///
///  Entries are persisted, so a deadline is an appointment that survives a
///  daemon restart: `resumeFromSavedState` runs the ones that came due while
///  the daemon was down and re-arms the timer for the rest.
///
///  Every "has this come due" question is asked of `clock`, the minimum
///  believable time, rather than of the system clock, so moving the system clock
///  backwards cannot push a deadline out. Each entry also carries the deadline
///  as a mach continuous instant, paired with the boot session that instant
///  belongs to, and whichever of the two clocks arrives first fires the kill.
///  Across a reboot the mach value belongs to a counter that has restarted, so
///  there the wall instant governs alone; everything the rule covered died with
///  the reboot anyway.
///
///  The whole due question is re-asked on `clock`'s refresh, which runs on the
///  uptime clock and so cannot be delayed by any change to the wall clock. That
///  is what bounds the damage a rolled-back clock can do: it delays a quit by at
///  most one refresh interval, whatever the size of the rollback, and the
///  countdown timer, which runs on the wall clock, is re-armed from the
///  believable one on the way through.
///
///  A deadline reached while the entry's recurring window is standing open with a
///  later end than the deadline itself is not a kill but an appointment moved:
///  the entry goes to the end of the occurrence in progress, keeping the lead its
///  warning was recorded with. That is what a machine which slept through a
///  deadline, or a daemon that was down across one, wakes up to. A window whose
///  end is the deadline is the deadline arriving on time, and it kills.
///
@interface SNTTimedRuleKills : NSObject

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                         configurator:(SNTConfigurator*)configurator
                                clock:(SNTBelievableClock*)clock NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

///
///  Loads the persisted entries: past-due ones run the kill path immediately
///  (the rule re-checked first, then the window), future ones arm the timer.
///
///  Split out of the initializer because it starts the timer and can run kills,
///  neither of which may happen before construction is complete. This is the
///  same split TimedSyncSession makes with SetupFromState.
///
- (void)resumeFromSavedState;

///
///  Records a kill for the rule identified by (ruleType, identifier, celHash).
///  Repeated execs inside the same window recompute the same deadline and
///  change nothing, including writing nothing; when the deadlines differ the
///  earlier one wins, so everything the rule covers is quit at the first
///  pending deadline.
///
///  `celHash` is the rule's CEL text hashed with +celHashForExpression:. It is
///  part of the key and it is re-checked when the timer fires, so editing the
///  rule cancels the pending kill rather than quitting things under text that
///  no longer exists.
///
///  `identifier` must be byte-for-byte what the rule table stores for the rule:
///  the re-check looks the rule up with `identifier = ?`, which SQLite compares
///  case-sensitively. A caller that normalizes case or whitespace on the way in
///  will find nothing at fire time, and every kill for that rule is silently
///  cancelled instead of running.
///
///  At `notifyAt` the user is warned that whatever the rule covers will be
///  quit, once per (rule, deadline) and only when something the rule covers is
///  actually running. A warning is never allowed to hold up a kill: one owed at
///  a moment the deadline has already arrived is dropped, not delivered late.
///
///  Only the rule types that can be matched against a running process are
///  supported: SIGNINGID (including `platform:`), TEAMID and CDHASH. BINARY and
///  CERTIFICATE rules are refused with a log line; their window still gates new
///  executions.
///
///  `windowDays` (0=Sunday through 6=Saturday), `windowStart` and `windowEnd`
///  ("HH:MM") and `windowZone` (the zone string the rule wrote: "local", an IANA
///  name or a [+-]HH:MM offset) describe the recurring window the deadline came
///  from, and are persisted with the entry so every later pass over it can
///  re-check the window. Only the days plus HH:MM form of policy_for_range() has
///  a window that recurs; for the timestamp and duration forms these are nil and
///  the entry stores no shape. A shape is stored only when all four are given,
///  and an entry with no shape is one whose deadline can only ever be met by a
///  kill.
///
- (void)recordKillForRuleType:(SNTRuleType)ruleType
                   identifier:(NSString*)identifier
                      celHash:(NSString*)celHash
                     deadline:(NSDate*)deadline
                     notifyAt:(NSDate*)notifyAt
                   windowDays:(NSArray<NSNumber*>*)windowDays
                  windowStart:(NSString*)windowStart
                    windowEnd:(NSString*)windowEnd
                   windowZone:(NSString*)windowZone;

///
///  SHA-256 (lowercase hex) of a rule's CEL text, or nil when there is none.
///  Exposed so the caller that records an entry and the fire-time re-check
///  derive CELHash the same way.
///
+ (NSString*)celHashForExpression:(NSString*)celExpr;

@end

#endif  // SANTA_SANTAD_SNTTIMEDRULEKILLS_H
