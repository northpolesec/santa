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
#include "Source/santad/KillingMachine.h"

@class SNTBelievableClock;
@class SNTCachedDecision;
@class SNTConfigurator;
@class SNTNotificationQueue;
@class SNTRuleTable;

///
///  Owns the kills asked for by CEL rules using policy_for_range(...,
///  kill_on_expiry(policy)): one entry per rule, a timer for the next event
///  across them, the warning banner shortly before a deadline, and the kill
///  itself at the deadline.
///
///  Nothing running is touched except at a recorded deadline. A rule arriving,
///  a window opening, or a window closing never kills anything by itself.
///
///  Entries are persisted, so a deadline is an appointment that survives a
///  daemon restart: `resumeFromSavedState` runs the ones that came due while
///  the daemon was down and re-arms the timer for the rest.
///
///  Every "has this come due" question is asked of `clock`, the minimum
///  believable time, and re-asked on its refresh, so a rolled-back system clock
///  delays a quit by at most one refresh interval whatever the size of the
///  rollback.
///
///  A deadline reached while the entry's recurring window is standing open is not
///  a kill but an appointment moved: the entry goes to the end of the occurrence
///  standing at the deadline, with a fresh warning lead. That is what a machine
///  which slept through a deadline wakes up to. A window that closes at the
///  deadline kills; only a back-to-back or 24-hour occurrence runs past it and
///  defers.
///
@interface SNTTimedRuleKills : NSObject

///
///  `killEnv` is the syscall environment kills and process lookups run against:
///  santa::KillEnv() in production, faked in tests.
///
- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                         configurator:(SNTConfigurator*)configurator
                                clock:(SNTBelievableClock*)clock
                              killEnv:(santa::KillEnv)killEnv NS_DESIGNATED_INITIALIZER;

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
///  Records the kill a decision carries, if any, for the process an allowed exec
///  produced. `token` is the exec target's audit token. Called wherever Santa's
///  answer lets the process run: the allow response, and the TouchID reply once
///  the user has authenticated in time. A decision with no deadline records
///  nothing, which is every exec not under a windowed rule.
///
///  The rule-side fields come off `cd`: `timedRuleKillRuleType`,
///  `timedRuleKillIdentifier`, `ruleId`, the deadline, the warning time and the
///  window shape. `timedRuleKillIdentifier` must be byte-for-byte what the rule
///  table stores: the fire-time re-check looks the rule up by it, which SQLite
///  compares case-sensitively.
///
///  `ruleId` is the rule's server-assigned id, which the sync server changes for
///  every edit to the rule. It is part of the key and it is re-checked when the
///  timer fires, so editing the rule cancels the pending kill rather than quitting
///  things under a rule that no longer exists.
///
///  Every exec is a new (pid, pidversion) pair on the rule's entry, so every
///  record writes. When the deadlines differ the earlier one wins for the whole
///  entry. Recording is refused, with a log line, when `ruleId` is at or below
///  zero (static rules, `santactl rule --cel`, v1-protocol sync rules) and when
///  the boot session UUID is unreadable, since nothing recorded without one could
///  ever be quit.
///
///  At `timedRuleKillNotifyAt` the user is warned that the recorded executions
///  will be quit, once per (rule, deadline) and only when one of them is still
///  running. A warning is never allowed to hold up a kill: one owed at a moment
///  the deadline has already arrived is dropped, not delivered late.
///
///  Every execution rule type is supported (CDHASH, BINARY, SIGNINGID including
///  `platform:`, CERTIFICATE and TEAMID), since the kill is by recorded execution
///  rather than by identity; a type that is not one of those is refused with a
///  log line.
///
///  The window shape (`timedRuleKillWindowDays`, 0=Sunday through 6=Saturday;
///  `timedRuleKillWindowStart` and `timedRuleKillWindowEnd`, "HH:MM"; and
///  `timedRuleKillWindowZone`, the zone string the rule wrote: "local", an IANA
///  name or a [+-]HH:MM offset) describes the recurring window the deadline came
///  from, and is persisted with the entry so every later pass over it can
///  re-check the window. Only the days plus HH:MM form of policy_for_range() has
///  a window that recurs; for the timestamp and duration forms these are nil and
///  the entry stores no shape. A shape is stored only when all four are given,
///  and an entry with no shape is one whose deadline can only ever be met by a
///  kill.
///
- (void)recordKillForDecision:(SNTCachedDecision*)cd process:(audit_token_t)token;

@end

#endif  // SANTA_SANTAD_SNTTIMEDRULEKILLS_H
