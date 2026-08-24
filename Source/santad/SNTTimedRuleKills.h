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

@class SNTConfigurator;
@class SNTNotificationQueue;
@class SNTRuleTable;

///
///  Owns the kills asked for by CEL rules using policy_for_range(...,
///  should_kill=true): one entry per rule, a timer for the next event across
///  them, the warning banner shortly before a deadline, and the kill itself at
///  the deadline.
///
///  Nothing running is touched except at a recorded deadline. A rule arriving,
///  a window opening, or a window closing never kills anything by itself.
///
///  Entries are persisted, so a deadline is an appointment that survives a
///  daemon restart: `resumeFromSavedState` runs the ones that came due while
///  the daemon was down and re-arms the timer for the rest.
///
@interface SNTTimedRuleKills : NSObject

- (instancetype)initWithNotifierQueue:(SNTNotificationQueue*)notifierQueue
                            ruleTable:(SNTRuleTable*)ruleTable
                         configurator:(SNTConfigurator*)configurator NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

///
///  Loads the persisted entries: past-due ones run the kill path immediately
///  (rule re-check first), future ones arm the timer.
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
- (void)recordKillForRuleType:(SNTRuleType)ruleType
                   identifier:(NSString*)identifier
                      celHash:(NSString*)celHash
                     deadline:(NSDate*)deadline
                     notifyAt:(NSDate*)notifyAt;

///
///  SHA-256 (lowercase hex) of a rule's CEL text, or nil when there is none.
///  Exposed so the caller that records an entry and the fire-time re-check
///  derive CELHash the same way.
///
+ (NSString*)celHashForExpression:(NSString*)celExpr;

@end

#endif  // SANTA_SANTAD_SNTTIMEDRULEKILLS_H
