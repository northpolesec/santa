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

#include "Source/santad/AdminUserState.h"

#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"

namespace santa {

// Keys for one entry in the persisted DemotedAdmins record.
static NSString* const kDemotedAdminUsername = @"Username";
static NSString* const kDemotedAdminUID = @"UID";
static NSString* const kDemotedAdminLocal = @"Local";

// Returns the uid TAM currently owns — an active session's target or a
// deadline-0 demote-retry residue left by a failed teardown — or nil if no
// TAM session state is persisted.
static NSNumber* TAMOwnedUID(SNTConfigurator* configurator) {
  NSDictionary* session = [configurator savedTimedSessionStateForKey:kStateTempAdminModeKey];
  NSNumber* uid = session[kStateTempAdminTargetUIDKey];
  return [uid isKindOfClass:[NSNumber class]] ? uid : nil;
}

AdminUserState::AdminUserState(SNTConfigurator* configurator,
                               std::unique_ptr<AdminGroupMembership> membership,
                               void (^revoke_tam)(void), NSNumber* (^active_tam_uid)(void))
    : configurator_(configurator),
      membership_(std::move(membership)),
      revoke_tam_([revoke_tam copy]),
      active_tam_uid_([active_tam_uid copy]) {}

void AdminUserState::HandlePolicy(SNTTemporaryAdminPolicy* policy) {
  absl::MutexLock lock(lock_);
  if (policy.type == SNTTemporaryAdminPolicyTypeOnDemand && policy.enforcesAdminGroup) {
    // The server names the accounts allowed to hold standing admin, so Santa
    // reconciles the group on every sync rather than snapshotting it once.
    SweepLocked(policy.allowedAdminUsernames);
    return;
  }
  bool have_record = [configurator_ savedDemotedAdmins] != nil;
  // Legacy path, for a server that does not send the allowed-admins wrapper.
  // A record that survives a revoke (kept to retry a failed restore) also
  // suppresses capture for the whole next enabled window: restored users keep
  // admin, and new admins are never demoted, until the record drains and a
  // later off-to-on edge captures fresh. Deliberate: the record cannot hold
  // two capture generations, and re-capturing while one exists would turn the
  // one-shot demotion into continuous enforcement that fights other
  // user-management software.
  if (policy.type == SNTTemporaryAdminPolicyTypeOnDemand && !have_record) {
    CaptureAndDemoteLocked();
  } else if (policy.type == SNTTemporaryAdminPolicyTypeRevoke && have_record) {
    RestoreAndClearLocked();
  }
}

void AdminUserState::SetupFromState() {
  // The callbacks capture `this` unretained: AdminUserState lives for the
  // daemon's lifetime, and kvo_ (which owns the observations) dies with it.
  kvo_ = @[
    [[SNTKVOManager alloc]
        initWithObject:configurator_
              selector:@selector(syncBaseURL)
                  type:[NSURL class]
              callback:^(NSURL* oldValue, NSURL* newValue) {
                if ((!newValue && !oldValue) ||
                    [newValue.absoluteString isEqualToString:oldValue.absoluteString]) {
                  return;
                }
                // Any change — removal or replacement — restores: the record
                // was captured under the old server's policy, and a new
                // server's first on-policy delivery finds no record and
                // captures fresh.
                HandleSyncServerChange();
              }],
    [[SNTKVOManager alloc] initWithObject:configurator_
                                 selector:@selector(pushTokenChain)
                                     type:[NSArray class]
                                 callback:^(NSArray* oldValue, NSArray* newValue) {
                                   // Ignore no-op fires. pushTokenChain is a KVO dependent key on
                                   // the whole syncState, so every syncState write fires this
                                   // callback even when the chain is unchanged — including the
                                   // write revoke_tam_ makes while HandleSyncServerChange holds
                                   // lock_. Without this guard that re-entrant fire would re-take
                                   // lock_ on the same thread and deadlock.
                                   if ((!newValue && !oldValue) ||
                                       [newValue isEqualToArray:oldValue]) {
                                     return;
                                   }
                                   if (!configurator_.isSyncV2Enabled) {
                                     HandleSyncServerChange();
                                   }
                                 }],
  ];

  // The watchers only fire on changes: a sync server that went away while the
  // daemon was not running is reconciled directly.
  if (!configurator_.isSyncV2Enabled) {
    HandleSyncServerChange();
  }
}

void AdminUserState::HandleSyncServerChange() {
  absl::MutexLock lock(lock_);
  if ([configurator_ savedDemotedAdmins] == nil) {
    return;
  }
  // Tear down any active TAM session before restoring, mirroring the sync
  // path's NewPolicyReceived-before-HandlePolicy ordering. TAM's own watchers
  // also revoke on these events, but KVO observer order is unspecified: if the
  // restore ran first it would mistake an active session for a demote-retry
  // residue, clear its state, and TAM's later revoke would then demote a
  // just-restored admin with the record already gone. Revoke is idempotent, so
  // the extra call is safe in either observer order.
  revoke_tam_();
  RestoreAndClearLocked();
}

void AdminUserState::CaptureAndDemoteLocked() {
  std::optional<std::vector<AdminGroupMember>> members = membership_->ListDirectUserMembers();
  if (!members.has_value()) {
    LOGE(@"DemotedAdmins: admin group enumeration failed; retrying at next sync");
    return;
  }

  NSNumber* tam_uid = TAMOwnedUID(configurator_);
  NSMutableArray<NSDictionary*>* record = [NSMutableArray array];
  for (const AdminGroupMember& member : *members) {
    if (member.uid < kMinDemotableUID) {
      continue;
    }
    if (tam_uid && member.uid == tam_uid.unsignedIntValue) {
      // This membership is TAM's (an active grant, or a failed-teardown
      // residue pending its restart retry), not a natural admin. Recording it
      // would launder a temporary elevation into a permanent one at restore.
      LOGI(@"DemotedAdmins: excluding TAM session target uid=%u from capture", member.uid);
      continue;
    }
    [record addObject:@{
      kDemotedAdminUsername : member.username,
      kDemotedAdminUID : @(member.uid),
      kDemotedAdminLocal : @(member.local),
    }];
  }

  // The record must be durable before any membership mutation: a record
  // without a flip is recovered by an idempotent restore, but a flip without
  // a record strands demoted users. An empty record is still written — its
  // presence marks the flip as applied.
  if (![configurator_ persistDemotedAdmins:record]) {
    LOGE(@"DemotedAdmins: failed to persist record; no users demoted; retrying at next sync");
    return;
  }

  for (NSDictionary* user in record) {
    uid_t uid = [user[kDemotedAdminUID] unsignedIntValue];
    NSError* err;
    if (membership_->RemoveMember(uid, &err)) {
      LOGI(@"DemotedAdmins: demoted %@ (uid=%u) to standard", user[kDemotedAdminUsername], uid);
    } else {
      // Deliberately not retried: re-applying demotions would fight other
      // user-management software. The user stays recorded and stays admin;
      // remediation is toggling the policy off then on.
      LOGE(@"DemotedAdmins: failed to demote %@ (uid=%u): %@", user[kDemotedAdminUsername], uid,
           err.localizedDescription);
    }
  }
}

// A record entry is treated as local unless it carries an explicit
// Local == NO. Missing or mistyped values (only possible via tampering or
// corruption) default to local so the entry stays terminal on unresolvable
// accounts and cannot keep the record alive forever.
static bool EntryIsLocal(NSDictionary* entry) {
  NSNumber* local = entry[kDemotedAdminLocal];
  return ![local isKindOfClass:[NSNumber class]] || local.boolValue;
}

void AdminUserState::SweepLocked(NSSet<NSString*>* allowed) {
  // Enumerate the group BEFORE asking who is elevated. Reversing this reopens
  // the window where a session that starts mid-sweep looks like a stray admin:
  // for the sweep to see a user in the group, the grant must already have
  // completed, and the grant holds TAM's lock across the whole promotion, so a
  // later read is guaranteed to name them.
  std::optional<std::vector<AdminGroupMember>> members = membership_->ListDirectUserMembers();
  if (!members.has_value()) {
    LOGE(@"AdminAllowlist: admin group enumeration failed; retrying at next sync");
    return;
  }
  // Two different questions, two different answers.
  //
  // active_tam_uid_ answers "may this user keep admin right now?" Only a live
  // session may, so a failed-teardown residue is excluded and the sweep demotes
  // it — which is the point of the accessor.
  //
  // TAMOwnedUID answers "did this membership come from TAM at all?", which
  // covers the residue too. A membership TAM created must never enter the
  // record: the restore at revoke would promote a user who was only ever a
  // temporary admin into a permanent one, and clear TAM's owed demotion on the
  // way. CaptureAndDemoteLocked guards the same way for the same reason.
  NSNumber* tam_uid = active_tam_uid_ ? active_tam_uid_() : nil;
  NSNumber* tam_owned_uid = TAMOwnedUID(configurator_);

  NSArray<NSDictionary*>* existing = [configurator_ savedDemotedAdmins];
  NSMutableArray<NSDictionary*>* record = [(existing ?: @[]) mutableCopy];
  NSMutableSet<NSNumber*>* recorded_uids = [NSMutableSet set];
  for (NSDictionary* entry in record) {
    NSNumber* uid = [entry isKindOfClass:[NSDictionary class]] ? entry[kDemotedAdminUID] : nil;
    if ([uid isKindOfClass:[NSNumber class]]) {
      [recorded_uids addObject:uid];
    }
  }

  // The first sweep in an enforcing window always writes, even with nothing to
  // record. See the persist comment below.
  bool record_changed = (existing == nil);

  std::vector<AdminGroupMember> demote;
  for (const AdminGroupMember& member : *members) {
    if (member.uid < kMinDemotableUID) {
      continue;
    }
    if (tam_uid && member.uid == tam_uid.unsignedIntValue) {
      // Legitimately elevated right now. TAM demotes them when their time is up.
      continue;
    }
    // Normalize the directory's spelling the same way the policy normalized the
    // server's. A raw comparison misses on a Unicode composition mismatch and
    // demotes the account with nothing logged.
    if ([allowed containsObject:[SNTTemporaryAdminPolicy normalizedUsername:member.username]]) {
      continue;
    }
    bool tam_owned = tam_owned_uid && member.uid == tam_owned_uid.unsignedIntValue;
    if (!tam_owned && ![recorded_uids containsObject:@(member.uid)]) {
      [record addObject:@{
        kDemotedAdminUsername : member.username,
        kDemotedAdminUID : @(member.uid),
        kDemotedAdminLocal : @(member.local),
      }];
      record_changed = true;
    }
    // Recorded or not: still an admin and still unlisted, so still demote.
    // Unlike the one-shot path, retrying here is correct.
    demote.push_back(member);
  }

  // Persist when the record changed, and on the first sweep even when it did
  // not: an empty record marks this machine as managed, which is what keeps a
  // later policy without the wrapper out of the one-shot capture branch.
  //
  // An explicit flag, not a count comparison. The restore pass removes entries
  // from this same record; a sweep that removed as many as it added would leave
  // the counts equal, skip the write, and demote users it never recorded.
  if (record_changed) {
    if (![configurator_ persistDemotedAdmins:record]) {
      LOGE(@"AdminAllowlist: failed to persist record; no users demoted; retrying at next sync");
      return;
    }
  }

  for (const AdminGroupMember& member : demote) {
    NSError* err;
    if (membership_->RemoveMember(member.uid, &err)) {
      LOGI(@"AdminAllowlist: demoted %@ (uid=%u) to standard", member.username, member.uid);
      demote_failures_logged_.erase(member.uid);
    } else if (demote_failures_logged_.insert(member.uid).second) {
      LOGE(@"AdminAllowlist: failed to demote %@ (uid=%u): %@; will retry each sync",
           member.username, member.uid, err.localizedDescription);
    }
  }

  // Restore pass. Walks the RECORD, never the allowlist: an account this Santa
  // never demoted has no entry, so editing the list can never promote it. This
  // is what keeps a user promoted by another tool outside Santa's reach.
  NSMutableArray<NSDictionary*>* kept = [NSMutableArray array];
  // Named distinctly from the demote pass's record_changed, which is still in
  // scope in this function.
  bool restore_changed = false;
  for (NSDictionary* entry in record) {
    if (![entry isKindOfClass:[NSDictionary class]]) {
      // Only possible via on-disk tampering or corruption. It can never be
      // resolved, but it must not crash the sweep or vanish silently.
      [kept addObject:entry];
      continue;
    }
    NSNumber* uid_number = entry[kDemotedAdminUID];
    NSString* recorded_username = [entry[kDemotedAdminUsername] isKindOfClass:[NSString class]]
                                      ? entry[kDemotedAdminUsername]
                                      : nil;
    if (![uid_number isKindOfClass:[NSNumber class]] || recorded_username.length == 0 ||
        uid_number.unsignedIntValue < kMinDemotableUID ||
        ![allowed containsObject:[SNTTemporaryAdminPolicy normalizedUsername:recorded_username]]) {
      [kept addObject:entry];
      continue;
    }

    uid_t uid = uid_number.unsignedIntValue;
    NSString* current_username = membership_->UsernameForUID(uid);
    if (current_username.length == 0) {
      if (EntryIsLocal(entry)) {
        // A local identity that no longer resolves was deleted. Terminal:
        // drop the entry so it cannot pin the record forever.
        LOGW(@"AdminAllowlist: local account %@ (uid=%u) no longer resolves; dropping entry",
             recorded_username, uid);
        restore_changed = true;
      } else {
        // A directory account may be deleted OR merely unreachable
        // (off-network, directory outage), and the two are indistinguishable.
        // Consuming the entry on an outage would strand a real admin.
        LOGW(@"AdminAllowlist: directory account %@ (uid=%u) unresolvable; retrying at next sync",
             recorded_username, uid);
        [kept addObject:entry];
      }
      continue;
    }
    if ([current_username caseInsensitiveCompare:recorded_username] != NSOrderedSame) {
      // The uid names a different account than the one demoted: the original was
      // deleted and the uid reused, or the account was renamed. Never promote it,
      // and drop the entry so it cannot pin the record forever.
      LOGW(@"AdminAllowlist: uid=%u now resolves to %@, not recorded %@; dropping entry", uid,
           current_username, recorded_username);
      restore_changed = true;
      continue;
    }

    if (tam_uid && uid == tam_uid.unsignedIntValue) {
      // This membership is TAM's, not a restore. Promoting now would consume
      // the entry, and TAM's teardown would then demote an allowed user with
      // nothing left in the record to bring them back. Retry next sweep.
      [kept addObject:entry];
      continue;
    }

    NSError* err;
    if (membership_->AddMember(uid, &err)) {
      LOGI(@"AdminAllowlist: %@ (uid=%u) is now allowed; restored to admin", recorded_username,
           uid);
      restore_changed = true;
    } else {
      // Keep the entry and retry next sync rather than losing track of them.
      LOGE(@"AdminAllowlist: failed to restore allowed user %@ (uid=%u): %@; retrying at next sync",
           recorded_username, uid, err.localizedDescription);
      [kept addObject:entry];
    }
  }

  if (restore_changed && ![configurator_ persistDemotedAdmins:kept]) {
    LOGE(@"AdminAllowlist: restores applied but record update did not persist; "
         @"retrying at next sync");
  }
}

void AdminUserState::RestoreAndClearLocked() {
  NSArray<NSDictionary*>* record = [configurator_ savedDemotedAdmins];
  bool all_restored = true;
  NSMutableSet<NSNumber*>* restored_uids = [NSMutableSet set];
  for (NSDictionary* user in record) {
    NSNumber* uid_number = [user isKindOfClass:[NSDictionary class]] ? user[kDemotedAdminUID] : nil;
    if (![uid_number isKindOfClass:[NSNumber class]]) {
      // Only possible via on-disk tampering or corruption. The entry can never
      // be restored, so it must not keep the whole record alive forever.
      LOGE(@"DemotedAdmins: malformed record entry %@; skipping", user);
      continue;
    }
    uid_t uid = [uid_number unsignedIntValue];
    if (uid < kMinDemotableUID) {
      // Capture never records system accounts, so this is tampering or
      // corruption. Never promote it; like the malformed case above, it must
      // not keep the record alive forever.
      LOGE(@"DemotedAdmins: record entry %@ is below the minimum uid; skipping", user);
      continue;
    }
    NSString* recorded_username = [user[kDemotedAdminUsername] isKindOfClass:[NSString class]]
                                      ? user[kDemotedAdminUsername]
                                      : nil;
    NSString* current_username = membership_->UsernameForUID(uid);
    if (recorded_username.length && current_username.length &&
        [current_username caseInsensitiveCompare:recorded_username] != NSOrderedSame) {
      // The uid resolves to a different account than was demoted: the
      // original was deleted and the uid reused. Never promote the new
      // account; like the deleted-account case, the entry is complete.
      [restored_uids addObject:@(uid)];
      LOGW(@"DemotedAdmins: uid=%u now resolves to %@, not recorded %@; treating as removed", uid,
           current_username, recorded_username);
      continue;
    }
    NSError* err;
    if (membership_->AddMember(uid, &err)) {
      [restored_uids addObject:@(uid)];
      LOGI(@"DemotedAdmins: restored %@ (uid=%u) to admin", user[kDemotedAdminUsername], uid);
    } else if (err.code == SNTErrorCodeTAMNoConsoleUser && EntryIsLocal(user)) {
      [restored_uids addObject:@(uid)];
      // A local identity that no longer resolves was deleted during the
      // enabled window. Nothing to restore. (Entries missing the Local key —
      // tampering or corruption — land here too, so a damaged entry can
      // never pin the record alive forever.)
      LOGW(@"DemotedAdmins: %@ (uid=%u) no longer resolves; treating as restored",
           user[kDemotedAdminUsername], uid);
    } else if (err.code == SNTErrorCodeTAMNoConsoleUser) {
      all_restored = false;
      // An unresolvable directory account may be deleted OR merely
      // unreachable (off-network, directory outage). Consuming the entry on
      // an outage would strand a real admin, so it is retried instead; the
      // restore stays an idempotent no-op for everyone already handled.
      LOGW(@"DemotedAdmins: directory account %@ (uid=%u) unresolvable; cannot "
           @"distinguish deleted from unreachable; retrying at next sync",
           user[kDemotedAdminUsername], uid);
    } else {
      all_restored = false;
      LOGE(@"DemotedAdmins: failed to restore %@ (uid=%u): %@; retrying at next sync",
           user[kDemotedAdminUsername], uid, err.localizedDescription);
    }
  }

  if (all_restored) {
    // If TAM persisted a demote-retry residue for a user this restore just
    // deliberately re-promoted, executing that retry at the next daemon start
    // would strand a restored natural admin — policy off, record gone. The
    // restore supersedes the owed demotion. (A residue for a uid outside the
    // record is TAM's business; leave it.)
    NSNumber* tam_uid = TAMOwnedUID(configurator_);
    if (tam_uid && [restored_uids containsObject:tam_uid]) {
      LOGI(@"DemotedAdmins: clearing TAM demote-retry residue for restored uid=%u",
           tam_uid.unsignedIntValue);
      [configurator_ persistTimedSessionState:nil forKey:kStateTempAdminModeKey];
    }
    if (![configurator_ persistDemotedAdmins:nil]) {
      // The rollback keeps the in-memory record, so the next revoke delivery
      // re-runs the (idempotent) restore and retries the deletion.
      LOGE(@"DemotedAdmins: restore complete but record deletion did not persist; "
           @"retrying at next sync");
    } else {
      demote_failures_logged_.clear();
    }
  }
}

}  // namespace santa
