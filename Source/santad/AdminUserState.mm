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
                               std::unique_ptr<AdminGroupMembership> membership)
    : configurator_(configurator), membership_(std::move(membership)) {}

void AdminUserState::HandlePolicy(SNTTemporaryAdminPolicy* policy) {
  absl::MutexLock lock(&lock_);
  bool have_record = [configurator_ savedDemotedAdmins] != nil;
  if (policy.type == SNTTemporaryAdminPolicyTypeOnDemand && !have_record) {
    CaptureAndDemoteLocked();
  } else if (policy.type == SNTTemporaryAdminPolicyTypeRevoke && have_record) {
    RestoreAndClearLocked();
  }
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
    }
  }
}

}  // namespace santa
