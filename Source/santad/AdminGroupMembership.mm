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

#include "Source/santad/AdminGroupMembership.h"

#import <Collaboration/Collaboration.h>
#import <CoreServices/CoreServices.h>

#include <unistd.h>

#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"

namespace santa {

namespace {

// The admin group is always a local group, so it is resolved with the local
// identity authority. The user, however, may be a network/directory (e.g. AD)
// account, so it is resolved with the default authority (local plus managed).
// This asymmetry is deliberate — a network user must still be addable to the
// local admin group — and matches the approach used by SAP Privileges. Do not
// "simplify" both to the same authority.
CBGroupIdentity* AdminGroupIdentity() {
  return [CBGroupIdentity groupIdentityWithPosixGID:AdminGroupMembership::kAdminGroupID
                                          authority:[CBIdentityAuthority localIdentityAuthority]];
}

// Resolve the user by numeric POSIX UID rather than by name. The UID is the
// stable, unambiguous directory key we already hold; resolving by name would put
// a non-reentrant getpwuid on this privileged mutation path — where a clobbered
// pw_name would change which account is added to or removed from the admin group
// — and could disagree across the separate IsMember / ChangeMembership /
// VerifyMembership lookups if the account were renamed between them. The default
// authority is retained so network/directory users still resolve (see
// AdminGroupIdentity for the group/user authority asymmetry).
CBIdentity* UserIdentityForUID(uid_t uid) {
  return [CBUserIdentity userIdentityWithPosixUID:uid
                                        authority:[CBIdentityAuthority defaultIdentityAuthority]];
}

// Delay between the two post-commit verification reads on the remove path, to
// absorb opendirectoryd membership-cache latency before failing closed.
static constexpr useconds_t kVerifyRetryDelayUSec = 200 * 1000;  // 200ms

// Re-reads live membership and returns whether it matches `expected`. A failed
// identity resolution counts as not matching.
bool VerifyMembership(uid_t uid, bool expected) {
  CBIdentity* fresh = UserIdentityForUID(uid);
  return fresh && ([fresh isMemberOfGroup:AdminGroupIdentity()] == expected);
}

class AdminGroupMembershipImpl : public AdminGroupMembership {
 public:
  bool IsMember(uid_t uid) override {
    CBIdentity* user = UserIdentityForUID(uid);
    CBGroupIdentity* group = AdminGroupIdentity();
    if (!user || !group) {
      return false;
    }
    return [user isMemberOfGroup:group];
  }

  bool AddMember(uid_t uid, NSError** error) override {
    return ChangeMembership(uid, /*add=*/true, error);
  }

  bool RemoveMember(uid_t uid, NSError** error) override {
    return ChangeMembership(uid, /*add=*/false, error);
  }

  std::optional<std::vector<AdminGroupMember>> ListDirectUserMembers() override {
    CBGroupIdentity* group = AdminGroupIdentity();
    if (!group) {
      return std::nullopt;
    }
    std::vector<AdminGroupMember> members;
    for (CBIdentity* identity in group.memberIdentities) {
      if (![identity isKindOfClass:[CBUserIdentity class]]) {
        continue;
      }
      CBUserIdentity* user = (CBUserIdentity*)identity;
      members.push_back({user.posixUID, user.posixName ?: @"",
                         [user.authority isEqual:[CBIdentityAuthority localIdentityAuthority]]});
    }
    return members;
  }

  NSString* UsernameForUID(uid_t uid) override {
    CBIdentity* identity = UserIdentityForUID(uid);
    if (![identity isKindOfClass:[CBUserIdentity class]]) {
      return nil;
    }
    return ((CBUserIdentity*)identity).posixName;
  }

 private:
  bool ChangeMembership(uid_t uid, bool add, NSError** error) {
    CBIdentity* user = UserIdentityForUID(uid);
    CBGroupIdentity* group = AdminGroupIdentity();
    // The two resolution failures carry distinct codes because restore callers
    // branch on them: an unresolvable group is a systemic directory-services
    // failure (the local admin group always exists) and must read as
    // retryable, while an unresolvable user with a healthy group means the
    // account no longer exists. Merging these branches would let a transient
    // opendirectoryd failure be misread as mass account deletion.
    if (!group) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"Unable to resolve admin group identity"];
      return false;
    }
    if (!user) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMNoConsoleUser
                       format:@"Unable to resolve identity for uid %u", uid];
      return false;
    }

    CSIdentityRef cs_user = [user CSIdentity];
    CSIdentityRef cs_group = [group CSIdentity];
    if (!cs_user || !cs_group) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"Unable to obtain CSIdentity for uid %u", uid];
      return false;
    }

    if (add) {
      CSIdentityAddMember(cs_group, cs_user);
    } else {
      CSIdentityRemoveMember(cs_group, cs_user);
    }

    CFErrorRef commit_error = NULL;
    if (!CSIdentityCommit(cs_group, NULL, &commit_error)) {
      NSError* bridged = (NSError*)CFBridgingRelease(commit_error);
      [SNTError populateError:error
                     withCode:SNTErrorCodeTAMMembershipChangeFailed
                       format:@"CSIdentityCommit failed: %@", bridged.localizedDescription];
      return false;
    }

    // Re-read membership to verify the commit took effect. opendirectoryd caches
    // membership with a short TTL, so a single fresh read can lag the commit.
    //
    // Add and remove are deliberately asymmetric. For add, optimism favors the
    // user: a committed add is treated as authoritative and a verify mismatch is
    // logged, because the next live lookup (sudo, Authorization Services) re-reads
    // through opendirectoryd anyway. For remove, optimism would favor NOT revoking,
    // which defeats the feature: a committed remove whose verification still shows
    // membership is retried once, and if it still shows membership it is reported as
    // a failure so the caller does not record a clean revocation.
    if (add) {
      if (!VerifyMembership(uid, /*expected=*/true)) {
        LOGW(@"Admin group add committed but verification read still shows "
             @"non-member (uid=%u) — treating commit as authoritative",
             uid);
      }
      return true;
    }

    if (VerifyMembership(uid, /*expected=*/false)) {
      return true;
    }
    // One bounded retry to absorb opendirectoryd cache latency.
    usleep(kVerifyRetryDelayUSec);
    if (VerifyMembership(uid, /*expected=*/false)) {
      return true;
    }
    [SNTError populateError:error
                   withCode:SNTErrorCodeTAMMembershipChangeFailed
                     format:@"Admin group remove committed but uid %u is still a "
                            @"member after verification",
                            uid];
    return false;
  }
};

}  // namespace

std::unique_ptr<AdminGroupMembership> CreateAdminGroupMembership() {
  return std::make_unique<AdminGroupMembershipImpl>();
}

}  // namespace santa
