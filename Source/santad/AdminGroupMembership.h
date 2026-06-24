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

#ifndef SANTA_SANTAD_ADMINGROUPMEMBERSHIP_H
#define SANTA_SANTAD_ADMINGROUPMEMBERSHIP_H

#import <Foundation/Foundation.h>

#include <sys/types.h>
#include <memory>

namespace santa {

// Abstracts mutation of admin-group (GID 80) membership. The orchestrator depends
// only on this interface so it can be unit-tested with a fake, and so the
// privileged backing can be either an in-process CoreServices call or an XPC call
// to a root helper without changing any consumer.
class AdminGroupMembership {
 public:
  static constexpr gid_t kAdminGroupID = 80;

  virtual ~AdminGroupMembership() = default;

  // Returns true if `uid` is currently a member of the admin group.
  virtual bool IsMember(uid_t uid) = 0;

  // Adds `uid` to the admin group and commits. A committed add is authoritative;
  // a post-commit verification mismatch (opendirectoryd cache latency) is logged,
  // not failed. Returns true on a committed change; populates `error` on failure.
  virtual bool AddMember(uid_t uid, NSError** error) = 0;

  // Removes `uid` from the admin group and commits. Fails closed: a committed
  // remove that the verification re-read still shows as a member (after one bounded
  // retry) returns false and populates `error`, so callers never record a clean
  // revocation for a user who is still elevated. Returns true only on a verified
  // removal; populates `error` on failure.
  virtual bool RemoveMember(uid_t uid, NSError** error) = 0;
};

// Returns the in-process CoreServices-backed implementation.
std::unique_ptr<AdminGroupMembership> CreateAdminGroupMembership();

}  // namespace santa

#endif  // SANTA_SANTAD_ADMINGROUPMEMBERSHIP_H
