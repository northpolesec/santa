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

#ifndef SANTA_SANTAD_ADMINUSERSTATE_H
#define SANTA_SANTAD_ADMINUSERSTATE_H

#include <memory>

#include "absl/synchronization/mutex.h"

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#include "Source/santad/AdminGroupMembership.h"

namespace santa {

// Reconciles pre-existing ("natural") admin users against the Temporary Admin
// Mode policy. When the policy turns on, the direct admin-group members with
// uid >= kMinDemotableUID are recorded in the tamper-protected state file and
// demoted to standard; when it turns off, exactly the recorded users are
// restored and the record is deleted.
//
// Record presence is the only edge detector. Workshop broadcasts the policy in
// every preflight, so HandlePolicy runs every sync and must be idempotent:
// on-with-a-record and off-without-a-record are no-ops. This is what keeps
// Santa from fighting other user-management software — a user promoted by an
// admin tool during the enabled window is never re-demoted.
class AdminUserState {
 public:
  // System accounts below this uid (including root, uid 0, which is always a
  // direct member of the admin group) are never demoted, recorded, or restored.
  static constexpr uid_t kMinDemotableUID = 500;

  AdminUserState(SNTConfigurator* configurator,
                 std::unique_ptr<AdminGroupMembership> membership);

  // Reconciles local admin users against `policy`. Called after each sync
  // batch commits, after TemporaryAdminMode::NewPolicyReceived, so on a revoke
  // TAM tears down its own elevation before natural admins are restored. A nil
  // policy or a type other than OnDemand/Revoke is a no-op.
  void HandlePolicy(SNTTemporaryAdminPolicy* policy);

 private:
  void CaptureAndDemoteLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);
  void RestoreAndClearLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  SNTConfigurator* configurator_;
  std::unique_ptr<AdminGroupMembership> membership_;
  absl::Mutex lock_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_ADMINUSERSTATE_H
