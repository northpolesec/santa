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

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTKVOManager.h"
#import "Source/common/SNTTemporaryAdminPolicy.h"
#include "Source/santad/AdminGroupMembership.h"
#include "absl/synchronization/mutex.h"

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

  // `revoke_tam` must synchronously revoke any active Temporary Admin Mode
  // session; HandleSyncServerChange calls it before restoring (see there).
  AdminUserState(SNTConfigurator* configurator, std::unique_ptr<AdminGroupMembership> membership,
                 void (^revoke_tam)(void));

  // Reconciles local admin users against `policy`. Called after each sync
  // batch commits, after TemporaryAdminMode::NewPolicyReceived, so on a revoke
  // TAM tears down its own elevation before natural admins are restored. A nil
  // policy or a type other than OnDemand/Revoke is a no-op.
  void HandlePolicy(SNTTemporaryAdminPolicy* policy);

  // Watches for the sync server being removed or replaced and restores the
  // recorded users when that happens: a machine that can no longer sync can
  // never receive the Revoke that would otherwise restore them. Also runs one
  // reconcile immediately, catching a server that went away while the daemon
  // was not running; a restore that fails there is retried at the next daemon
  // start. Called once at daemon startup, after TemporaryAdminMode's
  // SetupFromState; not from the constructor because the sync-v2 gate read is
  // daemon-only.
  void SetupFromState();

  // Restores the recorded users and deletes the record, revoking any active
  // TAM session first. A no-op without a record. Public for tests.
  void HandleSyncServerChange();

 private:
  void CaptureAndDemoteLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);
  void RestoreAndClearLocked() ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  SNTConfigurator* configurator_;
  std::unique_ptr<AdminGroupMembership> membership_;
  void (^revoke_tam_)(void);
  NSArray<SNTKVOManager*>* kvo_;
  absl::Mutex lock_;
};

}  // namespace santa

#endif  // SANTA_SANTAD_ADMINUSERSTATE_H
