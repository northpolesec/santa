/// Copyright 2017-2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santad/SNTCompilerController.h"

#include <bsm/libbsm.h>
#include <mach/message.h>
#include <os/base.h>
#include <string.h>

#include <atomic>
#include <functional>
#include <utility>

#include "Source/common/AuditUtilities.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTTimer.h"
#include "Source/common/String.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTDatabaseController.h"
#import "Source/santad/SNTDecisionCache.h"
#include "absl/container/flat_hash_set.h"

using santa::Logger;
using santa::Message;

static const pid_t PID_MAX = 99999;
static constexpr std::string_view kIgnoredCompilerProcessPathPrefix = "/dev/";
static constexpr uint32_t kCompilerMarkSweepIntervalSeconds = 300;

// Tracks compiler PIDs using pidversion to prevent PID reuse attacks.
//
// Each slot stores the pidversion of the active compiler at that PID index, or 0
// to indicate no compiler. This ensures that if a compiler exits and its EXIT
// event is dropped by ES, a new process that reuses the same PID will not be
// falsely treated as a compiler (since its pidversion will differ).
// The periodic sweep (-sweepExitedCompilers) clears such a slot once its process
// is gone.
//
// Edge case: pidversion is a signed 32-bit kernel counter (incremented globally
// via OSIncrementAtomic on each fork) that can wrap through all 2^32 values. If
// a compiler happens to fork at the exact moment pidversion wraps to 0, the
// stored value will be indistinguishable from "no compiler" — a false negative.
// This requires ~2^32 forks (~62 days at a sustained ~800 fork/sec) and only
// affects the single compiler instance at that moment. The failure mode is that
// transitive rules are not created for that compiler's output, potentially
// causing legitimate binaries to be blocked until the next compiler invocation
// (which will have a non-zero pidversion). This is a correctness blip, not a
// security issue, and is self-healing.
@interface SNTCompilerController () {
  std::atomic<int32_t> _compilerPIDs[PID_MAX];
  std::shared_ptr<santa::PendingExecCoordinator> _pendingExecCoordinator;
  std::function<bool(pid_t, audit_token_t*)> _tokenForPid;
  // (pid, pidversion) marks the previous sweep found stale. Touched only by
  // -sweepExitedCompilers, which runs on the sweep timer's serial queue.
  absl::flat_hash_set<santa::ProcessID> _staleCompilerMarks;
  SNTTimer* _markSweepTimer;
}
@end

@implementation SNTCompilerController

- (instancetype)initWithPendingExecCoordinator:
    (std::shared_ptr<santa::PendingExecCoordinator>)coordinator {
  return [self initWithPendingExecCoordinator:std::move(coordinator)
                                  tokenForPid:santa::AuditTokenForPid];
}

- (instancetype)
    initWithPendingExecCoordinator:(std::shared_ptr<santa::PendingExecCoordinator>)coordinator
                       tokenForPid:(std::function<bool(pid_t, audit_token_t*)>)tokenForPid {
  self = [super init];
  if (self) {
    _pendingExecCoordinator = std::move(coordinator);
    _tokenForPid = std::move(tokenForPid);
    if (_pendingExecCoordinator) {
      WEAKIFY(self);
      _markSweepTimer = [[SNTTimer alloc] initWithMinInterval:kCompilerMarkSweepIntervalSeconds
                                                  maxInterval:kCompilerMarkSweepIntervalSeconds
                                                         name:@"CompilerMarkSweep"
                                                  fireOnStart:NO
                                               rescheduleMode:SNTTimerRescheduleModeTrailingEdge
                                                     qosClass:QOS_CLASS_UTILITY
                                                     callback:^bool {
                                                       STRONGIFY(self);
                                                       [self sweepExitedCompilers];
                                                       return true;
                                                     }];
      [_markSweepTimer startWithInterval:kCompilerMarkSweepIntervalSeconds];
    }
  }
  return self;
}

- (BOOL)isCompiler:(const audit_token_t&)tok {
  pid_t pid = audit_token_to_pid(tok);
  if (pid < 0 || pid >= PID_MAX) return NO;
  int32_t stored = self->_compilerPIDs[pid].load(std::memory_order_relaxed);
  if (stored == 0) return NO;
  // Only the exact compiler instance (matching pidversion) is a compiler. A
  // mismatch means the event came from a different incarnation at the same PID:
  // most commonly the process's own pre-exec image, which emits NOTIFY events at an
  // earlier pidversion, or a recycled PID. Return NO, but do not clear the slot. A
  // mismatched event can be delivered after the real compiler was marked, and
  // clearing here would drop the still-valid mark and prevent the compiler's
  // output from getting a transitive rule.
  return stored == audit_token_to_pidversion(tok);
}

- (void)setProcess:(const audit_token_t&)tok isCompiler:(bool)isCompiler {
  pid_t pid = audit_token_to_pid(tok);
  if (pid < 1) {
    LOGE(@"Unable to watch compiler pid=%d", pid);
  } else if (pid >= PID_MAX) {
    LOGE(@"Unable to watch compiler pid=%d >= PID_MAX(%d)", pid, PID_MAX);
  } else {
    int32_t val = isCompiler ? audit_token_to_pidversion(tok) : 0;
    int32_t prev = self->_compilerPIDs[pid].exchange(val, std::memory_order_relaxed);
    // Every process exit clears its slot, so only a mark, or a clear of a slot
    // that held one, is compiler activity. The exchange makes the count track
    // the number of marked slots exactly.
    if (_pendingExecCoordinator && (val != 0 || prev != 0)) {
      _pendingExecCoordinator->UpdateCompilerMarks((val != 0) - (prev != 0));
    }
    if (isCompiler) {
      LOGD(@"Watching compiler pid=%d pidver=%d", pid, val);
    }
  }
}

// Clears the mark at `pid` only if it still holds `pidversion`, so a mark set
// since the caller read the slot is never lost. Only a successful clear changes
// the count. Returns whether it cleared the mark.
- (BOOL)clearCompilerMarkForPid:(pid_t)pid pidversion:(int32_t)pidversion {
  if (pid < 1 || pid >= PID_MAX || pidversion == 0) return NO;
  int32_t expected = pidversion;
  if (!self->_compilerPIDs[pid].compare_exchange_strong(expected, 0, std::memory_order_relaxed)) {
    return NO;
  }
  if (_pendingExecCoordinator) {
    _pendingExecCoordinator->UpdateCompilerMarks(-1);
  }
  return YES;
}

// Clears marks whose process is gone without its exit having been processed,
// so the marked-compiler count reflects running compilers. A mark is cleared
// only when the same (pid, pidversion) fails the check on two consecutive
// sweeps: a process can be gone while its last NOTIFY_CLOSE, which needs the
// mark, has not been processed yet, and two sweeps give that close at least one
// interval.
- (void)sweepExitedCompilers {
  if (!_pendingExecCoordinator || !_pendingExecCoordinator->MarkedCompilersExist()) {
    _staleCompilerMarks.clear();
    return;
  }

  absl::flat_hash_set<santa::ProcessID> stale;
  int cleared = 0;
  for (pid_t pid = 1; pid < PID_MAX; pid++) {
    int32_t marked = self->_compilerPIDs[pid].load(std::memory_order_relaxed);
    if (marked == 0) continue;

    santa::ProcessID mark{pid, marked};
    audit_token_t tok;
    if (_tokenForPid(pid, &tok) && santa::ProcessID::FromToken(tok) == mark) continue;

    if (!_staleCompilerMarks.contains(mark)) {
      stale.insert(mark);
      continue;
    }

    // A clear also records compiler activity, so CompilerActiveRecently() stays
    // true for one more activity window, though no compiler is running. A fresh
    // unknown binary run in that window is held until the wait times out, then
    // blocked.
    if ([self clearCompilerMarkForPid:pid pidversion:marked]) {
      cleared++;
    }
  }
  _staleCompilerMarks = std::move(stale);

  if (cleared > 0) {
    LOGI(@"Cleared %d compiler marks whose process is no longer running", cleared);
  }
}

// Adds a fake cached decision to SNTDecisionCache for pending files. If the file
// is executed before we can create a transitive rule for it, then we can at
// least log the pending decision info.
//
// An execution of the file held for this rule keeps its cached decision until
// the hold has logged it, so that log reads the held execution's decision.
// Returns the fake decision cached, or nil if none was.
- (SNTCachedDecision*)saveFakeDecision:(SNTFileInfo*)fileInfo {
  SNTDecisionCache* cache = [SNTDecisionCache sharedCache];
  SNTCachedDecision* existing = [cache cachedDecisionForVnode:fileInfo.vnode];
  if (existing.heldForTransitiveRule) {
    return nil;
  }

  SNTCachedDecision* cd = [[SNTCachedDecision alloc] initWithVnode:fileInfo.vnode];
  cd.decision = SNTEventStateAllowPendingTransitive;
  cd.sha256 = @"pending";
  return [cache cacheDecision:cd replacingDecision:existing] ? cd : nil;
}

// Removes the fake decision unless something has replaced it since.
- (void)removeFakeDecision:(SNTCachedDecision*)fakeDecision {
  if (fakeDecision) {
    [[SNTDecisionCache sharedCache] forgetCachedDecision:fakeDecision];
  }
}

- (BOOL)handleEvent:(const Message&)esMsg withLogger:(std::shared_ptr<Logger>)logger {
  SNTFileInfo* targetFile;
  NSString* targetPath;
  NSError* error;

  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_CLOSE:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return NO;
      }

      if (strncmp(kIgnoredCompilerProcessPathPrefix.data(), esMsg->event.close.target->path.data,
                  kIgnoredCompilerProcessPathPrefix.length()) == 0) {
        return NO;
      }

      targetPath = @(esMsg->event.close.target->path.data);
      targetFile = [[SNTFileInfo alloc] initWithEndpointSecurityFile:esMsg->event.close.target
                                                               error:&error];

      break;
    case ES_EVENT_TYPE_NOTIFY_RENAME:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return NO;
      }

      if (strncmp(kIgnoredCompilerProcessPathPrefix.data(), esMsg->event.rename.source->path.data,
                  kIgnoredCompilerProcessPathPrefix.length()) == 0) {
        return NO;
      }

      {
        // The event can be handled before or after the rename completes, so the `source` vnode
        // may be at either path. Verify each against the source's stat. `existing_file` is the
        // file being replaced, not the renamed one.
        const struct stat* renamedStat = &esMsg->event.rename.source->stat;
        NSString* destPath =
            esMsg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE
                ? @(esMsg->event.rename.destination.existing_file->path.data)
                : [NSString
                      stringWithFormat:@"%s/%s",
                                       esMsg->event.rename.destination.new_path.dir->path.data,
                                       esMsg->event.rename.destination.new_path.filename.data];

        for (NSString* path in @[ @(esMsg->event.rename.source->path.data), destPath ]) {
          targetPath = path;
          targetFile = [[SNTFileInfo alloc] initWithResolvedPath:path
                                                            stat:renamedStat
                                                           error:&error];
          if (targetFile && targetFile.identityVerification != SNTFileInfoIdentityMismatch) {
            break;
          }
        }
      }

      break;
    case ES_EVENT_TYPE_NOTIFY_CLONE:
      if (![self isCompiler:esMsg->process->audit_token]) {
        return NO;
      }

      // Note: For CLONE events, we first attempt to process the `source`. But if that doesn't
      // exist (it normally will since clones are copies), we fall back to the `destination`.
      if (strncmp(kIgnoredCompilerProcessPathPrefix.data(), esMsg->event.clone.source->path.data,
                  kIgnoredCompilerProcessPathPrefix.length()) == 0) {
        return NO;
      }

      targetFile = [[SNTFileInfo alloc] initWithEndpointSecurityFile:esMsg->event.clone.source
                                                               error:&error];
      if (!targetFile) {
        LOGD(@"Unable to locate source file for clone event while creating transitive. Falling "
             @"back to destination. Path: %s, Error: %@",
             esMsg->event.clone.source->path.data, error);
        targetPath = [NSString stringWithFormat:@"%s/%s", esMsg->event.clone.target_dir->path.data,
                                                esMsg->event.clone.target_name.data];
        targetFile = [[SNTFileInfo alloc] initWithResolvedPath:targetPath error:&error];
        // The event carries no stat for the new file. A clone starts out the same size as its
        // source, so require that.
        if (targetFile &&
            targetFile.fileSize != (NSUInteger)esMsg->event.clone.source->stat.st_size) {
          LOGW(@"Not creating transitive rule for %@: size does not match the clone source",
               targetPath);
          return NO;
        }
      }

      break;
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      // The image that called exec is gone, so its mark is stale. If the new
      // image is a compiler, the Authorizer has marked it at its new pidversion,
      // and this clear leaves that mark. The old image's NOTIFY_CLOSEs, including
      // closes of close-on-exec files during the exec, come before this event, so
      // they were handled while the mark was set.
      [self clearCompilerMarkForPid:audit_token_to_pid(esMsg->process->audit_token)
                         pidversion:audit_token_to_pidversion(esMsg->process->audit_token)];
      return YES;
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      [self setProcess:esMsg->process->audit_token isCompiler:false];
      return YES;
    default: return NO;
  }

  // If we get here, we need to update transitve rules
  if (targetFile) {
    if (targetFile.identityVerification == SNTFileInfoIdentityMismatch) {
      // A transitive rule names a file by content hash and persists, so it must
      // not be written from an unconfirmed read. An unconfirmed read still
      // produces an SNTFileInfo, so one reaches here whenever no candidate path
      // above could be confirmed.
      LOGW(@"Not creating transitive rule for %@: identity could not be confirmed",
           targetFile.path);
      return NO;
    }
    [self createTransitiveRule:esMsg target:targetFile logger:logger];
    return YES;
  } else {
    LOGD(@"Unable to create SNTFileInfo while attempting to create transitive rule. Event: %d | "
         @"Path: %@ | Error: %@",
         (int)esMsg->event_type, targetPath, error);
    return NO;
  }
}

// Assume that this method is called only when we already know that the writing process is a
// compiler.  It checks if the closed file is executable, and if so, transitively allowlists it.
// The passed in message contains the pid of the writing process and path of closed file.
- (void)createTransitiveRule:(const Message&)esMsg
                      target:(SNTFileInfo*)targetFile
                      logger:(std::shared_ptr<Logger>)logger {
  SNTCachedDecision* fakeDecision = [self saveFakeDecision:targetFile];

  // Check if this file is an executable.
  if (targetFile.isExecutable) {
    // Check if there is an existing (non-transitive) rule for this file.  We leave existing rules
    // alone, so that a allowlist or blocklist rule can't be overwritten by a transitive one.
    SNTRuleTable* ruleTable = [SNTDatabaseController ruleTable];
    SNTRule* prevRule =
        [ruleTable executionRuleForIdentifiers:(struct RuleIdentifiers){
                                                   .binarySHA256 = targetFile.SHA256,
                                               }];
    // Note: Don't overwrite existing rules, unless it was a transitive rule which is allowed
    // in order to have timestamps updated.
    if (!prevRule || prevRule.state == SNTRuleStateAllowTransitive) {
      // Construct a new transitive allowlist rule for the executable.
      SNTRule* rule = [[SNTRule alloc] initWithIdentifier:targetFile.SHA256
                                                    state:SNTRuleStateAllowTransitive
                                                     type:SNTRuleTypeBinary];

      if (!rule) {
        LOGW(@"Failed to create transitive rule: %@ (SHA-256: %@)", targetFile.path,
             targetFile.SHA256);
      } else {
        // Add the new rule to the rules database.
        NSArray<NSError*>* errors;
        if (![ruleTable addExecutionRules:@[ rule ]
                              ruleCleanup:SNTRuleCleanupNone
                                   errors:&errors]) {
          for (NSError* error in errors) {
            LOGE(@"Unable to add new transitive rule to database: %@", error.localizedDescription);
          }
        } else {
          logger->LogAllowlist(esMsg, santa::NSStringToUTF8StringView(targetFile.SHA256),
                               santa::NSStringToUTF8StringView(targetFile.path));
          if (_pendingExecCoordinator) {
            _pendingExecCoordinator->NotifyRuleCreated(
                santa::NSStringToUTF8String(targetFile.SHA256));
          }
        }
      }
    }
  }

  [self removeFakeDecision:fakeDecision];
}

@end
