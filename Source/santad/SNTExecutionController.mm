/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import "Source/santad/SNTExecutionController.h"

#import <Foundation/Foundation.h>

#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/param.h>
#include <utmpx.h>

#include <cstring>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "Source/common/AccountLookup.h"
#include "Source/common/BranchPrediction.h"
#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/MOLCodesignChecker.h"
#include "Source/common/PrefixTree.h"
#import "Source/common/SNTBlockMessage.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigState.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#include "Source/common/SantaCache.h"
#include "Source/common/SantaVnode.h"
#include "Source/common/String.h"
#include "Source/common/SystemResources.h"
#include "Source/common/Unit.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#include "Source/common/processtree/process.h"
#include "Source/common/processtree/process_tree.h"
#include "Source/santad/CELActivation.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#import "Source/santad/SNTBelievableClock.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#import "Source/santad/SNTTimedRuleKills.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

using santa::Message;
using santa::PrefixTree;
using santa::ProcessControl;
using santa::TTYWriter;
using santa::Unit;

static const size_t kMaxAllowedPathLength = MAXPATHLEN - 1;  // -1 to account for null terminator

@interface SNTExecutionController ()
@property SNTEventTable* eventTable;
@property SNTNotificationQueue* notifierQueue;
@property SNTPolicyProcessor* policyProcessor;
@property(readwrite) SNTRuleTable* ruleTable;
@property SNTSyncdQueue* syncdQueue;
@property SNTTimedRuleKills* timedRuleKills;
@property SNTMetricCounter* events;
@property santa::ProcessControlBlock processControlBlock;

@property dispatch_queue_t eventQueue;
@end

// Convert a block decision to the corresponding allow decision, preserving the rule type.
//
// The result is not merely a label: the caller assigns it to cd.decision and the action is
// formulated from (SNTEventStateAllow & cd.decision), so mapping a state to an allow here
// authorizes the execution.
static SNTEventState BlockToAllowDecision(SNTEventState blockDecision) {
  switch (blockDecision) {
    case SNTEventStateBlockUnknown: return SNTEventStateAllowUnknown;
    case SNTEventStateBlockBinary: return SNTEventStateAllowBinary;
    case SNTEventStateBlockCertificate: return SNTEventStateAllowCertificate;
    case SNTEventStateBlockScope: return SNTEventStateAllowScope;
    case SNTEventStateBlockTeamID: return SNTEventStateAllowTeamID;
    case SNTEventStateBlockSigningID: return SNTEventStateAllowSigningID;
    case SNTEventStateBlockCDHash: return SNTEventStateAllowCDHash;
    case SNTEventStateBlockCELFallback: return SNTEventStateAllowCELFallback;
    case SNTEventStateBlockLongPath: return SNTEventStateAllowUnknown;  // No direct equivalent
    default:
      // No allow counterpart, so do not invent one: returning the block state unchanged
      // leaves the SNTEventStateAllow bit clear and denies.
      return blockDecision;
  }
}

// Returns true if two processes execute the same binary.
//   * Strict: when both are CdhashStrictlyEnforced the kernel-reported cdhash is
//     authoritative (the kernel guarantees it binds to executed content).
//   * Otherwise: prefer a SHA-256 comparison when both hashes are known. Santa
//     computes a SHA-256 when authorizing each exec; the target's is `bSHA256`
//     (cd.sha256) and the source's is read back from SNTDecisionCache by the
//     caller. SHA-256 binds to content, which is stronger than (dev, ino)
//     against inode reuse. Fall back to (dev, ino) when a hash is unavailable.
static bool SameBinary(const es_process_t* a, NSString* aSHA256, const es_process_t* b,
                       NSString* bSHA256) {
  if (santa::CdhashStrictlyEnforced(a->codesigning_flags) &&
      santa::CdhashStrictlyEnforced(b->codesigning_flags)) {
    return memcmp(a->cdhash, b->cdhash, CS_CDHASH_LEN) == 0;
  }
  if (aSHA256.length > 0 && bSHA256.length > 0) {
    return [aSHA256 isEqualToString:bSHA256];
  }
  return a->executable->stat.st_dev == b->executable->stat.st_dev &&
         a->executable->stat.st_ino == b->executable->stat.st_ino;
}

@implementation SNTExecutionController {
  LogExecutionBlock _logger;
  std::shared_ptr<TTYWriter> _ttyWriter;
  std::unique_ptr<SantaCache<std::pair<pid_t, int>, bool>> _procSignalCache;

  // Cache of TouchID approvals: SHA-256 (as std::string) -> timestamp (nanoseconds since boot)
  // Note: We use std::string instead of NSString* because SantaCache uses == for key comparison,
  // which would compare pointer addresses for NSString*, not string contents.
  std::unique_ptr<SantaCache<std::string, uint64_t>> _touchIDApprovalCache;

  std::shared_ptr<santa::santad::process_tree::ProcessTree> _processTree;
  std::shared_ptr<santa::SandboxExpectations> _sandboxExpectations;

  // Set of (pid, pidversion) of processes Santa authorized as sandboxed seatbelt
  // processes. Because the OS sandbox is irreversible, membership implies the
  // process is still sandboxed; it is used to relax the seatbelt requirement
  // when such a process re-execs the same binary. Keyed like _procSignalCache;
  // stale entries from exited processes are harmless because (pid, pidversion)
  // is globally unique and never recurs.
  std::unique_ptr<SantaCache<std::pair<pid_t, int>, bool>> _sandboxedSeatbeltProcs;

  // The evaluation time every CEL activation this controller builds is given,
  // which is what policy_for_range() judges its windows against.
  std::function<absl::Time()> _celNow;
}

#pragma mark Initializers

- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable
                       eventTable:(SNTEventTable*)eventTable
                    notifierQueue:(SNTNotificationQueue*)notifierQueue
                       syncdQueue:(SNTSyncdQueue*)syncdQueue
                           logger:(LogExecutionBlock)logger
                        ttyWriter:(std::shared_ptr<TTYWriter>)ttyWriter
                  policyProcessor:(SNTPolicyProcessor*)policyProcessor
              processControlBlock:(santa::ProcessControlBlock)processControlBlock
                      processTree:
                          (std::shared_ptr<santa::santad::process_tree::ProcessTree>)processTree
              sandboxExpectations:(std::shared_ptr<santa::SandboxExpectations>)sandboxExpectations
                   timedRuleKills:(SNTTimedRuleKills*)timedRuleKills
                  believableClock:(SNTBelievableClock*)believableClock {
  self = [super init];
  if (self) {
    _ruleTable = ruleTable;
    _eventTable = eventTable;
    _notifierQueue = notifierQueue;
    _syncdQueue = syncdQueue;
    _logger = logger;
    _ttyWriter = std::move(ttyWriter);
    _policyProcessor = policyProcessor;
    _procSignalCache = std::make_unique<SantaCache<std::pair<pid_t, int>, bool>>(100000);
    _touchIDApprovalCache = std::make_unique<SantaCache<std::string, uint64_t>>(100);
    _sandboxedSeatbeltProcs = std::make_unique<SantaCache<std::pair<pid_t, int>, bool>>(100000);
    _processControlBlock = processControlBlock;
    _processTree = std::move(processTree);
    _sandboxExpectations = std::move(sandboxExpectations);
    _timedRuleKills = timedRuleKills;

    // Built once: a time window must be judged against the believable clock, or
    // a system clock moved backwards would re-open one that has closed.
    if (believableClock) {
      _celNow = [believableClock] {
        return absl::UnixEpoch() + absl::Seconds([believableClock now].timeIntervalSince1970);
      };
    } else {
      // Only tests reach this; the daemon always has a clock.
      LOGE(@"No believable clock: CEL time windows will be evaluated against the system clock, "
           @"which a clock change can move");
      _celNow = absl::Now;
    }

    _eventQueue =
        dispatch_queue_create("com.northpolesec.santa.daemon.event_upload", DISPATCH_QUEUE_SERIAL);

    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[MOLCodesignChecker alloc] initWithSelf];

    SNTMetricSet* metricSet = [SNTMetricSet sharedInstance];
    _events = [metricSet counterWithName:@"/santa/events"
                              fieldNames:@[ @"action_response" ]
                                helpText:@"Events processed by Santa per response"];
  }
  return self;
}

/// Records the kill this decision carries, if any, for the process `token` names.
/// Called only from the paths where the execution actually proceeds.
- (void)recordTimedRuleKillForDecision:(SNTCachedDecision*)cd process:(audit_token_t)token {
  if (!cd.timedRuleKillDeadline) {
    return;
  }
  [self.timedRuleKills recordKillForDecision:cd process:token];
}

- (void)incrementEventCounters:(SNTEventState)eventType {
  const NSString* eventTypeStr;

  switch (eventType) {
    case SNTEventStateBlockBinary: eventTypeStr = kBlockBinary; break;
    case SNTEventStateAllowBinary: eventTypeStr = kAllowBinary; break;
    case SNTEventStateAllowLocalBinary: eventTypeStr = kAllowLocalBinary; break;
    case SNTEventStateBlockCertificate: eventTypeStr = kBlockCertificate; break;
    case SNTEventStateAllowCertificate: eventTypeStr = kAllowCertificate; break;
    case SNTEventStateBlockTeamID: eventTypeStr = kBlockTeamID; break;
    case SNTEventStateAllowTeamID: eventTypeStr = kAllowTeamID; break;
    case SNTEventStateBlockSigningID: eventTypeStr = kBlockSigningID; break;
    case SNTEventStateAllowSigningID: eventTypeStr = kAllowSigningID; break;
    case SNTEventStateBlockCDHash: eventTypeStr = kBlockCDHash; break;
    case SNTEventStateAllowCDHash: eventTypeStr = kAllowCDHash; break;
    case SNTEventStateBlockScope: eventTypeStr = kBlockScope; break;
    case SNTEventStateAllowScope: eventTypeStr = kAllowScope; break;
    case SNTEventStateBlockUnknown: eventTypeStr = kBlockUnknown; break;
    case SNTEventStateAllowUnknown: eventTypeStr = kAllowUnknown; break;
    case SNTEventStateAllowCompilerBinary: eventTypeStr = kAllowCompilerBinary; break;
    case SNTEventStateAllowCompilerCDHash: eventTypeStr = kAllowCompilerCDHash; break;
    case SNTEventStateAllowCompilerSigningID: eventTypeStr = kAllowCompilerSigningID; break;
    case SNTEventStateAllowTransitive: eventTypeStr = kAllowTransitive; break;
    case SNTEventStateBlockLongPath: eventTypeStr = kBlockLongPath; break;
    case SNTEventStateBlockCELFallback: eventTypeStr = kBlockCELFallback; break;
    case SNTEventStateBlockBinaryMismatch: eventTypeStr = kBlockBinaryMismatch; break;
    case SNTEventStateAllowCELFallback: eventTypeStr = kAllowCELFallback; break;
    case SNTEventStateAllowPlatform: eventTypeStr = kAllowPlatform; break;
    default: eventTypeStr = kUnknownEventState; break;
  }

  [_events incrementForFieldValues:@[ (NSString*)eventTypeStr ]];
}

#pragma mark Binary Validation

- (bool)synchronousShouldProcessExecEvent:(const Message&)esMsg {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    LOGE(@"Attempt to validate unhandled event. Event type: %d", esMsg->event_type);
    [NSException
         raise:@"Invalid event type"
        format:@"synchronousShouldProcessExecEvent: Unexpected event type: %d", esMsg->event_type];
  }

  const es_process_t* targetProc = esMsg->event.exec.target;

  if (targetProc->executable->path.length > kMaxAllowedPathLength ||
      targetProc->executable->path_truncated) {
    // Store a SNTCachedDecision so that this event gets properly logged
    SNTCachedDecision* cd =
        [[SNTCachedDecision alloc] initWithEndpointSecurityFile:targetProc->executable];
    cd.decision = SNTEventStateBlockLongPath;
    cd.customMsg = [NSString stringWithFormat:@"Path exceeded max length for processing (%zu)",
                                              targetProc->executable->path.length];

    if (targetProc->team_id.data) {
      cd.teamID = [NSString stringWithUTF8String:targetProc->team_id.data];
    }

    // TODO(mlw): We should be able to grab signing info to have more-enriched log messages in the
    // future. The code to do this should probably be abstracted from the SNTPolicyProcessor.

    [[SNTDecisionCache sharedCache] cacheDecision:cd];

    return NO;
  }

  // An SNTCachedDecision will be created later on during full processing
  return YES;
}

// Returns YES if `instigator` is, or descends via fork/exec from, a process
// Santa authorized as a sandboxed seatbelt process. The OS sandbox is inherited
// by all descendants, so a process that forked — possibly several times, e.g.
// the classic double-fork daemonization — from a recorded sandboxed seatbelt
// process is itself sandboxed even though its own (pid, pidversion) was never
// recorded. The process tree's parent chain is held by shared_ptr, so the
// ancestry remains walkable even after intermediate ancestors exit.
- (BOOL)isSandboxedSeatbeltDescendant:(const es_process_t*)instigator {
  // Fast path / fallback when the process tree is unavailable: the instigator
  // itself was recorded (a direct self-exec with no intervening fork).
  if (_sandboxedSeatbeltProcs->get(
          std::make_pair(audit_token_to_pid(instigator->audit_token),
                         audit_token_to_pidversion(instigator->audit_token)))) {
    return YES;
  }

  if (!_processTree) {
    return NO;
  }

  auto proc = _processTree->Get(santa::santad::process_tree::Pid{
      .pid = audit_token_to_pid(instigator->audit_token),
      .pidversion = (uint64_t)audit_token_to_pidversion(instigator->audit_token)});
  if (!proc) {
    return NO;
  }

  // RootSlice walks from the process up to the root (it includes the process
  // itself as the first element).
  for (const auto& ancestor : _processTree->RootSlice(*proc)) {
    if (_sandboxedSeatbeltProcs->get(
            std::make_pair(ancestor->pid_.pid, (int)ancestor->pid_.pidversion))) {
      return YES;
    }
  }
  return NO;
}

// Returns YES if `instigator` is executing the same binary as `target`. For
// strictly cdhash-enforced binaries the cdhash is authoritative, so the
// (relatively expensive) source-hash lookup is skipped. Otherwise the SHA-256
// Santa computed for the instigator's image is read back from SNTDecisionCache
// and compared against the target's. A recorded hash whose identity was never
// confirmed is skipped: it describes a different file.
- (BOOL)isSameBinaryAsInstigator:(const es_process_t*)instigator
                          target:(const es_process_t*)target
                    targetSHA256:(NSString*)targetSHA256 {
  if (santa::CdhashStrictlyEnforced(instigator->codesigning_flags)) {
    return SameBinary(instigator, nil, target, targetSHA256);
  }

  SNTCachedDecision* instigatorCd = [[SNTDecisionCache sharedCache]
      cachedDecisionForVnode:SantaVnode::VnodeForFile(instigator->executable)];
  // Not fail-closed: SameBinary does not reject a nil hash, it falls back to the
  // kernel-reported identity of both processes.
  NSString* instigatorSHA256 = instigatorCd.identityMismatched ? nil : instigatorCd.sha256;
  return SameBinary(instigator, instigatorSHA256, target, targetSHA256);
}

- (void)forgetSandboxedSeatbeltProc:(const audit_token_t&)token {
  _sandboxedSeatbeltProcs->remove(
      std::make_pair(audit_token_to_pid(token), audit_token_to_pidversion(token)));
}

// Whether the file on disk presents the same signed identity the kernel reported
// for the image it loaded.
//
// Only a qualified identity counts: a signing identifier alone is chosen freely
// by whoever signed, so it must be qualified by a team identifier or platform
// status -- the same form Santa treats as an identity everywhere else.
//
// An absent value on any side is never a match. CS_SIGNED and CS_VALID are set
// for signatures carrying no team identifier, so the presence checks below are
// not implied by the flags check.
static BOOL SignedIdentityMatchesReported(const es_process_t* targetProc,
                                          MOLCodesignChecker* csInfo) {
  if (!(targetProc->codesigning_flags & CS_SIGNED) || !(targetProc->codesigning_flags & CS_VALID)) {
    return NO;
  }

  if (targetProc->signing_id.length == 0 || csInfo.signingID.length == 0 ||
      santa::StringTokenToStringView(targetProc->signing_id) !=
          santa::NSStringToUTF8StringView(csInfo.signingID)) {
    return NO;
  }

  if (targetProc->team_id.length > 0 && csInfo.teamID.length > 0) {
    return santa::StringTokenToStringView(targetProc->team_id) ==
           santa::NSStringToUTF8StringView(csInfo.teamID);
  }

  // Reached by system code carrying no team identifier. Live, not vestigial:
  // cryptex-resident binaries are system protected but sit on the Preboot
  // device, which SNTFileInfo's zero-syscall path excludes.
  return targetProc->is_platform_binary && csInfo.platformBinary;
}

// Returns YES when the decision grants compiler status
static BOOL DecisionIsCompiler(SNTEventState decision) {
  return decision == SNTEventStateAllowCompilerBinary ||
         decision == SNTEventStateAllowCompilerSigningID ||
         decision == SNTEventStateAllowCompilerCDHash;
}

- (void)validateExecEvent:(const Message&)esMsg
           cachedDecision:(SNTCachedDecision*)existingDecision
               postAction:(bool (^)(SNTAction, SNTCachedDecision*))postAction {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    // Programming error. Bail.
    LOGE(@"Attempt to validate non-EXEC event. Event type: %d", esMsg->event_type);
    [NSException
         raise:@"Invalid event type"
        format:@"validateExecEvent:postAction: Unexpected event type: %d", esMsg->event_type];
  }

  SNTConfigurator* config = [SNTConfigurator configurator];
  SNTConfigState* configState = [[SNTConfigState alloc] initWithConfig:config];

  const es_process_t* targetProc = esMsg->event.exec.target;

  // A carried-over decision is reused to skip recomputing identity. If that
  // identity was never confirmed, it cannot stand in for this execution's.
  // Cleared unconditionally, not just when this execution is itself
  // unconfirmed: the restrictions on the evaluation that produced these values
  // do not travel with them.
  if (unlikely(existingDecision.identityMismatched)) {
    existingDecision = nil;
  }

  // Get info about the file. If we can't get this info, respond appropriately and log an error.
  NSError* fileInfoError;
  SNTFileInfo* binInfo = [[SNTFileInfo alloc] initWithEndpointSecurityFile:targetProc->executable
                                                                     error:&fileInfoError];
  if (unlikely(!binInfo)) {
    // The initializer can return nil after establishing a mismatch. That is not
    // the same condition as being unable to read a file, so it must not be
    // routed through failClosed.
    if (fileInfoError.code == SNTErrorCodeIdentityMismatch) {
      LOGE(@"Failed to confirm identity of %@ and denying action",
           @(targetProc->executable->path.data));
      SNTCachedDecision* cd = [self mismatchDecisionForProcess:targetProc configState:configState];
      [self denyAndReportEarlyDenialForDecision:cd
                                        binInfo:binInfo
                                     targetProc:targetProc
                                          esMsg:esMsg
                                    configState:configState
                                     postAction:postAction];
      return;
    }

    if (config.failClosed) {
      LOGE(@"Failed to read file %@: %@ and denying action", @(targetProc->executable->path.data),
           fileInfoError.localizedDescription);
      postAction(SNTActionRespondDeny, nil);
      [self.events incrementForFieldValues:@[ (NSString*)kDenyNoFileInfo ]];
    } else {
      LOGE(@"Failed to read file %@: %@ but allowing action", @(targetProc->executable->path.data),
           fileInfoError.localizedDescription);
      postAction(SNTActionRespondAllow, nil);
      [self.events incrementForFieldValues:@[ (NSString*)kAllowNoFileInfo ]];
    }
    return;
  }

  // The stat the event carried did not describe the file that was opened, so
  // every content-derived value below describes a different file. Proceed only
  // when the file on disk still presents the signing vendor the kernel
  // reported, keeping the evaluation within a vendor an administrator has
  // already made a policy statement about.
  BOOL identityMismatched = binInfo.identityVerification == SNTFileInfoIdentityMismatch;
  if (unlikely(identityMismatched)) {
    MOLCodesignChecker* csInfo = [binInfo codesignCheckerWithError:NULL];
    if (!SignedIdentityMatchesReported(targetProc, csInfo)) {
      // Denied irrespective of client mode, including Monitor: this is a
      // tampering condition, and Santa already responds to those without
      // consulting the mode. See SNTEndpointSecurityTamperResistance.
      SNTCachedDecision* cd = [self mismatchDecisionForProcess:targetProc configState:configState];
      [self denyAndReportEarlyDenialForDecision:cd
                                        binInfo:binInfo
                                     targetProc:targetProc
                                          esMsg:esMsg
                                    configState:configState
                                     postAction:postAction];
      return;
    }
    // Vendor matches. Identity carried by a decision from a previous evaluation
    // describes a different file, so it cannot be reused for this one.
    existingDecision = nil;
  }

  // TODO(markowsky): Maybe add a metric here for how many large executables we're seeing.
  // if (binInfo.fileSize > SomeUpperLimit) ...

  // When re-evaluating with a cached decision, use the pre-computed signing
  // metadata to avoid expensive codesign verification.
  ActivationCallbackBlock activationBlock =
      existingDecision ? santa::CreateCELActivationBlock(
                             esMsg, existingDecision.rawSigningID, existingDecision.teamID,
                             existingDecision.platformBinary, existingDecision.signingTime,
                             existingDecision.secureSigningTime, existingDecision.rawEntitlements,
                             _processTree, _celNow)
                       : santa::CreateCELActivationBlock(
                             esMsg, [binInfo codesignCheckerWithError:NULL], _processTree, _celNow);

  cpu_type_t imageCPUType = esMsg->version >= 6 ? esMsg->event.exec.image_cputype : CPU_TYPE_ANY;
  SNTCachedDecision* cd = [self.policyProcessor decisionForFileInfo:binInfo
                                                      targetProcess:targetProc
                                                       imageCPUType:imageCPUType
                                                        configState:configState
                                                 activationCallback:activationBlock
                                                     cachedDecision:existingDecision];

  cd.codesigningFlags = targetProc->codesigning_flags;
  cd.vnodeId = SantaVnode::VnodeForFile(targetProc->executable);

  if (unlikely(identityMismatched)) {
    cd.identityMismatched = YES;
    // Matched to the event by signing vendor only, so the result applies to
    // this invocation alone.
    cd.cacheable = NO;
    // Compiler status is a statement about a specific file, so it cannot follow
    // from an evaluation of a different one. Clearing the bits matters:
    // cacheable = NO alone still yields a compiler action at the mapping below.
    if (DecisionIsCompiler(cd.decision)) {
      switch (cd.decision) {
        case SNTEventStateAllowCompilerBinary: cd.decision = SNTEventStateAllowBinary; break;
        case SNTEventStateAllowCompilerSigningID: cd.decision = SNTEventStateAllowSigningID; break;
        case SNTEventStateAllowCompilerCDHash: cd.decision = SNTEventStateAllowCDHash; break;
        default: break;
      }
    }
    NSString* extra = @"Executable identity confirmed by signing vendor only";
    cd.decisionExtra =
        cd.decisionExtra ? [NSString stringWithFormat:@"%@; %@", cd.decisionExtra, extra] : extra;
  }

  // Seatbelt expectation check: the sandboxed exec is authorized iff
  // santactl pre-registered an expectation for the caller's audit token,
  // and the expectation matches the exec target under one of two modes:
  //   * Strict (CS_VALID & (CS_HARD|CS_KILL)): the kernel refuses or kills
  //     on any page-hash mismatch (verified against XNU cs_invalid_page),
  //     so cdhash is a strong binding to executed content.
  //   * Fallback: the kernel does not enforce page integrity, so binary
  //     identity is verified via (dev, ino, sha256). `(dev, ino)` binds
  //     the exec'd vnode to the inode santactl pinned; sha256 binds
  //     content at santad's read time to santactl's hash. This matches
  //     Santa's posture for every other rule state (see SNTPolicyProcessor).
  // No expectation -> deny, unless the transitive self-exec relaxation below
  // applies.
  //
  // Transitive sandbox relaxation: the OS sandbox is transitive and
  // irreversible, so a process Santa already authorized as a sandboxed seatbelt
  // process (recorded in _sandboxedSeatbeltProcs) — or any process that forked
  // from it, possibly several times (e.g. double-fork daemonization), and is
  // still running that same binary's image — stays under the profile originally
  // applied for that binary. Such a re-exec carries no expectation (santactl is
  // not involved), so relax the requirement for it. Scope is limited to a
  // same-binary self-exec by a sandboxed descendant: a different
  // seatbelt-required binary would inherit an unrelated profile and must still
  // go through santactl. Membership can only be seeded by first passing the
  // expectation check, so this introduces no new trust boundary. See
  // -isSandboxedSeatbeltDescendant: for the fork-aware ancestry walk.
  //
  // Cache safety: flipping the decision here must not let a later exec of
  // the same vnode be auto-allowed without re-checking its expectation.
  // SNTPolicyProcessor sets cd.cacheable=NO for every SEATBELT rule hit,
  // so the action below becomes SNTActionRespondAllowNoCache rather than
  // SNTActionRespondAllow.
  if (cd.seatbeltRequired) {
    // A profile is registered for a specific file, so an expectation match
    // against an unconfirmed read does not establish that the loaded image is
    // the one it was registered for. Not redundant with the comparisons that
    // follow: the strict one uses kernel-reported values, the fallback does not.
    //
    // It cannot live in the identity gate earlier in this method:
    // cd.seatbeltRequired is only known once rule evaluation has run.
    if (unlikely(identityMismatched)) {
      cd.decision = SNTEventStateBlockBinaryMismatch;
      cd.cacheable = NO;
      cd.decisionExtra = @"Sandbox profile requires a confirmed executable identity";
      [self denyAndReportEarlyDenialForDecision:cd
                                        binInfo:binInfo
                                     targetProc:targetProc
                                          esMsg:esMsg
                                    configState:configState
                                     postAction:postAction];
      return;
    }

    auto maybeExp = _sandboxExpectations->Consume(esMsg->process->audit_token);
    bool authorized = false;

    if (maybeExp) {
      if (santa::CdhashStrictlyEnforced(targetProc->codesigning_flags)) {
        authorized = memcmp(maybeExp->cdhash.data(), targetProc->cdhash, CS_CDHASH_LEN) == 0;
      } else {
        authorized = maybeExp->dev == targetProc->executable->stat.st_dev &&
                     maybeExp->ino == targetProc->executable->stat.st_ino && cd.sha256.length > 0 &&
                     !maybeExp->sha256.empty() &&
                     santa::NSStringToUTF8String(cd.sha256) == maybeExp->sha256;
      }

      if (!authorized) {
        // Intentionally opaque: distinguishing which specific check failed
        // would give an attacker a tuning signal.
        cd.decisionExtra = @"Seatbelt expectation verification failed";
      }
    } else if ([self isSandboxedSeatbeltDescendant:esMsg->process] &&
               [self isSameBinaryAsInstigator:esMsg->process
                                       target:targetProc
                                 targetSHA256:cd.sha256]) {
      authorized = true;
      cd.decisionExtra = @"Seatbelt requirement relaxed: sandboxed self-exec";
    } else {
      cd.decisionExtra = @"Binary requires seatbelt sandbox but no expectation was registered";
    }

    if (authorized) {
      cd.decision = BlockToAllowDecision(cd.decision);
      // Record the now-sandboxed target so it may later re-exec itself. Covers
      // both the expectation path (santactl -> binary) and the relaxed path.
      _sandboxedSeatbeltProcs->set(
          std::make_pair(audit_token_to_pid(targetProc->audit_token),
                         audit_token_to_pidversion(targetProc->audit_token)),
          true);
    }
  }

  // When the kernel kills the target for code signature invalidity, this exec
  // cannot succeed no matter what Santa decides. The policy still applies and
  // the block is still logged and uploaded, but no UI is shown: the user would
  // otherwise blame Santa for a kill it didn't cause.
  if (santa::KernelWillKillForCodeSigning(targetProc->codesigning_flags, imageCPUType) &&
      (cd.decision & SNTEventStateAllow) == 0) {
    cd.silentBlockGUI = YES;
    cd.silentBlockTTY = YES;
    cd.holdAndAsk = NO;
    NSString* extra = @"Kernel will kill the process for code signature invalidity; "
                      @"suppressing block UI";
    cd.decisionExtra =
        cd.decisionExtra ? [NSString stringWithFormat:@"%@; %@", cd.decisionExtra, extra] : extra;
    LOGW(@"Denying %@ but suppressing block UI: the kernel will kill this process for code "
         @"signature invalidity (codesigning_flags=0x%x). The exec would have failed regardless of "
         @"Santa's decision.",
         santa::StringTokenToNSString(targetProc->executable->path), targetProc->codesigning_flags);
  }

  // Formulate an initial action from the decision.
  SNTAction action = (SNTEventStateAllow & cd.decision)
                         ? (cd.cacheable ? SNTActionRespondAllow : SNTActionRespondAllowNoCache)
                         : SNTActionRespondDeny;

  // Save decision details for logging the execution later.  For transitive rules, we also use
  // the shasum stored in the decision details to update the rule's timestamp whenever an
  // ACTION_NOTIFY_EXEC message related to the transitive rule is received.
  [[SNTDecisionCache sharedCache] cacheDecision:cd];

  // Upgrade the action to a compiler action when appropriate, because we want the
  // kernel to track this information in its decision cache. A compiler decision is
  // always already an allow, so this only ever refines an allow.
  //
  // Cacheability must survive the upgrade. A compiler decision from a non-cacheable
  // evaluation, such as a CEL rule that read argv or the environment, authorizes
  // only this invocation. Caching it as a terminal entry would let a later
  // execution of the same vnode inherit both the allow and the compiler status
  // without re-evaluating the rule.
  if (DecisionIsCompiler(cd.decision)) {
    action = cd.cacheable ? SNTActionRespondAllowCompiler : SNTActionRespondAllowCompilerNoCache;
  }

  pid_t newProcPid = audit_token_to_pid(targetProc->audit_token);
  BOOL stoppedProc = false;
  std::pair<pid_t, int> pidAndVersion =
      std::make_pair(newProcPid, audit_token_to_pidversion(targetProc->audit_token));

  // Check TouchID approval cache before prompting - only if cooldown was specified
  if (cd.holdAndAsk && cd.sha256 && cd.touchIDCooldownMinutes != nil) {
    uint64_t cooldownMinutes = [cd.touchIDCooldownMinutes unsignedLongLongValue];
    if (cooldownMinutes > 0) {
      uint64_t cachedTimestamp = _touchIDApprovalCache->get(santa::NSStringToUTF8String(cd.sha256));
      if (cachedTimestamp > 0) {
        uint64_t expiryTime = cachedTimestamp + (cooldownMinutes * 60 * NSEC_PER_SEC);
        if (GetCurrentUptime() < expiryTime) {
          // Cache hit - skip TouchID prompt
          cd.holdAndAsk = NO;
          cd.decisionExtra = @"TouchID Cached";
          cd.decision = BlockToAllowDecision(cd.decision);
          action = (cd.cacheable ? SNTActionRespondAllow : SNTActionRespondAllowNoCache);
          // Update the cached decision with the new state
          [[SNTDecisionCache sharedCache] cacheDecision:cd];
        }
      }
    }
  }

  // Only allow a user in standalone mode to override a block if an
  // explicit block rule is not set when using a sync service.
  if (cd.holdAndAsk) {
    // In standalone mode we want hold off on making a decision until the user has had a chance to
    // approve. ES won't let us do this, we'd hit the response deadline. Instead, we suspend the
    // new process to stop the binary from executing but we respond to ES with an allow decision.
    // If the user authorizes execution we resume the process. Any attempts to resume the paused
    // binary outside of the auth flow will be blocked.
    _procSignalCache->set(pidAndVersion, true);
    stoppedProc = self.processControlBlock(newProcPid, ProcessControl::Suspend);
    postAction(SNTActionRespondHold, cd);
  } else {
    // Respond with the decision.
    postAction(action, cd);

    // Only recorded for an execution that proceeds: an in-window policy that
    // blocks records nothing, and a held exec records it from the reply below.
    if (ACTION_IS_ALLOW(action)) {
      [self recordTimedRuleKillForDecision:cd process:targetProc->audit_token];
    }
  }

  // Increment metric counters
  [self incrementEventCounters:cd.decision];

  // Log to database if necessary.
  if (config.enableAllEventUpload ||
      (cd.decision == SNTEventStateAllowUnknown && !config.disableUnknownEventUpload) ||
      cd.auditReturn || (cd.decision & SNTEventStateAllow) == 0) {
    SNTStoredExecutionEvent* se = [self storedExecutionEventForDecision:cd
                                                                binInfo:binInfo
                                                             targetProc:targetProc
                                                                  esMsg:esMsg
                                                                    pid:newProcPid];
    // Only store events if there is a sync server configured.
    if (config.syncBaseURL) {
      dispatch_async(_eventQueue, ^{
        [self.eventTable addStoredEvent:se];
      });
    }

    // If binary was blocked, do the needful
    if (!ACTION_IS_ALLOW(action)) {
      NotificationReplyBlock replyBlock = nil;

      // holdAndAsk (TouchID) is never combined with a silent block, so its reply
      // block is built unconditionally here and only fires via the GUI below.
      if (cd.holdAndAsk) {
        // Copy the esMsg to ensure that when the passed-in ref goes away
        // we're still holding a valid Message object inside the replyBlock.
        __block Message esMsgCopy(esMsg);
        replyBlock = ^(BOOL authenticated) {
          LOGD(@"User responded to block event for %@ with authenticated: %d", se.filePath,
               authenticated);
          // The window closed while the prompt was up: its kill is already due,
          // so the process never runs.
          BOOL allowed = authenticated;
          if (authenticated && cd.timedRuleKillDeadline) {
            NSDate* now =
                [NSDate dateWithTimeIntervalSince1970:absl::ToDoubleSeconds(self->_celNow() -
                                                                            absl::UnixEpoch())];
            allowed = [cd.timedRuleKillDeadline compare:now] == NSOrderedDescending;
          }
          if (allowed) {
            if (cd.decisionClientMode == SNTClientModeStandalone &&
                cd.decision == SNTEventStateBlockUnknown) {
              // Create a rule for the binary that was allowed by the user in
              // standalone mode and notify the sync service.
              [self createRuleForStandaloneModeEvent:se identityMismatched:cd.identityMismatched];
            }

            // Update decision to reflect that it was allowed via TouchID,
            // preserving the rule type (e.g., BlockSigningID -> AllowSigningID)
            cd.decision = BlockToAllowDecision(cd.decision);
            cd.decisionExtra = @"TouchID Approved";

            // Cache the TouchID approval so subsequent executions within the cooldown period
            // don't require re-authorization - only if cooldown was specified and > 0
            // The cooldown cache is keyed on the content hash, which names the
            // file that was read. Skip it for an unconfirmed read, so a later
            // execution is not matched against someone else's approval.
            if (cd.sha256 && !cd.identityMismatched && cd.touchIDCooldownMinutes != nil &&
                [cd.touchIDCooldownMinutes unsignedLongLongValue] > 0) {
              std::string sha256Key = santa::NSStringToUTF8String(cd.sha256);
              self->_touchIDApprovalCache->set(sha256Key, GetCurrentUptime());
            }

            if (stoppedProc) {
              _ttyWriter->Write(targetProc, @"Authorized, allowing execution\n---\n\n");
            }

            // Allow the binary to begin running.
            self.processControlBlock(newProcPid, ProcessControl::Resume);

            // The execution is allowed, so record it whatever the suspend or
            // resume reported: a hold that could not stop the process left it
            // running, a resume that failed left it stopped, and SIGKILL takes a
            // stopped process at the deadline.
            [self recordTimedRuleKillForDecision:cd process:targetProc->audit_token];
          } else {
            // Decision stays as-is; only the extra field says why.
            cd.decisionExtra = authenticated ? @"TouchID Approved After Expiry" : @"TouchID Denied";

            // Nothing approved this execution in time, so kill the stopped process.
            if (stoppedProc) {
              _ttyWriter->Write(
                  targetProc,
                  authenticated ? @"Authorized after the window closed, denying execution\n---\n\n"
                                : @"Authorization not given, denying execution\n---\n\n");
            }
            self.processControlBlock(newProcPid, ProcessControl::Kill);
          }

          // Clear holdAndAsk and update cache so it's recorded as a final decision
          cd.holdAndAsk = NO;
          [[SNTDecisionCache sharedCache] cacheDecision:cd];

          // Log the execution event (since NOTIFY was suppressed during holdAndAsk)
          self->_logger(std::move(esMsgCopy));

          _procSignalCache->remove(pidAndVersion);
          postAction(allowed ? SNTActionHoldAllowed : SNTActionHoldDenied, cd);
        };
      }

      [self reportBlockedExecutionEvent:se
                               decision:cd
                                binInfo:binInfo
                             targetProc:targetProc
                            configState:configState
                            stoppedProc:stoppedProc
                             replyBlock:replyBlock];
    }
  }
}

// Decision for an execution denied because the file's identity could not be
// confirmed. Everything here is kernel-reported, so it is available even when
// the file could not be read; content-derived values are the caller's to add.
- (SNTCachedDecision*)mismatchDecisionForProcess:(const es_process_t*)targetProc
                                     configState:(SNTConfigState*)configState {
  SNTCachedDecision* cd =
      [[SNTCachedDecision alloc] initWithEndpointSecurityFile:targetProc->executable];
  cd.decision = SNTEventStateBlockBinaryMismatch;
  cd.decisionClientMode = configState.clientMode;
  cd.cacheable = NO;
  cd.identityMismatched = YES;
  cd.codesigningFlags = targetProc->codesigning_flags;
  cd.teamID = santa::StringTokenToNSString(targetProc->team_id);
  cd.signingID = santa::StringTokenToNSString(targetProc->signing_id);
  cd.decisionExtra = @"Executable identity could not be confirmed";
  return cd;
}

// Denies an execution that returns before the common reporting path at the end
// of -validateExecEvent:cachedDecision:postAction:, then reports it.
//
// The order matches the common path, and both halves of it matter. Cache the
// decision, respond, then report. Reporting is unbounded work and must never
// precede the response. Caching precedes the response because ES delivers
// NOTIFY_EXEC even for a denied exec and that telemetry recovers the decision
// by vnode.
//
// SNTActionRespondDenyOnce, never SNTActionRespondDeny: the latter is retained
// for the deny cache interval and would apply to later executions of the vnode.
- (void)denyAndReportEarlyDenialForDecision:(SNTCachedDecision*)cd
                                    binInfo:(SNTFileInfo*)binInfo
                                 targetProc:(const es_process_t*)targetProc
                                      esMsg:(const Message&)esMsg
                                configState:(SNTConfigState*)configState
                                 postAction:(bool (^)(SNTAction, SNTCachedDecision*))postAction {
  [[SNTDecisionCache sharedCache] cacheDecision:cd];
  postAction(SNTActionRespondDenyOnce, cd);

  // Report-only: this names the file that was read, not the image the kernel
  // loaded, which is why this denies. Hashing is proportional to file size, so
  // it waits for the response.
  //
  // It mutates the decision already in SNTDecisionCache, which is how the
  // telemetry picks the hash up. Nothing authorizes on it: DenyOnce leaves no
  // AuthResultCache entry to reuse, and readers that could act on it test
  // identityMismatched first.
  if (!cd.sha256) {
    cd.sha256 = binInfo.SHA256;
  }

  [self incrementEventCounters:cd.decision];

  SNTStoredExecutionEvent* se =
      [self storedExecutionEventForDecision:cd
                                    binInfo:binInfo
                                 targetProc:targetProc
                                      esMsg:esMsg
                                        pid:audit_token_to_pid(targetProc->audit_token)];

  SNTConfigurator* config = [SNTConfigurator configurator];
  if (config.syncBaseURL) {
    dispatch_async(_eventQueue, ^{
      [self.eventTable addStoredEvent:se];
    });
  }

  [self reportBlockedExecutionEvent:se
                           decision:cd
                            binInfo:binInfo
                         targetProc:targetProc
                        configState:configState
                        stoppedProc:false
                         replyBlock:nil];
}

// Builds the stored event describing an execution. Shared by the common
// reporting path and by the early-return denials, so both describe an
// execution the same way.
- (SNTStoredExecutionEvent*)storedExecutionEventForDecision:(SNTCachedDecision*)cd
                                                    binInfo:(SNTFileInfo*)binInfo
                                                 targetProc:(const es_process_t*)targetProc
                                                      esMsg:(const Message&)esMsg
                                                        pid:(pid_t)newProcPid {
  SNTStoredExecutionEvent* se = [[SNTStoredExecutionEvent alloc] init];
  se.occurrenceDate = [[NSDate alloc] init];
  se.fileSHA256 = cd.sha256;
  // binInfo is nil when the file could not be read at all; fall back to the
  // path the event carried so the event still identifies something.
  se.filePath = binInfo.path ?: santa::StringTokenToNSString(targetProc->executable->path);
  se.decision = cd.decision;
  se.auditReturn = cd.auditReturn;
  se.holdAndAsk = cd.holdAndAsk;
  se.silentTouchID = cd.silentTouchID;
  se.seatbeltRequired = cd.seatbeltRequired;
  se.staticRule = cd.staticRule;
  se.ruleId = cd.ruleId;

  se.signingChain = cd.certChain;
  se.teamID = cd.teamID;
  se.signingID = cd.signingID;
  se.cdhash = cd.cdhash;
  se.codesigningFlags = cd.codesigningFlags;
  se.signingStatus = cd.signingStatus;
  se.pid = @(newProcPid);
  se.ppid = @(audit_token_to_pid(targetProc->parent_audit_token));
  se.parentName = @(esMsg.ParentProcessName().c_str());
  se.entitlements = cd.entitlements;
  se.entitlementsFiltered = cd.entitlementsFiltered;
  se.secureSigningTime = cd.secureSigningTime;
  se.signingTime = cd.signingTime;

  // Bundle data
  se.fileBundleID = [binInfo bundleIdentifier];
  se.fileBundleName = [binInfo bundleName];
  se.fileBundlePath = [binInfo bundlePath];
  if ([binInfo bundleShortVersionString]) {
    se.fileBundleVersionString = [binInfo bundleShortVersionString];
  }
  if ([binInfo bundleVersion]) {
    se.fileBundleVersion = [binInfo bundleVersion];
  }

  // User data
  std::optional<std::string> user =
      santa::account::UsernameForUID(audit_token_to_ruid(targetProc->audit_token));
  if (user.has_value()) se.executingUser = @(user->c_str());
  NSArray *loggedInUsers, *currentSessions;
  [self loggedInUsers:&loggedInUsers sessions:&currentSessions];
  se.currentSessions = currentSessions;
  se.loggedInUsers = loggedInUsers;

  // Quarantine data
  se.quarantineDataURL = binInfo.quarantineDataURL;
  se.quarantineRefererURL = binInfo.quarantineRefererURL;
  se.quarantineTimestamp = binInfo.quarantineTimestamp;
  se.quarantineAgentBundleID = binInfo.quarantineAgentBundleID;

  return se;
}

// Reports an execution that was blocked: bundle hashing or an immediate sync
// upload, the TTY message, and the GUI notification. `replyBlock` is non-nil
// only for an execution being held for approval.
- (void)reportBlockedExecutionEvent:(SNTStoredExecutionEvent*)se
                           decision:(SNTCachedDecision*)cd
                            binInfo:(SNTFileInfo*)binInfo
                         targetProc:(const es_process_t*)targetProc
                        configState:(SNTConfigState*)configState
                        stoppedProc:(bool)stoppedProc
                         replyBlock:(NotificationReplyBlock)replyBlock {
  SNTConfigurator* config = [SNTConfigurator configurator];
  if (config.enableBundles && binInfo.bundle) {
    // If the binary is part of a bundle, find and hash all the related binaries in the bundle.
    // Let the GUI know hashing is needed. Once the hashing is complete the GUI will send a
    // message to santad to perform the upload logic for bundles.
    // See syncBundleEvent:relatedEvents: for more info.
    se.needsBundleHash = YES;
  } else if (config.syncBaseURL) {
    // So the server has something to show the user straight away, initiate an event
    // upload for the blocked binary rather than waiting for the next sync.
    dispatch_async(_eventQueue, ^{
      [self.syncdQueue addStoredEvent:se];
    });
  }

  if (!cd.silentBlockTTY) {
    _ttyWriter->Write(targetProc, ^NSString* {
      if (cd.holdAndAsk) {
        if (stoppedProc) {
          return @"---\n\033[1mSanta\033[0m\n\nHolding execution of this "
                 @"binary until approval is granted in the GUI...\n";
        } else {
          return @"---\n\033[1mSanta\033[0m\n\nUnable to hold execution so "
                 @"the process was killed\n---\n\n";
        }
      }

      // Let the user know what happened on the terminal
      NSAttributedString* s = [SNTBlockMessage attributedBlockMessageForEvent:se
                                                                customMessage:cd.customMsg];

      NSMutableString* msg = [NSMutableString stringWithCapacity:1024];
      // Escape sequences `\033[1m` and `\033[0m` begin/end bold lettering
      [msg appendFormat:@"\n\033[1mSanta\033[0m\n\n%@\n\n", s.string];
      [msg appendFormat:@"\033[1mReason:    \033[0m %@\n"
                        @"\033[1mPath:      \033[0m %@\n"
                        @"\033[1mIdentifier:\033[0m %@\n"
                        @"\033[1mParent:    \033[0m %@ (%@)\n\n",
                        [SNTBlockMessage blockReasonForEvent:se], se.filePath, se.fileSHA256,
                        se.parentName, se.ppid];
      NSURL* detailURL =
          [SNTBlockMessage eventDetailURLForEvent:se
                                        customURL:(cd.customURL ?: config.eventDetailURL)];
      if (detailURL) {
        [msg appendFormat:@"More info:\n%@\n", detailURL.absoluteString];
      }
      return msg;
    });
  }

  // Suppress the GUI for a silent-GUI block, but never when holding for
  // approval: a held process depends on the GUI reply to resume or be killed,
  // so it must always be shown even if the flags were somehow combined.
  if (!cd.silentBlockGUI || cd.holdAndAsk) {
    // Let the user know what happened in the GUI.
    [self.notifierQueue addEvent:se
               withCustomMessage:cd.customMsg
                       customURL:cd.customURL ?: config.eventDetailURL
           eventDetailButtonText:cd.eventDetailButtonText
                     configState:configState
                        andReply:replyBlock];
  }
}

#pragma mark Signal Validation

- (void)validateSuspendResumeEvent:(const santa::Message&)esMsg
                        postAction:(void (^)(bool))postAction {
  audit_token_t at = esMsg->event.proc_suspend_resume.target->audit_token;
  pid_t pid = audit_token_to_pid(at);
  int pidVersion = audit_token_to_pidversion(at);
  if (_procSignalCache->get(std::make_pair(pid, pidVersion))) {
    return postAction(false);
  }
  postAction(true);
}

#pragma mark Helpers

- (void)loggedInUsers:(NSArray**)users sessions:(NSArray**)sessions {
  NSMutableSet* loggedInUsers = [NSMutableSet set];
  NSMutableArray* loggedInHosts = [NSMutableArray array];

  struct utmpx* nxt;
  while ((nxt = getutxent())) {
    if (nxt->ut_type != USER_PROCESS) continue;

    NSString* userName = @(nxt->ut_user);
    NSString* sessionName;
    if (strnlen(nxt->ut_host, 1) > 0) {
      sessionName = [NSString stringWithFormat:@"%@@%s", userName, nxt->ut_host];
    } else {
      sessionName = [NSString stringWithFormat:@"%@@%s", userName, nxt->ut_line];
    }

    if (userName.length) [loggedInUsers addObject:userName];
    if (sessionName.length) [loggedInHosts addObject:sessionName];
  }
  endutxent();

  *users = [loggedInUsers allObjects];
  *sessions = [loggedInHosts copy];
}

// Creates a rule for the binary that was allowed by the user in standalone mode.
//
// `identityMismatched` gates only the identifiers derived from the file that was
// read. A signing ID is kernel-reported for the loaded image, so it names the
// right file either way; a content hash names whatever was read and must not be
// turned into a rule.
- (void)createRuleForStandaloneModeEvent:(SNTStoredExecutionEvent*)se
                      identityMismatched:(BOOL)identityMismatched {
  SNTRuleType ruleType;
  NSString* ruleIdentifier;
  SNTRuleState newRuleState;

  if (se.signingStatus == SNTSigningStatusProduction && se.signingID) {
    ruleType = SNTRuleTypeSigningID;
    ruleIdentifier = se.signingID;
    newRuleState = SNTRuleStateAllowLocalSigningID;
  } else if (se.fileSHA256 && !identityMismatched) {
    ruleType = SNTRuleTypeBinary;
    ruleIdentifier = se.fileSHA256;
    newRuleState = SNTRuleStateAllowLocalBinary;
  } else {
    LOGE(@"No appropriate identifiers available to add rule in standalone mode for %@",
         se.filePath);
    return;
  }

  NSString* commentStr = [NSString stringWithFormat:@"%@", se.filePath];

  // Add rule to allow binary same as santactl rule.
  NSError* err;
  SNTRule* newRule = [[SNTRule alloc] initWithIdentifier:ruleIdentifier
                                                   state:newRuleState
                                                    type:ruleType
                                               customMsg:nil
                                               customURL:nil
                                   eventDetailButtonText:nil
                                               timestamp:[[NSDate now] timeIntervalSince1970]
                                                 comment:commentStr
                                                 celExpr:nil
                                          seatbeltPolicy:nil
                                                  ruleId:0
                                                   error:&err];
  if (err) {
    LOGE(@"Failed to add rule in standalone mode for %@: %@", se.filePath,
         err.localizedDescription);
    return;
  }

  NSArray<NSError*>* errors;
  BOOL success = [self.ruleTable addExecutionRules:@[ newRule ]
                                       ruleCleanup:SNTRuleCleanupNone
                                            errors:&errors];
  if (errors.count > 0 || !success) {
    LOGW(@"%@ encountered while adding a rule in standalone mode for: %@:",
         success ? @"Issues" : @"Errors", se.filePath);
    for (NSError* error in errors) {
      LOGE(@"\t %@", error.localizedDescription);
    }
  }

  // TODO: Notify the sync service of the new rule.
}

- (void)flushTouchIDApprovalCache {
  _touchIDApprovalCache->clear();
}

@end
