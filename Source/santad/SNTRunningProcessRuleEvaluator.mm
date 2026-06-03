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

#import "Source/santad/SNTRunningProcessRuleEvaluator.h"

#include <libproc.h>
#include <sys/param.h>
#include <sys/qos.h>

#include <optional>
#include <vector>

#import "Source/common/AuditUtilities.h"
#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/SystemResources.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/KillingMachine.h"
#import "Source/santad/SNTDecisionCache.h"

namespace {

NSArray<NSNumber*>* RunningProcessList() {
  std::optional<std::vector<pid_t>> pids = santa::GetPidList();
  if (!pids) {
    return nil;
  }

  NSMutableArray<NSNumber*>* result = [NSMutableArray arrayWithCapacity:pids->size()];
  for (pid_t pid : *pids) {
    [result addObject:@(pid)];
  }
  return result;
}

NSString* PathForPid(pid_t pid) {
  char pathBuf[MAXPATHLEN] = {};
  if (proc_pidpath(pid, pathBuf, sizeof(pathBuf)) <= 0) {
    return nil;
  }
  return @(pathBuf);
}

BOOL RuleRequestsForceKill(SNTRule* rule) {
  if (rule.runningProcessAction != SNTRuleRunningProcessActionForceKill) {
    return NO;
  }

  switch (rule.state) {
    case SNTRuleStateBlock:
    case SNTRuleStateSilentBlock: return YES;
    default: return NO;
  }
}

struct RuleIdentifiers RuleIdentifiersForDecision(SNTCachedDecision* cd) {
  SNTRuleIdentifiers* identifiers =
      [[SNTRuleIdentifiers alloc] initWithRuleIdentifiers:{
                                                              .cdhash = cd.cdhash,
                                                              .binarySHA256 = cd.sha256,
                                                              .signingID = cd.signingID,
                                                              .certificateSHA256 = cd.certSHA256,
                                                              .teamID = cd.teamID,
                                                          }
                                         andSigningStatus:cd.signingStatus];
  return [identifiers toStruct];
}

}  // namespace

@interface SNTRunningProcessRuleEvaluator ()
@property SNTRuleTable* ruleTable;
@property SNTDecisionCache* decisionCache;
@property dispatch_queue_t queue;
@property(copy) SNTRunningProcessListBlock processListBlock;
@property(copy) SNTRunningProcessPathBlock pathForBlock;
@property(copy) SNTRunningProcessAuditTokenBlock auditTokenBlock;
@property(copy) SNTRunningProcessKillBlock killBlock;
- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable
                    decisionCache:(SNTDecisionCache*)cache
                 processListBlock:(SNTRunningProcessListBlock)processListBlock
                     pathForBlock:(SNTRunningProcessPathBlock)pathForBlock
                  auditTokenBlock:(SNTRunningProcessAuditTokenBlock)auditTokenBlock
                        killBlock:(SNTRunningProcessKillBlock)killBlock;
- (void)reevaluateRunningProcessesSync;
@end

@implementation SNTRunningProcessRuleEvaluator

- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable decisionCache:(SNTDecisionCache*)cache {
  return [self initWithRuleTable:ruleTable
      decisionCache:cache
      processListBlock:^NSArray<NSNumber*>* {
        return RunningProcessList();
      }
      pathForBlock:^NSString*(pid_t pid) {
        return PathForPid(pid);
      }
      auditTokenBlock:^BOOL(pid_t pid, audit_token_t* token) {
        return santa::AuditTokenForPid(pid, token);
      }
      killBlock:^SNTKillResponse*(SNTKillRequestRunningProcess* request) {
        return santa::KillingMachine(request);
      }];
}

- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable
                    decisionCache:(SNTDecisionCache*)cache
                 processListBlock:(SNTRunningProcessListBlock)processListBlock
                     pathForBlock:(SNTRunningProcessPathBlock)pathForBlock
                  auditTokenBlock:(SNTRunningProcessAuditTokenBlock)auditTokenBlock
                        killBlock:(SNTRunningProcessKillBlock)killBlock {
  self = [super init];
  if (self) {
    _ruleTable = ruleTable;
    _decisionCache = cache;
    _processListBlock = [processListBlock copy];
    _pathForBlock = [pathForBlock copy];
    _auditTokenBlock = [auditTokenBlock copy];
    _killBlock = [killBlock copy];
    _queue = dispatch_queue_create_with_target("com.northpolesec.santa.running-process-rules",
                                               DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL,
                                               dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
  }
  return self;
}

- (void)reevaluateRunningProcesses {
  dispatch_async(self.queue, ^{
    [self reevaluateRunningProcessesSync];
  });
}

#ifdef DEBUG
- (void)reevaluateRunningProcessesSyncForTesting {
  [self reevaluateRunningProcessesSync];
}
#endif

- (void)reevaluateRunningProcessesSync {
  NSArray<NSNumber*>* pids = self.processListBlock();
  if (!pids) {
    LOGW(@"Unable to evaluate running processes: process list unavailable");
    return;
  }

  NSUInteger evaluated = 0;
  NSUInteger matched = 0;
  NSUInteger killed = 0;
  NSUInteger failed = 0;

  for (NSNumber* pidNum in pids) {
    @autoreleasepool {
      pid_t pid = [pidNum intValue];
      if (pid == 0) {
        continue;
      }

      audit_token_t tokenBefore;
      if (!self.auditTokenBlock(pid, &tokenBefore)) {
        continue;
      }

      NSString* path = self.pathForBlock(pid);
      if (path.length == 0) {
        continue;
      }

      SNTFileInfo* fileInfo = [[SNTFileInfo alloc] initWithPath:path];
      if (!fileInfo) {
        continue;
      }

      SNTCachedDecision* cd = [self.decisionCache rehydrateAndCacheDecisionForFileInfo:fileInfo];
      if (!cd) {
        continue;
      }

      NSError* csError = nil;
      MOLCodesignChecker* csInfo = [fileInfo codesignCheckerWithError:&csError];
      cd.signingStatus =
          (csInfo || csError) ? SigningStatus(csInfo, csError) : SNTSigningStatusInvalid;

      if (cd.signingID && self.ruleTable.criticalSystemBinaries[cd.signingID]) {
        continue;
      }

      SNTRule* rule = [self.ruleTable executionRuleForIdentifiers:RuleIdentifiersForDecision(cd)];
      evaluated++;
      if (!RuleRequestsForceKill(rule)) {
        continue;
      }
      matched++;

      audit_token_t tokenAfter;
      if (!self.auditTokenBlock(pid, &tokenAfter) ||
          santa::Pidversion(tokenBefore) != santa::Pidversion(tokenAfter)) {
        continue;
      }

      SNTKillRequestRunningProcess* request =
          [[SNTKillRequestRunningProcess alloc] initWithUUID:[[NSUUID UUID] UUIDString]
                                                         pid:pid
                                                  pidversion:santa::Pidversion(tokenAfter)
                                             bootSessionUUID:[SNTSystemInfo bootSessionUUID]];
      SNTKillResponse* response = self.killBlock(request);
      if (response.error != SNTKillResponseErrorNone) {
        failed++;
        continue;
      }

      for (SNTKilledProcess* proc in response.killedProcesses) {
        if (proc.error == SNTKilledProcessErrorNone) {
          killed++;
        } else {
          failed++;
        }
      }
    }
  }

  LOGI(@"Running process rule evaluation complete. %lu evaluated, %lu matched, %lu killed, "
       @"%lu failed",
       static_cast<unsigned long>(evaluated), static_cast<unsigned long>(matched),
       static_cast<unsigned long>(killed), static_cast<unsigned long>(failed));
}

@end
