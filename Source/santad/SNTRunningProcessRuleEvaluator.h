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

#import <Foundation/Foundation.h>

#include <bsm/libbsm.h>

@class SNTDecisionCache;
@class SNTKillRequestRunningProcess;
@class SNTKillResponse;
@class SNTRuleTable;

typedef NSArray<NSNumber*>* _Nullable (^SNTRunningProcessListBlock)(void);
typedef NSString* _Nullable (^SNTRunningProcessPathBlock)(pid_t pid);
typedef BOOL (^SNTRunningProcessAuditTokenBlock)(pid_t pid, audit_token_t* token);
typedef SNTKillResponse* _Nullable (^SNTRunningProcessKillBlock)(
    SNTKillRequestRunningProcess* request);

@interface SNTRunningProcessRuleEvaluator : NSObject

- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable decisionCache:(SNTDecisionCache*)cache;

- (void)reevaluateRunningProcesses;

#ifdef DEBUG
- (instancetype)initWithRuleTable:(SNTRuleTable*)ruleTable
                    decisionCache:(SNTDecisionCache*)cache
                 processListBlock:(SNTRunningProcessListBlock)processListBlock
                     pathForBlock:(SNTRunningProcessPathBlock)pathForBlock
                  auditTokenBlock:(SNTRunningProcessAuditTokenBlock)auditTokenBlock
                        killBlock:(SNTRunningProcessKillBlock)killBlock;
- (void)reevaluateRunningProcessesSyncForTesting;
#endif

@end
