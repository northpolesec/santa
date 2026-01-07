/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/common/SNTConfigBundle.h"
#import "Source/common/SNTFileAccessRule.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTXPCUnprivilegedControlInterface.h"

@class SNTStoredEvent;

///
///  Protocol implemented by santad and utilized by santactl (privileged operations)
///
@protocol SNTDaemonControlXPC <SNTUnprivilegedDaemonControlXPC>

///
///  Cache ops
///
- (void)flushCache:(void (^)(BOOL))reply;

///
///  Database ops
///
typedef NS_ENUM(NSInteger, SNTRuleAddSource) {
  SNTRuleAddSourceSyncService,
  SNTRuleAddSourceSantactl,
};
- (void)databaseRuleAddExecutionRules:(NSArray<SNTRule *> *)executionRules
                      fileAccessRules:(NSArray<SNTFileAccessRule *> *)fileAccessRules
                          ruleCleanup:(SNTRuleCleanup)cleanupType
                               source:(SNTRuleAddSource)source
                                reply:(void (^)(BOOL, NSArray<NSError *> *error))reply;
- (void)databaseEventsPending:(void (^)(NSArray<SNTStoredEvent *> *events))reply;
- (void)databaseRemoveEventsWithIDs:(NSArray *)ids;
- (void)retrieveAllExecutionRules:(void (^)(NSArray<SNTRule *> *rules, NSError *error))reply;
- (void)retrieveAllFileAccessRules:
    (void (^)(NSDictionary<NSString *, NSDictionary *> *fileAccessRules, NSError *error))reply;

///
///  Config ops
///
- (void)updateSyncSettings:(SNTConfigBundle *)result reply:(void (^)(void))reply;

///
///  Syncd Ops
///
- (void)postRuleSyncNotificationForApplication:(NSString *)app reply:(void (^)(void))reply;
// Retrieve saved stats state info from santad
- (void)retrieveStatsState:(void (^)(NSDate *, NSString *))reply;
// Have santad save the latest stats state information
- (void)saveStatsSubmissionAttemptTime:(NSDate *)timestamp version:(NSString *)version;

///
/// Command ops
///
- (void)killProcesses:(SNTKillRequest *)killRequest reply:(void (^)(SNTKillResponse *))reply;

///
/// Control Ops
///
- (void)installSantaApp:(NSString *)appPath reply:(void (^)(BOOL))reply;

@end

@interface SNTXPCControlInterface : NSObject

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceID;

///
///  Returns the SystemExtension ID for this service.
///
+ (NSString *)systemExtensionID;

///
///  Returns an initialized NSXPCInterface for the SNTUnprivilegedDaemonControlXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)controlInterface;

///
///  Retrieve a pre-configured MOLXPCConnection for communicating with santad.
///  Connections just needs any handlers set and then can be resumed and used.
///
+ (MOLXPCConnection *)configuredConnection;

@end
