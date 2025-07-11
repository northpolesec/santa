/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/ProcessControl.h"
#include "Source/santad/TTYWriter.h"

const static NSString *kBlockBinary = @"BlockBinary";
const static NSString *kAllowBinary = @"AllowBinary";
const static NSString *kAllowLocalBinary = @"AllowLocalBinary";
const static NSString *kBlockCertificate = @"BlockCertificate";
const static NSString *kAllowCertificate = @"AllowCertificate";
const static NSString *kBlockTeamID = @"BlockTeamID";
const static NSString *kAllowTeamID = @"AllowTeamID";
const static NSString *kBlockSigningID = @"BlockSigningID";
const static NSString *kAllowSigningID = @"AllowSigningID";
const static NSString *kAllowLocalSigningID = @"AllowLocalSigningID";
const static NSString *kBlockCDHash = @"BlockCDHash";
const static NSString *kAllowCDHash = @"AllowCDHash";
const static NSString *kBlockScope = @"BlockScope";
const static NSString *kAllowScope = @"AllowScope";
const static NSString *kAllowUnknown = @"AllowUnknown";
const static NSString *kBlockUnknown = @"BlockUnknown";
const static NSString *kAllowCompilerBinary = @"AllowCompilerBinary";
const static NSString *kAllowCompilerCDHash = @"AllowCompilerCDHash";
const static NSString *kAllowCompilerSigningID = @"AllowCompilerSigningID";
const static NSString *kAllowTransitive = @"AllowTransitive";
const static NSString *kUnknownEventState = @"Unknown";
const static NSString *kBlockPrinterWorkaround = @"BlockPrinterWorkaround";
const static NSString *kAllowNoFileInfo = @"AllowNoFileInfo";
const static NSString *kDenyNoFileInfo = @"DenyNoFileInfo";
const static NSString *kBlockLongPath = @"BlockLongPath";

@class SNTEventTable;
@class SNTNotificationQueue;
@class SNTRuleTable;
@class SNTSyncdQueue;

///
///  SNTExecutionController is responsible for handling binary execution requests:
///    + Uses SNTPolicyProcessor to make a decision about whether to allow or deny the binary.
///    + Sending the decision to the kernel as soon as possible
///    + (If denied or unknown) Storing details about the execution event to the database
///      for upload and spwaning santactl to quickly try and send that to the server.
///    + (If denied) Potentially sending a message to SantaGUI to notify the user
///
@interface SNTExecutionController : NSObject

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable
                       eventTable:(SNTEventTable *)eventTable
                    notifierQueue:(SNTNotificationQueue *)notifierQueue
                       syncdQueue:(SNTSyncdQueue *)syncdQueue
                        ttyWriter:(std::shared_ptr<santa::TTYWriter>)ttyWriter
         entitlementsPrefixFilter:(NSArray<NSString *> *)prefixFilter
         entitlementsTeamIDFilter:(NSArray<NSString *> *)teamIDFilter
              processControlBlock:(santa::ProcessControlBlock)processControlBlock;

///
///  Handles the logic of deciding whether to allow the binary to run or not, sends the response to
///  the given `postAction` block. Also logs the event to the log and if necessary stores the event
///  in the database and sends a notification to the GUI agent.
///
///  @param message The message received from the EndpointSecurity event provider.
///  @param postAction The block invoked with the desired response result.
///
- (void)validateExecEvent:(const santa::Message &)esMsg postAction:(bool (^)(SNTAction))postAction;

///
///  Handles the logic of deciding whether to allow a pid_suspend/pid_resume through to a binary or
///  not, sends the response to the given `postAction` block.
///
///  @param message The message reveived from the EndpointSecurity event provider.
///  @param postAction The block invoked with the desired response result.
///
- (void)validateSuspendResumeEvent:(const santa::Message &)esMsg
                        postAction:(void (^)(bool))postAction;

///
/// Perform light, synchronous processing of the given event to decide whether or not the
/// event should undergo full processing. The checks done by this function MUST NOT block
/// the thread (e.g. perform no XPC) and should be fast and efficient so as to mitigate
/// potential buildup of event backlog.
///
///  @param message The message received from the EndpointSecurity event provider.
///  @return bool True if the event should be processed, otherwise false.
///
- (bool)synchronousShouldProcessExecEvent:(const santa::Message &)esMsg;

- (void)updateEntitlementsPrefixFilter:(NSArray<NSString *> *)filter;
- (void)updateEntitlementsTeamIDFilter:(NSArray<NSString *> *)filter;

@property(nonatomic, readonly) SNTRuleTable *ruleTable;

@end
