/// Copyright 2015-2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#import "Source/santad/SNTExecutionController.h"

#import <Foundation/Foundation.h>

#include <bsm/libbsm.h>
#include <copyfile.h>
#include <libproc.h>
#include <pwd.h>
#include <sys/param.h>
#include <utmpx.h>

#include <memory>
#include <set>
#include <string>
#include <utility>

#include "Source/common/BranchPrediction.h"
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
#include "Source/common/Unit.h"
#import "Source/santad/DataLayer/SNTEventTable.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#import "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTNotificationQueue.h"
#import "Source/santad/SNTSyncdQueue.h"
#include "absl/synchronization/mutex.h"

using santa::Message;
using santa::PrefixTree;
using santa::ProcessControl;
using santa::TTYWriter;
using santa::Unit;

static const size_t kMaxAllowedPathLength = MAXPATHLEN - 1;  // -1 to account for null terminator

@interface SNTExecutionController ()
@property SNTEventTable *eventTable;
@property SNTNotificationQueue *notifierQueue;
@property SNTPolicyProcessor *policyProcessor;
@property(readwrite) SNTRuleTable *ruleTable;
@property SNTSyncdQueue *syncdQueue;
@property SNTMetricCounter *events;
@property santa::ProcessControlBlock processControlBlock;

@property dispatch_queue_t eventQueue;
@end

// Convert a block decision to the corresponding allow decision, preserving the rule type.
static SNTEventState BlockToAllowDecision(SNTEventState blockDecision) {
  switch (blockDecision) {
    case SNTEventStateBlockUnknown: return SNTEventStateAllowUnknown;
    case SNTEventStateBlockBinary: return SNTEventStateAllowBinary;
    case SNTEventStateBlockCertificate: return SNTEventStateAllowCertificate;
    case SNTEventStateBlockScope: return SNTEventStateAllowScope;
    case SNTEventStateBlockTeamID: return SNTEventStateAllowTeamID;
    case SNTEventStateBlockSigningID: return SNTEventStateAllowSigningID;
    case SNTEventStateBlockCDHash: return SNTEventStateAllowCDHash;
    case SNTEventStateBlockLongPath: return SNTEventStateAllowUnknown;  // No direct equivalent
    default: return SNTEventStateAllowUnknown;
  }
}

@implementation SNTExecutionController {
  LogExecutionBlock _logger;
  std::shared_ptr<TTYWriter> _ttyWriter;
  std::unique_ptr<SantaCache<std::pair<pid_t, int>, bool>> _procSignalCache;
}

static NSString *const kPrinterProxyPreMonterey =
    (@"/System/Library/Frameworks/Carbon.framework/Versions/Current/"
     @"Frameworks/Print.framework/Versions/Current/Plugins/PrinterProxy.app/"
     @"Contents/MacOS/PrinterProxy");
static NSString *const kPrinterProxyPostMonterey =
    (@"/System/Library/PrivateFrameworks/PrintingPrivate.framework/"
     @"Versions/Current/Plugins/PrinterProxy.app/Contents/MacOS/PrinterProxy");

#pragma mark Initializers

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable
                       eventTable:(SNTEventTable *)eventTable
                    notifierQueue:(SNTNotificationQueue *)notifierQueue
                       syncdQueue:(SNTSyncdQueue *)syncdQueue
                           logger:(LogExecutionBlock)logger
                        ttyWriter:(std::shared_ptr<TTYWriter>)ttyWriter
                  policyProcessor:(SNTPolicyProcessor *)policyProcessor
              processControlBlock:(santa::ProcessControlBlock)processControlBlock {
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
    _processControlBlock = processControlBlock;

    _eventQueue =
        dispatch_queue_create("com.northpolesec.santa.daemon.event_upload", DISPATCH_QUEUE_SERIAL);

    // This establishes the XPC connection between libsecurity and syspolicyd.
    // Not doing this causes a deadlock as establishing this link goes through xpcproxy.
    (void)[[MOLCodesignChecker alloc] initWithSelf];

    SNTMetricSet *metricSet = [SNTMetricSet sharedInstance];
    _events = [metricSet counterWithName:@"/santa/events"
                              fieldNames:@[ @"action_response" ]
                                helpText:@"Events processed by Santa per response"];
  }
  return self;
}

- (void)incrementEventCounters:(SNTEventState)eventType {
  const NSString *eventTypeStr;

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
    default: eventTypeStr = kUnknownEventState; break;
  }

  [_events incrementForFieldValues:@[ (NSString *)eventTypeStr ]];
}

#pragma mark Binary Validation

- (bool)synchronousShouldProcessExecEvent:(const Message &)esMsg {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    LOGE(@"Attempt to validate unhandled event. Event type: %d", esMsg->event_type);
    [NSException
         raise:@"Invalid event type"
        format:@"synchronousShouldProcessExecEvent: Unexpected event type: %d", esMsg->event_type];
  }

  const es_process_t *targetProc = esMsg->event.exec.target;

  if (targetProc->executable->path.length > kMaxAllowedPathLength ||
      targetProc->executable->path_truncated) {
    // Store a SNTCachedDecision so that this event gets properly logged
    SNTCachedDecision *cd =
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

- (void)validateExecEvent:(const Message &)esMsg postAction:(bool (^)(SNTAction))postAction {
  if (unlikely(esMsg->event_type != ES_EVENT_TYPE_AUTH_EXEC)) {
    // Programming error. Bail.
    LOGE(@"Attempt to validate non-EXEC event. Event type: %d", esMsg->event_type);
    [NSException
         raise:@"Invalid event type"
        format:@"validateExecEvent:postAction: Unexpected event type: %d", esMsg->event_type];
  }

  SNTConfigurator *config = [SNTConfigurator configurator];
  SNTConfigState *configState = [[SNTConfigState alloc] initWithConfig:config];

  const es_process_t *targetProc = esMsg->event.exec.target;

  // Get info about the file. If we can't get this info, respond appropriately and log an error.
  NSError *fileInfoError;
  SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithEndpointSecurityFile:targetProc->executable
                                                                     error:&fileInfoError];
  if (unlikely(!binInfo)) {
    if (config.failClosed) {
      LOGE(@"Failed to read file %@: %@ and denying action", @(targetProc->executable->path.data),
           fileInfoError.localizedDescription);
      postAction(SNTActionRespondDeny);
      [self.events incrementForFieldValues:@[ (NSString *)kDenyNoFileInfo ]];
    } else {
      LOGE(@"Failed to read file %@: %@ but allowing action", @(targetProc->executable->path.data),
           fileInfoError.localizedDescription);
      postAction(SNTActionRespondAllow);
      [self.events incrementForFieldValues:@[ (NSString *)kAllowNoFileInfo ]];
    }
    return;
  }

  // PrinterProxy workaround, see description above the method for more details.
  if ([self printerProxyWorkaround:binInfo]) {
    postAction(SNTActionRespondDeny);
    [self.events incrementForFieldValues:@[ (NSString *)kBlockPrinterWorkaround ]];
    return;
  }

  // TODO(markowsky): Maybe add a metric here for how many large executables we're seeing.
  // if (binInfo.fileSize > SomeUpperLimit) ...

  SNTCachedDecision *cd = [self.policyProcessor
      decisionForFileInfo:binInfo
            targetProcess:targetProc
              configState:configState
       activationCallback:[self
                              createActivationBlockForMessage:esMsg
                                                    andCSInfo:[binInfo
                                                                  codesignCheckerWithError:NULL]]];

  cd.codesigningFlags = targetProc->codesigning_flags;
  cd.vnodeId = SantaVnode::VnodeForFile(targetProc->executable);

  // Formulate an initial action from the decision.
  SNTAction action = (SNTEventStateAllow & cd.decision)
                         ? (cd.cacheable ? SNTActionRespondAllow : SNTActionRespondAllowNoCache)
                         : SNTActionRespondDeny;

  // Save decision details for logging the execution later.  For transitive rules, we also use
  // the shasum stored in the decision details to update the rule's timestamp whenever an
  // ACTION_NOTIFY_EXEC message related to the transitive rule is received.
  [[SNTDecisionCache sharedCache] cacheDecision:cd];

  // Upgrade the action to SNTActionRespondAllowCompiler when appropriate, because we want the
  // kernel to track this information in its decision cache.
  if (cd.decision == SNTEventStateAllowCompilerBinary ||
      cd.decision == SNTEventStateAllowCompilerSigningID ||
      cd.decision == SNTEventStateAllowCompilerCDHash) {
    action = SNTActionRespondAllowCompiler;
  }

  pid_t newProcPid = audit_token_to_pid(targetProc->audit_token);
  BOOL stoppedProc = false;
  std::pair<pid_t, int> pidAndVersion =
      std::make_pair(newProcPid, audit_token_to_pidversion(targetProc->audit_token));
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
    postAction(SNTActionRespondHold);
  } else {
    // Respond with the decision.
    postAction(action);
  }

  // Increment metric counters
  [self incrementEventCounters:cd.decision];

  // Log to database if necessary.
  if (config.enableAllEventUpload ||
      (cd.decision == SNTEventStateAllowUnknown && !config.disableUnknownEventUpload) ||
      (cd.decision & SNTEventStateAllow) == 0) {
    SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];
    se.occurrenceDate = [[NSDate alloc] init];
    se.fileSHA256 = cd.sha256;
    se.filePath = binInfo.path;
    se.decision = cd.decision;
    se.holdAndAsk = cd.holdAndAsk;

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
    struct passwd *user = getpwuid(audit_token_to_ruid(targetProc->audit_token));
    if (user) se.executingUser = @(user->pw_name);
    NSArray *loggedInUsers, *currentSessions;
    [self loggedInUsers:&loggedInUsers sessions:&currentSessions];
    se.currentSessions = currentSessions;
    se.loggedInUsers = loggedInUsers;

    // Quarantine data
    se.quarantineDataURL = binInfo.quarantineDataURL;
    se.quarantineRefererURL = binInfo.quarantineRefererURL;
    se.quarantineTimestamp = binInfo.quarantineTimestamp;
    se.quarantineAgentBundleID = binInfo.quarantineAgentBundleID;

    // Only store events if there is a sync server configured.
    if (config.syncBaseURL) {
      dispatch_async(_eventQueue, ^{
        [self.eventTable addStoredEvent:se];
      });
    }

    // If binary was blocked, do the needful
    if (action != SNTActionRespondAllow && action != SNTActionRespondAllowCompiler &&
        action != SNTActionRespondAllowNoCache) {
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

      if (!cd.silentBlock) {
        _ttyWriter->Write(targetProc, ^NSString * {
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
          NSAttributedString *s = [SNTBlockMessage attributedBlockMessageForEvent:se
                                                                    customMessage:cd.customMsg];

          NSMutableString *msg = [NSMutableString stringWithCapacity:1024];
          // Escape sequences `\033[1m` and `\033[0m` begin/end bold lettering
          [msg appendFormat:@"\n\033[1mSanta\033[0m\n\n%@\n\n", s.string];
          [msg appendFormat:@"\033[1mPath:      \033[0m %@\n"
                            @"\033[1mIdentifier:\033[0m %@\n"
                            @"\033[1mParent:    \033[0m %@ (%@)\n\n",
                            se.filePath, se.fileSHA256, se.parentName, se.ppid];
          NSURL *detailURL =
              [SNTBlockMessage eventDetailURLForEvent:se
                                            customURL:(cd.customURL ?: config.eventDetailURL)];
          if (detailURL) {
            [msg appendFormat:@"More info:\n%@\n\n", detailURL.absoluteString];
          }
          return msg;
        });

        NotificationReplyBlock replyBlock = nil;

        if (cd.holdAndAsk) {
          // Copy the esMsg to ensure that when the passed-in ref goes away
          // we're still holding a valid Message object inside the replyBlock.
          __block Message esMsgCopy(esMsg);
          replyBlock = ^(BOOL authenticated) {
            LOGD(@"User responded to block event for %@ with authenticated: %d", se.filePath,
                 authenticated);
            if (authenticated) {
              if (cd.decisionClientMode == SNTClientModeStandalone &&
                  cd.decision == SNTEventStateBlockUnknown) {
                // Create a rule for the binary that was allowed by the user in
                // standalone mode and notify the sync service.
                [self createRuleForStandaloneModeEvent:se];
              }

              // Update decision to reflect that it was allowed via TouchID,
              // preserving the rule type (e.g., BlockSigningID -> AllowSigningID)
              cd.decision = BlockToAllowDecision(cd.decision);
              cd.decisionExtra = @"TouchID Approved";

              if (stoppedProc) {
                _ttyWriter->Write(targetProc, @"Authorized, allowing execution\n---\n\n");
              }

              // Allow the binary to begin running.
              self.processControlBlock(newProcPid, ProcessControl::Resume);
            } else {
              // Decision stays as-is when TouchID is denied, just populate the extra field.
              cd.decisionExtra = @"TouchID Denied";

              // The user did not approve, so kill the stopped process.
              if (stoppedProc) {
                _ttyWriter->Write(targetProc,
                                  @"Authorization not given, denying execution\n---\n\n");
              }
              self.processControlBlock(newProcPid, ProcessControl::Kill);
            }

            // Clear holdAndAsk and update cache so it's recorded as a final decision
            cd.holdAndAsk = NO;
            [[SNTDecisionCache sharedCache] cacheDecision:cd];

            // Log the execution event (since NOTIFY was suppressed during holdAndAsk)
            self->_logger(std::move(esMsgCopy));

            _procSignalCache->remove(pidAndVersion);
            postAction(authenticated ? SNTActionHoldAllowed : SNTActionHoldDenied);
          };
        }

        // Let the user know what happened in the GUI.
        [self.notifierQueue addEvent:se
                   withCustomMessage:cd.customMsg
                           customURL:cd.customURL ?: config.eventDetailURL
                         configState:configState
                            andReply:replyBlock];
      }
    }
  }
}

#pragma mark Signal Validation

- (void)validateSuspendResumeEvent:(const santa::Message &)esMsg
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

/**
  Workaround for issue with PrinterProxy.app.

  Every time a new printer is added to the machine, a copy of the PrinterProxy.app is copied from
  the Print.framework to ~/Library/Printers with the name of the printer as the name of the app.
  The binary inside is changed slightly (in a way that is unique to the printer name) and then
  re-signed with an adhoc signature. I don't know why this is done but it seems that the binary
  itself doesn't need to be changed as copying the old one back in-place seems to work,
  so that's what we do.

  If this workaround is applied the decision request is not responded to as the existing request
  is invalidated when the file is closed which will trigger a brand new request coming from the
  kernel.

  @param fi SNTFileInfo object for the binary being executed.
  @return YES if the workaround was applied, NO otherwise.
*/
- (BOOL)printerProxyWorkaround:(SNTFileInfo *)fi {
  if ([fi.path hasSuffix:@"/Contents/MacOS/PrinterProxy"] &&
      [fi.path containsString:@"Library/Printers"]) {
    SNTFileInfo *proxyFi = [self printerProxyFileInfo];
    if ([proxyFi.SHA256 isEqual:fi.SHA256]) return NO;

    copyfile_flags_t copyflags = COPYFILE_ALL | COPYFILE_UNLINK;
    if (copyfile(proxyFi.path.UTF8String, fi.path.UTF8String, NULL, copyflags) != 0) {
      LOGE(@"Failed to apply PrinterProxy workaround for %@", fi.path);
    } else {
      LOGI(@"PrinterProxy workaround applied to: %@", fi.path);
    }

    return YES;
  }
  return NO;
}

/**
  Returns an SNTFileInfo for the system PrinterProxy path on this system.
*/
- (SNTFileInfo *)printerProxyFileInfo {
  SNTFileInfo *proxyInfo = [[SNTFileInfo alloc] initWithPath:kPrinterProxyPostMonterey];
  if (!proxyInfo) proxyInfo = [[SNTFileInfo alloc] initWithPath:kPrinterProxyPreMonterey];
  return proxyInfo;
}

- (void)loggedInUsers:(NSArray **)users sessions:(NSArray **)sessions {
  NSMutableSet *loggedInUsers = [NSMutableSet set];
  NSMutableArray *loggedInHosts = [NSMutableArray array];

  struct utmpx *nxt;
  while ((nxt = getutxent())) {
    if (nxt->ut_type != USER_PROCESS) continue;

    NSString *userName = @(nxt->ut_user);
    NSString *sessionName;
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
- (void)createRuleForStandaloneModeEvent:(SNTStoredExecutionEvent *)se {
  SNTRuleType ruleType;
  NSString *ruleIdentifier;
  SNTRuleState newRuleState;

  if (se.signingStatus == SNTSigningStatusProduction && se.signingID) {
    ruleType = SNTRuleTypeSigningID;
    ruleIdentifier = se.signingID;
    newRuleState = SNTRuleStateAllowLocalSigningID;
  } else if (se.fileSHA256) {
    ruleType = SNTRuleTypeBinary;
    ruleIdentifier = se.fileSHA256;
    newRuleState = SNTRuleStateAllowLocalBinary;
  } else {
    LOGE(@"No appropriate identifiers available to add rule in standalone mode for %@",
         se.filePath);
    return;
  }

  NSString *commentStr = [NSString stringWithFormat:@"%@", se.filePath];

  // Add rule to allow binary same as santactl rule.
  NSError *err;
  SNTRule *newRule = [[SNTRule alloc] initWithIdentifier:ruleIdentifier
                                                   state:newRuleState
                                                    type:ruleType
                                               customMsg:nil
                                               customURL:nil
                                               timestamp:[[NSDate now] timeIntervalSince1970]
                                                 comment:commentStr
                                                 celExpr:nil
                                                   error:&err];
  if (err) {
    LOGE(@"Failed to add rule in standalone mode for %@: %@", se.filePath,
         err.localizedDescription);
    return;
  }

  NSArray<NSError *> *errors;
  BOOL success = [self.ruleTable addExecutionRules:@[ newRule ]
                                       ruleCleanup:SNTRuleCleanupNone
                                            errors:&errors];
  if (errors.count > 0 || !success) {
    LOGW(@"%@ encountered while adding a rule in standalone mode for: %@:",
         success ? @"Issues" : @"Errors", se.filePath);
    for (NSError *error in errors) {
      LOGE(@"\t %@", error.localizedDescription);
    }
  }

  // TODO: Notify the sync service of the new rule.
}

// Create a block that returns a santa::cel::Activation object for the given Message
// and MOLCodesignChecker object. The block defines a bool parameter that determines
// whether to create a v1 or v2 activation object.
//
// Note: The returned block captures a reference to the Message object and must
// not use it after the Message object is destroyed. Care must be taken to not
// use this in an asynchronous context outside of the evaluation of that execution.
- (ActivationCallbackBlock)createActivationBlockForMessage:(const santa::Message &)esMsg
                                                 andCSInfo:(nullable MOLCodesignChecker *)csInfo {
  std::shared_ptr<santa::EndpointSecurityAPI> esApi = esMsg.ESAPI();

  return ^std::unique_ptr<::google::api::expr::runtime::BaseActivation>(bool useV2) {
    auto makeActivation =
        [&]<bool IsV2>() -> std::unique_ptr<::google::api::expr::runtime::BaseActivation> {
      using Traits = santa::cel::CELProtoTraits<IsV2>;
      using ExecutableFileT = typename Traits::ExecutableFileT;

      auto f = std::make_unique<ExecutableFileT>();

      if (csInfo.signingTime) {
        f->mutable_signing_time()->set_seconds(csInfo.signingTime.timeIntervalSince1970);
      }
      if (csInfo.secureSigningTime) {
        f->mutable_secure_signing_time()->set_seconds(
            csInfo.secureSigningTime.timeIntervalSince1970);
      }

      return std::make_unique<santa::cel::Activation<IsV2>>(
          std::move(f),
          ^std::vector<std::string>() {
            return esApi->ExecArgs(&esMsg->event.exec);
          },
          ^std::map<std::string, std::string>() {
            return esApi->ExecEnvs(&esMsg->event.exec);
          },
          ^uid_t() {
            return audit_token_to_euid(esMsg->event.exec.target->audit_token);
          },
          ^std::string() {
            es_file_t *f = esMsg->event.exec.cwd;
            return std::string(f->path.data, f->path.length);
          });
    };

    if (useV2) {
      return makeActivation.operator()<true>();
    } else {
      return makeActivation.operator()<false>();
    }
  };
}

@end
