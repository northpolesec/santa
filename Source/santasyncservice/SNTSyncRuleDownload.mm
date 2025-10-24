/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santasyncservice/SNTSyncRuleDownload.h"

#include <Foundation/Foundation.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTFileAccessRule.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#import "Source/common/faa/WatchItemPolicy.h"
#import "Source/common/faa/WatchItems.h"
#include "Source/santasyncservice/ProtoTraits.h"
#import "Source/santasyncservice/SNTPushNotificationsTracker.h"
#import "Source/santasyncservice/SNTSyncConfigBundle.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"
#include "google/protobuf/arena.h"
#include "syncv2/v2.pb.h"

namespace pbv2 = ::santa::sync::v2;

using santa::NSStringToUTF8String;
using santa::StringToNSString;

template <bool IsV2>
SNTRule *RuleFromProtoRule(
    const typename santa::ProtoTraits<std::bool_constant<IsV2>>::RuleT &rule);
template <bool IsV2>
void ProcessBundleNotificationsForRule(
    SNTSyncRuleDownload *self, SNTRule *rule,
    const typename santa::ProtoTraits<std::bool_constant<IsV2>>::RuleT *protoRule);
template <bool IsV2>
void ProcessDeprecatedBundleNotificationsForRule(
    SNTRule *rule, const typename santa::ProtoTraits<std::bool_constant<IsV2>>::RuleT *protoRule);
SNTFileAccessRule *FaaRuleFromProtoFAARuleRemove(
    const ::pbv2::FileAccessRule::Remove &pbRemoveRule);
SNTFileAccessRule *FileAccessRuleFromProtoFileAccessRule(const ::pbv2::FileAccessRule &wi);
SNTFileAccessRule *FaaRuleFromProtoFAARuleAdd(const ::pbv2::FileAccessRule::Add &pbAddRule);
NSArray *PathsFromProtoFAARulePaths(
    const google::protobuf::RepeatedPtrField<::pbv2::FileAccessRule::Path> &pbPaths);
NSDictionary *OptionsFromProtoFAARuleAdd(const ::pbv2::FileAccessRule::Add &pbAddRule);
NSArray *ProcessesFromProtoFAARuleProcesses(
    const google::protobuf::RepeatedPtrField<::pbv2::FileAccessRule::Process> &pbProcesses);

// Small local object to more easily return the different sets of downloaded rules.
@interface SNTDownloadedRuleSets : NSObject
@property(readonly) NSArray<SNTRule *> *executionRules;
@property(readonly) NSArray<SNTFileAccessRule *> *fileAccessRules;
@end

@implementation SNTDownloadedRuleSets
- (instancetype)initWithExecutionRules:(NSArray<SNTRule *> *)executionRules
                       fileAccessRules:(NSArray<SNTFileAccessRule *> *)fileAccessRules {
  self = [super init];
  if (self) {
    _executionRules = executionRules;
    _fileAccessRules = fileAccessRules;
  }
  return self;
}
@end

SNTRuleCleanup SyncTypeToRuleCleanup(SNTSyncType syncType) {
  switch (syncType) {
    case SNTSyncTypeNormal: return SNTRuleCleanupNone;
    case SNTSyncTypeClean: return SNTRuleCleanupNonTransitive;
    case SNTSyncTypeCleanAll: return SNTRuleCleanupAll;
    default: return SNTRuleCleanupNone;
  }
}

// Downloads new rules from server and converts them into SNTRule.
// Returns an array of all converted rules, or nil if there was a server problem.
// Note that rules from the server are filtered.
template <bool IsV2>
SNTDownloadedRuleSets *DownloadNewRulesFromServer(SNTSyncRuleDownload *self) {
  using Traits = santa::ProtoTraits<std::bool_constant<IsV2>>;
  google::protobuf::Arena arena;

  self.syncState.rulesReceived = 0;
  self.syncState.fileAccessRulesReceived = 0;
  NSMutableArray<SNTRule *> *newRules = [NSMutableArray array];
  NSMutableArray<SNTFileAccessRule *> *newFileAccessRules = [NSMutableArray array];
  std::string cursor;

  do {
    @autoreleasepool {
      auto req = google::protobuf::Arena::Create<typename Traits::RuleDownloadRequestT>(&arena);
      req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));

      if (!cursor.empty()) {
        req->set_cursor(cursor);
      }
      typename Traits::RuleDownloadResponseT response;
      NSError *err = [self performRequest:[self requestWithMessage:req]
                              intoMessage:&response
                                  timeout:30];

      if (err) {
        SLOGE(@"Error downloading rules: %@", err);
        return nil;
      }

      for (const typename Traits::RuleT &rule : response.rules()) {
        SNTRule *r = RuleFromProtoRule<IsV2>(rule);
        if (!r) {
          SLOGD(@"Ignoring bad rule: %s", rule.Utf8DebugString().c_str());
          continue;
        }
        ProcessBundleNotificationsForRule<IsV2>(self, r, &rule);
        [newRules addObject:r];
      }

      if constexpr (IsV2) {
        for (const typename Traits::FileAccessRuleT &faaRule : response.file_access_rules()) {
          SNTFileAccessRule *rule = FileAccessRuleFromProtoFileAccessRule(faaRule);
          if (!rule) {
            SLOGD(@"Ignoring bad file access rule: %s", faaRule.Utf8DebugString().c_str());
            continue;
          }
          [newFileAccessRules addObject:rule];
        }
      }

      cursor = response.cursor();
      SLOGI(@"Received %lu rules", (unsigned long)response.rules_size());
      self.syncState.rulesReceived += response.rules_size();
      if constexpr (IsV2) {
        self.syncState.fileAccessRulesReceived += response.file_access_rules_size();
      }
    }
  } while (!cursor.empty());

  self.syncState.rulesProcessed = newRules.count;
  self.syncState.fileAccessRulesProcessed = newFileAccessRules.count;

  return [[SNTDownloadedRuleSets alloc] initWithExecutionRules:newRules
                                               fileAccessRules:newFileAccessRules];
}

NSArray *PathsFromProtoFAARulePaths(
    const google::protobuf::RepeatedPtrField<::pbv2::FileAccessRule::Path> &pbPaths) {
  NSMutableArray *watchPaths = [NSMutableArray array];

  for (const ::pbv2::FileAccessRule::Path &path : pbPaths) {
    NSMutableDictionary *pathDict = [NSMutableDictionary dictionary];
    pathDict[kWatchItemConfigKeyPathsPath] = StringToNSString(path.path());

    switch (path.path_type()) {
      // Note: If unspecified, using kWatchItemPolicyDefaultPathType (WatchItemPathType::kLiteral)
      case ::pbv2::FileAccessRule::Path::PATH_TYPE_UNSPECIFIED: [[clang::fallthrough]];
      case ::pbv2::FileAccessRule::Path::PATH_TYPE_LITERAL:
        pathDict[kWatchItemConfigKeyPathsIsPrefix] = @(NO);
        break;
      case ::pbv2::FileAccessRule::Path::PATH_TYPE_PREFIX:
        pathDict[kWatchItemConfigKeyPathsIsPrefix] = @(YES);
        break;
      default: return nil;
    }

    [watchPaths addObject:pathDict];
  }

  return watchPaths;
}

NSDictionary *OptionsFromProtoFAARuleAdd(const ::pbv2::FileAccessRule::Add &pbAddRule) {
  NSMutableDictionary *optionsDict = [NSMutableDictionary dictionary];

  switch (pbAddRule.rule_type()) {
    case ::pbv2::FileAccessRule::RULE_TYPE_UNSPECIFIED:
    case ::pbv2::FileAccessRule::RULE_TYPE_PATHS_WITH_ALLOWED_PROCESSES:
      optionsDict[kWatchItemConfigKeyOptionsRuleType] = kRuleTypePathsWithAllowedProcesses;
      break;
    case ::pbv2::FileAccessRule::RULE_TYPE_PATHS_WITH_DENIED_PROCESSES:
      optionsDict[kWatchItemConfigKeyOptionsRuleType] = kRuleTypePathsWithDeniedProcesses;
      break;
    case ::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_ALLOWED_PATHS:
      optionsDict[kWatchItemConfigKeyOptionsRuleType] = kRuleTypeProcessesWithAllowedPaths;
      break;
    case ::pbv2::FileAccessRule::RULE_TYPE_PROCESSES_WITH_DENIED_PATHS:
      optionsDict[kWatchItemConfigKeyOptionsRuleType] = kRuleTypeProcessesWithDeniedPaths;
      break;
    default: return nil;
  }

  optionsDict[kWatchItemConfigKeyOptionsVersion] = StringToNSString(pbAddRule.version());
  optionsDict[kWatchItemConfigKeyOptionsAllowReadAccess] = @(pbAddRule.allow_read_access());
  optionsDict[kWatchItemConfigKeyOptionsAuditOnly] = @(!pbAddRule.block_violations());
  optionsDict[kWatchItemConfigKeyOptionsEnableSilentMode] = @(pbAddRule.enable_silent_mode());
  optionsDict[kWatchItemConfigKeyOptionsEnableSilentTTYMode] =
      @(pbAddRule.enable_silent_tty_mode());
  optionsDict[kWatchItemConfigKeyOptionsCustomMessage] =
      pbAddRule.block_message().length() > 0 ? StringToNSString(pbAddRule.block_message()) : nil;
  optionsDict[kWatchItemConfigKeyOptionsEventDetailText] =
      pbAddRule.event_detail_text().length() > 0 ? StringToNSString(pbAddRule.event_detail_text())
                                                 : nil;
  optionsDict[kWatchItemConfigKeyOptionsEventDetailURL] =
      pbAddRule.event_detail_url().length() > 0 ? StringToNSString(pbAddRule.event_detail_url())
                                                : nil;

  return optionsDict;
}

NSArray *ProcessesFromProtoFAARuleProcesses(
    const google::protobuf::RepeatedPtrField<::pbv2::FileAccessRule::Process> &pbProcesses) {
  NSMutableArray *processes = [NSMutableArray array];

  for (const ::pbv2::FileAccessRule::Process &process : pbProcesses) {
    NSMutableDictionary *processDict = [NSMutableDictionary dictionary];

    switch (process.identifier_case()) {
      case ::pbv2::FileAccessRule::Process::kBinaryPath:
        processDict[kWatchItemConfigKeyProcessesBinaryPath] =
            StringToNSString(process.binary_path());
        break;
      case ::pbv2::FileAccessRule::Process::kCdHash:
        processDict[kWatchItemConfigKeyProcessesCDHash] = StringToNSString(process.cd_hash());
        break;
      case ::pbv2::FileAccessRule::Process::kSigningId:
        processDict[kWatchItemConfigKeyProcessesSigningID] = StringToNSString(process.signing_id());
        break;
      case ::pbv2::FileAccessRule::Process::kCertificateSha256:
        processDict[kWatchItemConfigKeyProcessesCertificateSha256] =
            StringToNSString(process.certificate_sha256());
        break;
      case ::pbv2::FileAccessRule::Process::kTeamId:
        processDict[kWatchItemConfigKeyProcessesTeamID] = StringToNSString(process.team_id());
        break;
      default: return nil;
    }

    [processes addObject:processDict];
  }

  return processes;
}

SNTFileAccessRule *FaaRuleFromProtoFAARuleAdd(const ::pbv2::FileAccessRule::Add &pbAddRule) {
  NSMutableDictionary *details = [NSMutableDictionary dictionary];

  NSArray *paths = PathsFromProtoFAARulePaths(pbAddRule.paths());
  if (!paths) {
    return nil;
  }
  details[kWatchItemConfigKeyPaths] = paths;

  NSDictionary *optionsDict = OptionsFromProtoFAARuleAdd(pbAddRule);
  if (!optionsDict) {
    return nil;
  }
  details[kWatchItemConfigKeyOptions] = optionsDict;

  NSArray *processes = ProcessesFromProtoFAARuleProcesses(pbAddRule.processes());
  if (!paths) {
    return nil;
  }
  details[kWatchItemConfigKeyProcesses] = processes;

  NSString *name = StringToNSString(pbAddRule.name());

  NSError *err;
  if (santa::WatchItems::IsValidRule(name, details, &err)) {
    return [[SNTFileAccessRule alloc] initAddRuleWithName:name details:details];
  } else {
    return nil;
  }
}

SNTFileAccessRule *FaaRuleFromProtoFAARuleRemove(
    const ::pbv2::FileAccessRule::Remove &pbRemoveRule) {
  return [[SNTFileAccessRule alloc] initRemoveRuleWithName:StringToNSString(pbRemoveRule.name())];
}

SNTFileAccessRule *FileAccessRuleFromProtoFileAccessRule(const ::pbv2::FileAccessRule &wi) {
  switch (wi.action_case()) {
    case ::pbv2::FileAccessRule::kAdd: return FaaRuleFromProtoFAARuleAdd(wi.add());
    case ::pbv2::FileAccessRule::kRemove: return FaaRuleFromProtoFAARuleRemove(wi.remove());
    default: return nil;
  }
}

template <bool IsV2>
SNTRule *RuleFromProtoRule(
    const typename santa::ProtoTraits<std::bool_constant<IsV2>>::RuleT &rule) {
  using Traits = santa::ProtoTraits<std::bool_constant<IsV2>>;
  NSString *identifier = StringToNSString(rule.identifier());
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  if (!identifier.length) identifier = StringToNSString(rule.deprecated_sha256());
#pragma clang diagnostic pop
  if (!identifier.length) {
    LOGE(@"Failed to process rule with no identifier");
    return nil;
  }

  SNTRuleState state;
  switch (rule.policy()) {
    case Traits::ALLOWLIST: state = SNTRuleStateAllow; break;
    case Traits::ALLOWLIST_COMPILER: state = SNTRuleStateAllowCompiler; break;
    case Traits::BLOCKLIST: state = SNTRuleStateBlock; break;
    case Traits::SILENT_BLOCKLIST: state = SNTRuleStateSilentBlock; break;
    case Traits::REMOVE: state = SNTRuleStateRemove; break;
    case Traits::CEL: state = SNTRuleStateCEL; break;
    default: LOGE(@"Failed to process rule with unknown policy: %d", rule.policy()); return nil;
  }

  SNTRuleType type;
  switch (rule.rule_type()) {
    case Traits::BINARY: type = SNTRuleTypeBinary; break;
    case Traits::CERTIFICATE: type = SNTRuleTypeCertificate; break;
    case Traits::TEAMID: type = SNTRuleTypeTeamID; break;
    case Traits::SIGNINGID: type = SNTRuleTypeSigningID; break;
    case Traits::CDHASH: type = SNTRuleTypeCDHash; break;
    default: LOGE(@"Failed to process rule with unknown type: %d", rule.rule_type()); return nil;
  }

  const std::string &custom_msg = rule.custom_msg();
  NSString *customMsg = (!custom_msg.empty()) ? StringToNSString(custom_msg) : nil;

  const std::string &custom_url = rule.custom_url();
  NSString *customURL = (!custom_url.empty()) ? StringToNSString(custom_url) : nil;

  const std::string &cel_expr = rule.cel_expr();
  NSString *celExpr = (!cel_expr.empty()) ? StringToNSString(cel_expr) : nil;

  return [[SNTRule alloc] initWithIdentifier:identifier
                                       state:state
                                        type:type
                                   customMsg:customMsg
                                   customURL:customURL
                                     celExpr:celExpr];
}

template <bool IsV2>
void ProcessBundleNotificationsForRule(
    SNTSyncRuleDownload *self, SNTRule *rule,
    const typename santa::ProtoTraits<std::bool_constant<IsV2>>::RuleT *protoRule) {
  // Display a system notification if notification_app_name is set and this is not a clean sync.
  NSString *appName = StringToNSString(protoRule->notification_app_name());
  if (appName.length) {
    // If notification_app_name is set but this is a clean sync, return early. We don't want to
    // spam users with notifications for many apps that might be included in a clean sync, and
    // we don't want to fallback to the deprecated behavior. Also ignore app name if the rule state
    // is remove.
    if (self.syncState.syncType != SNTSyncTypeNormal || rule.state == SNTRuleStateRemove) return;
    [[SNTPushNotificationsTracker tracker] addNotification:[@{
                                             kFileName : appName,
                                             kFileBundleBinaryCount : @(0)
                                           } mutableCopy]
                                                   forHash:rule.identifier];
    return;
  }

  // If notification_app_name is not set, continue processing with deprecated behavior.
  ProcessDeprecatedBundleNotificationsForRule<IsV2>(rule, protoRule);
}

template <bool IsV2>
void ProcessDeprecatedBundleNotificationsForRule(
    SNTRule *rule, const typename santa::ProtoTraits<std::bool_constant<IsV2>>::RuleT *protoRule) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  // Check rule for extra notification related info.
  if (rule.state == SNTRuleStateAllow || rule.state == SNTRuleStateAllowCompiler) {
    // primaryHash is the bundle hash if there was a bundle hash included in the rule, otherwise
    // it is simply the binary hash.
    NSString *primaryHash = StringToNSString(protoRule->file_bundle_hash());
    if (primaryHash.length != 64) {
      primaryHash = rule.identifier;
    }

    // As we read in rules, we update the "remaining count" information. This count represents the
    // number of rules associated with the primary hash that still need to be downloaded and added.
    [[SNTPushNotificationsTracker tracker]
        decrementPendingRulesForHash:primaryHash
                      totalRuleCount:@(protoRule->file_bundle_binary_count())];
  }
#pragma clang diagnostic push
}

@implementation SNTSyncRuleDownload

- (NSURL *)stageURL {
  NSString *stageName = [@"ruledownload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  // Grab the new rules from server
  // SNTDownloadedRuleSets *newRules = [self downloadNewRulesFromServer];
  SNTDownloadedRuleSets *newRules;
  if (self.syncState.isSyncV2) {
    newRules = DownloadNewRulesFromServer<true>(self);
  } else {
    newRules = DownloadNewRulesFromServer<false>(self);
  }
  // `downloadNewRulesFromServer` returns nil if there was a problem with the download
  if (!newRules) {
    return NO;
  }
  // If the request was successfully completed, but no new rules received, just return
  if (!newRules.executionRules.count && !newRules.fileAccessRules.count) {
    return YES;
  }

  // Tell santad to add the new rules to the database.
  // Wait until finished or until 5 minutes pass.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSError *error;
  [[self.daemonConn remoteObjectProxy]
      databaseRuleAddExecutionRules:newRules.executionRules
                    fileAccessRules:newRules.fileAccessRules
                        ruleCleanup:SyncTypeToRuleCleanup(self.syncState.syncType)
                             source:SNTRuleAddSourceSyncService
                              reply:^(NSError *e) {
                                error = e;
                                dispatch_semaphore_signal(sema);
                              }];
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_SEC))) {
    SLOGE(@"Failed to add rule(s) to database: timeout sending rules to daemon");
    return NO;
  }

  if (error) {
    SLOGE(@"Failed to add rule(s) to database: %@", error.localizedDescription);
    SLOGD(@"Failure reason: %@", error.localizedFailureReason);
    return NO;
  }

  // Tell santad to record a successful rules sync and wait for it to finish.
  sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] updateSyncSettings:RuleSyncConfigBundle()
                                                    reply:^{
                                                      dispatch_semaphore_signal(sema);
                                                    }];
  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

  if (newRules.executionRules.count) {
    SLOGI(@"Processed %lu execution rules", newRules.executionRules.count);
  }

  if (newRules.fileAccessRules.count) {
    SLOGI(@"Processed %lu file access rules", newRules.fileAccessRules.count);
  }

  // Send out push notifications about any newly allowed binaries
  // that had been previously blocked by santad.
  [self announceUnblockingRules:newRules.executionRules];
  return YES;
}

// Send out push notifications for allowed bundles/binaries whose rule download was preceded by
// an associated announcing FCM message.
- (void)announceUnblockingRules:(NSArray<SNTRule *> *)newRules {
  if (newRules.count == 0) {
    // No new execution rules received
    return;
  }

  NSMutableArray *processed = [NSMutableArray array];
  SNTPushNotificationsTracker *tracker = [SNTPushNotificationsTracker tracker];
  [[tracker all]
      enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSDictionary *notifier, BOOL *stop) {
        // Each notifier object is a dictionary with name and count keys. If the count has been
        // decremented to zero, then this means that we have downloaded all of the rules associated
        // with this SHA256 hash (which might be a bundle hash or a binary hash), in which case we
        // are OK to show a notification that the named bundle/binary can be run.
        NSNumber *remaining = notifier[kFileBundleBinaryCount];
        if (remaining && [remaining intValue] == 0) {
          [processed addObject:key];
          NSString *app = notifier[kFileName];
          [[self.daemonConn remoteObjectProxy] postRuleSyncNotificationForApplication:app
                                                                                reply:^{
                                                                                }];
        }
      }];

  [tracker removeNotificationsForHashes:processed];
}

@end
