/// Copyright 2015 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

extern NSString *const kDefaultXSRFTokenHeader;
extern NSString *const kXSRFTokenHeader;

extern NSString *const kSerialNumber;
extern NSString *const kHostname;
extern NSString *const kSantaVer;
extern NSString *const kOSVer;
extern NSString *const kOSBuild;
extern NSString *const kModelIdentifier;
extern NSString *const kPrimaryUser;
extern NSString *const kRequestCleanSync;
extern NSString *const kBatchSize;
extern NSString *const kUploadLogsURL;
extern NSString *const kClientMode;
extern NSString *const kClientModeMonitor;
extern NSString *const kClientModeLockdown;
extern NSString *const kBlockUSBMount;
extern NSString *const kRemountUSBMode;
extern NSString *const kCleanSyncDeprecated;
extern NSString *const kSyncType;
extern NSString *const kAllowedPathRegex;
extern NSString *const kAllowedPathRegexDeprecated;
extern NSString *const kBlockedPathRegex;
extern NSString *const kBlockedPathRegexDeprecated;
extern NSString *const kBinaryRuleCount;
extern NSString *const kCertificateRuleCount;
extern NSString *const kCompilerRuleCount;
extern NSString *const kTransitiveRuleCount;
extern NSString *const kTeamIDRuleCount;
extern NSString *const kSigningIDRuleCount;
extern NSString *const kCDHashRuleCount;
extern NSString *const kFullSyncInterval;
extern NSString *const kFCMToken;
extern NSString *const kFCMFullSyncInterval;
extern NSString *const kFCMGlobalRuleSyncDeadline;
extern NSString *const kEnableBundles;
extern NSString *const kEnableBundlesDeprecated;
extern NSString *const kEnableTransitiveRules;
extern NSString *const kEnableTransitiveRulesDeprecated;
extern NSString *const kEnableTransitiveRulesSuperDeprecated;
extern NSString *const kEnableAllEventUpload;
extern NSString *const kDisableUnknownEventUpload;
extern NSString *const kOverrideFileAccessAction;

extern NSString *const kEvents;
extern NSString *const kFileSHA256;
extern NSString *const kFilePath;
extern NSString *const kFileName;
extern NSString *const kExecutingUser;
extern NSString *const kExecutionTime;
extern NSString *const kDecision;
extern NSString *const kDecisionAllowUnknown;
extern NSString *const kDecisionAllowBinary;
extern NSString *const kDecisionAllowCertificate;
extern NSString *const kDecisionAllowScope;
extern NSString *const kDecisionAllowTeamID;
extern NSString *const kDecisionAllowSigningID;
extern NSString *const kDecisionAllowCDHash;
extern NSString *const kDecisionBlockUnknown;
extern NSString *const kDecisionBlockBinary;
extern NSString *const kDecisionBlockCertificate;
extern NSString *const kDecisionBlockScope;
extern NSString *const kDecisionBlockTeamID;
extern NSString *const kDecisionBlockSigningID;
extern NSString *const kDecisionBlockCDHash;
extern NSString *const kDecisionUnknown;
extern NSString *const kDecisionBundleBinary;
extern NSString *const kLoggedInUsers;
extern NSString *const kCurrentSessions;
extern NSString *const kFileBundleID;
extern NSString *const kFileBundlePath;
extern NSString *const kFileBundleExecutableRelPath;
extern NSString *const kFileBundleName;
extern NSString *const kFileBundleVersion;
extern NSString *const kFileBundleShortVersionString;
extern NSString *const kFileBundleHash;
extern NSString *const kFileBundleHashMilliseconds;
extern NSString *const kFileBundleBinaryCount;
extern NSString *const kPID;
extern NSString *const kPPID;
extern NSString *const kParentName;
extern NSString *const kSigningChain;
extern NSString *const kCertSHA256;
extern NSString *const kCertCN;
extern NSString *const kCertOrg;
extern NSString *const kCertOU;
extern NSString *const kCertValidFrom;
extern NSString *const kCertValidUntil;
extern NSString *const kTeamID;
extern NSString *const kSigningID;
extern NSString *const kCDHash;
extern NSString *const kQuarantineDataURL;
extern NSString *const kQuarantineRefererURL;
extern NSString *const kQuarantineTimestamp;
extern NSString *const kQuarantineAgentBundleID;
extern NSString *const kEventUploadBundleBinaries;

extern NSString *const kRules;
extern NSString *const kRuleSHA256;
extern NSString *const kRuleIdentifier;
extern NSString *const kRulePolicy;
extern NSString *const kRulePolicyAllowlist;
extern NSString *const kRulePolicyAllowlistLocalBinary;
extern NSString *const kRulePolicyAllowlistLocalSigningID;
extern NSString *const kRulePolicyAllowlistDeprecated;
extern NSString *const kRulePolicyAllowlistCompiler;
extern NSString *const kRulePolicyAllowlistCompilerDeprecated;
extern NSString *const kRulePolicyBlocklist;
extern NSString *const kRulePolicyBlocklistDeprecated;
extern NSString *const kRulePolicySilentBlocklist;
extern NSString *const kRulePolicySilentBlocklistDeprecated;
extern NSString *const kRulePolicyRemove;
extern NSString *const kRulePolicyCEL;
extern NSString *const kRuleType;
extern NSString *const kRuleTypeBinary;
extern NSString *const kRuleTypeCertificate;
extern NSString *const kRuleTypeTeamID;
extern NSString *const kRuleTypeSigningID;
extern NSString *const kRuleTypeCDHash;
extern NSString *const kRuleCustomMsg;
extern NSString *const kRuleCustomURL;
extern NSString *const kRuleComment;
extern NSString *const kRuleCELExpr;
extern NSString *const kCursor;

extern NSString *const kBackoffInterval;

extern NSString *const kFullSync;
extern NSString *const kRuleSync;
extern NSString *const kConfigSync;
extern NSString *const kLogSync;

extern const NSUInteger kDefaultEventBatchSize;

extern NSString *const kPostflightRulesReceived;
extern NSString *const kPostflightRulesProcessed;

///
///  kDefaultFullSyncInterval
///  kDefaultFCMFullSyncInterval
///  kDefaultFCMGlobalRuleSyncDeadline
///
///  Are represented in seconds
///
extern const NSUInteger kDefaultFullSyncInterval;
extern const NSUInteger kDefaultPushNotificationsFullSyncInterval;
extern const NSUInteger kDefaultPushNotificationsGlobalRuleSyncDeadline;
