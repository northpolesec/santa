/// Copyright 2014-2022 Google Inc. All rights reserved.
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

#import "Source/common/SNTConfigurator.h"

#include <mach/mach_time.h>
#include <sys/stat.h>

#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTModeTransition.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStrengthify.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SystemResources.h"

// Ensures the given object is an NSArray and only contains NSString value types
static NSArray<NSString *> *EnsureArrayOfStrings(id obj) {
  if (![obj isKindOfClass:[NSArray class]]) {
    return nil;
  }

  for (id item in obj) {
    if (![item isKindOfClass:[NSString class]]) {
      return nil;
    }
  }

  return obj;
}

@interface SNTConfigurator ()
@property(readonly, nonatomic) NSUserDefaults *defaults;

/// Keys and expected value types.
@property(readonly, nonatomic) NSDictionary *syncServerKeyTypes;
@property(readonly, nonatomic) NSDictionary *forcedConfigKeyTypes;

/// Holds the configurations from a sync server and mobileconfig.
@property(atomic) NSDictionary *syncState;
@property(atomic) NSMutableDictionary *configState;
@property(atomic) NSDictionary *state;

@property(readonly, nonatomic) NSString *syncStateFilePath;
@property(readonly, nonatomic) NSString *stateFilePath;

typedef BOOL (^StateFileAccessAuthorizer)(void);
@property(nonatomic, copy) StateFileAccessAuthorizer syncStateAccessAuthorizerBlock;
@property(nonatomic, copy) StateFileAccessAuthorizer stateAccessAuthorizerBlock;

// Re-declare read/write for KVO
@property BOOL inTemporaryMonitorMode;

@end

@implementation SNTConfigurator

/// The hard-coded path to the sync state file.
NSString *const kSyncStateFilePath = @"/var/db/santa/sync-state.plist";

/// The hard-coded path to the state file.
NSString *const kStateFilePath = @"/var/db/santa/state.plist";
NSString *const kOldStateFilePath = @"/var/db/santa/stats-state.plist";

/// Keys associated with the state file.
static NSString *const kStateStatsKey = @"Stats";
static NSString *const kStateStatsLastSubmissionAttemptKey = @"LastAttempt";
static NSString *const kStateStatsLastSubmissionVersionKey = @"LastVersion";
static NSString *const kStateTempMonitorModeKey = @"TMM";
static NSString *const kStateTempMonitorModeBootSessionUUIDKey = @"UUID";
static NSString *const kStateTempMonitorModeDeadlineKey = @"Deadline";

#ifdef DEBUG
NSString *const kConfigOverrideFilePath = @"/var/db/santa/config-overrides.plist";
#endif

/// The domain used by mobileconfig.
static const CFStringRef kMobileConfigDomain = CFSTR("com.northpolesec.santa");

/// The keys managed by a mobileconfig.
static NSString *const kStaticRulesKey = @"StaticRules";
static NSString *const kSyncBaseURLKey = @"SyncBaseURL";
static NSString *const kSyncEnableProtoTransfer = @"SyncEnableProtoTransfer";
static NSString *const kSyncProxyConfigKey = @"SyncProxyConfiguration";
static NSString *const kSyncExtraHeadersKey = @"SyncExtraHeaders";
static NSString *const kSyncEnableCleanSyncEventUpload = @"SyncEnableCleanSyncEventUpload";
static NSString *const kClientAuthCertificateFileKey = @"ClientAuthCertificateFile";
static NSString *const kClientAuthCertificatePasswordKey = @"ClientAuthCertificatePassword";
static NSString *const kClientAuthCertificateCNKey = @"ClientAuthCertificateCN";
static NSString *const kClientAuthCertificateIssuerKey = @"ClientAuthCertificateIssuerCN";
static NSString *const kServerAuthRootsDataKey = @"ServerAuthRootsData";
static NSString *const kServerAuthRootsFileKey = @"ServerAuthRootsFile";
static NSString *const kEnableStatsCollectionKey = @"EnableStatsCollection";
static NSString *const kStatsOrganizationID = @"StatsOrganizationID";

static NSString *const kMachineOwnerKey = @"MachineOwner";
static NSString *const kMachineOwnerGroupsKey = @"MachineOwnerGroups";
static NSString *const kMachineIDKey = @"MachineID";
static NSString *const kMachineOwnerPlistFileKey = @"MachineOwnerPlist";
static NSString *const kMachineOwnerPlistKeyKey = @"MachineOwnerKey";
static NSString *const kMachineOwnerGroupsPlistKeyKey = @"MachineOwnerGroupsKey";
static NSString *const kMachineIDPlistFileKey = @"MachineIDPlist";
static NSString *const kMachineIDPlistKeyKey = @"MachineIDKey";

static NSString *const kEnableStandalonePasswordFallbackKey = @"EnableStandalonePasswordFallback";
static NSString *const kEnableSilentModeKey = @"EnableSilentMode";
static NSString *const kEnableSilentTTYModeKey = @"EnableSilentTTYMode";
static NSString *const kAboutTextKey = @"AboutText";
static NSString *const kMoreInfoURLKey = @"MoreInfoURL";
static NSString *const kEventDetailURLKey = @"EventDetailURL";
static NSString *const kEventDetailTextKey = @"EventDetailText";
static NSString *const kDismissTextKey = @"DismissText";
static NSString *const kUnknownBlockMessage = @"UnknownBlockMessage";
static NSString *const kBannedBlockMessage = @"BannedBlockMessage";
static NSString *const kBannedUSBBlockMessage = @"BannedUSBBlockMessage";
static NSString *const kRemountUSBBlockMessage = @"RemountUSBBlockMessage";

static NSString *const kModeNotificationMonitor = @"ModeNotificationMonitor";
static NSString *const kModeNotificationLockdown = @"ModeNotificationLockdown";
static NSString *const kModeNotificationStandalone = @"ModeNotificationStandalone";
static NSString *const kEnableNotificationSilences = @"EnableNotificationSilences";
static NSString *const kFunFontsOnSpecificDays = @"FunFontsOnSpecificDays";

static NSString *const kEnablePageZeroProtectionKey = @"EnablePageZeroProtection";
static NSString *const kEnableBadSignatureProtectionKey = @"EnableBadSignatureProtection";
static NSString *const kFailClosedKey = @"FailClosed";
static NSString *const kDisableUnknownEventUploadKey = @"DisableUnknownEventUpload";

static NSString *const kFileChangesRegexKey = @"FileChangesRegex";
static NSString *const kFileChangesPrefixFiltersKey = @"FileChangesPrefixFilters";

static NSString *const kEventLogType = @"EventLogType";
static NSString *const kEventLogPath = @"EventLogPath";
static NSString *const kSpoolDirectory = @"SpoolDirectory";
static NSString *const kSpoolDirectoryFileSizeThresholdKB = @"SpoolDirectoryFileSizeThresholdKB";
static NSString *const kSpoolDirectorySizeThresholdMB = @"SpoolDirectorySizeThresholdMB";
static NSString *const kSpoolDirectoryEventMaxFlushTimeSec = @"SpoolDirectoryEventMaxFlushTimeSec";

static NSString *const kFileAccessPolicy = @"FileAccessPolicy";
static NSString *const kFileAccessPolicyPlist = @"FileAccessPolicyPlist";
static NSString *const kFileAccessBlockMessage = @"FileAccessBlockMessage";
static NSString *const kFileAccessPolicyUpdateIntervalSec = @"FileAccessPolicyUpdateIntervalSec";
static NSString *const kFileAccessGlobalLogsPerSec = @"FileAccessGlobalLogsPerSec";
static NSString *const kFileAccessGlobalWindowSizeSec = @"FileAccessGlobalWindowSizeSec";

static NSString *const kEnableTelemetryExport = @"EnableTelemetryExport";
static NSString *const kTelemetryExportIntervalSec = @"TelemetryExportIntervalSec";
static NSString *const kTelemetryExportTimeoutSec = @"TelemetryExportTimeoutSec";
static NSString *const kTelemetryExportBatchThresholdSizeMB =
    @"TelemetryExportBatchThresholdSizeMB";
static NSString *const kTelemetryExportMaxFilesPerBatch = @"TelemetryExportMaxFilesPerBatch";

static NSString *const kEnableMachineIDDecoration = @"EnableMachineIDDecoration";

static NSString *const kEnableForkAndExitLogging = @"EnableForkAndExitLogging";
static NSString *const kIgnoreOtherEndpointSecurityClients = @"IgnoreOtherEndpointSecurityClients";
static NSString *const kTelemetryKey = @"Telemetry";

static NSString *const kClientContentEncoding = @"SyncClientContentEncoding";

static NSString *const kFCMProject = @"FCMProject";
static NSString *const kFCMEntity = @"FCMEntity";
static NSString *const kFCMAPIKey = @"FCMAPIKey";

static NSString *const kEnableAPNS = @"EnableAPNS";

static NSString *const kEnableNATS = @"EnableNATS";

static NSString *const kEntitlementsPrefixFilterKey = @"EntitlementsPrefixFilter";
static NSString *const kEntitlementsTeamIDFilterKey = @"EntitlementsTeamIDFilter";

static NSString *const kOnStartUSBOptions = @"OnStartUSBOptions";

static NSString *const kMetricFormat = @"MetricFormat";
static NSString *const kMetricURL = @"MetricURL";
static NSString *const kMetricExportInterval = @"MetricExportInterval";
static NSString *const kMetricExportTimeout = @"MetricExportTimeout";
static NSString *const kMetricExtraLabels = @"MetricExtraLabels";

static NSString *const kEnabledProcessAnnotations = @"EnabledProcessAnnotations";

// The keys managed by a sync server or mobileconfig.
static NSString *const kClientModeKey = @"ClientMode";
static NSString *const kBlockUSBMountKey = @"BlockUSBMount";
static NSString *const kRemountUSBModeKey = @"RemountUSBMode";
static NSString *const kEnableTransitiveRulesKey = @"EnableTransitiveRules";
static NSString *const kEnableTransitiveRulesKeyDeprecated = @"EnableTransitiveWhitelisting";
static NSString *const kAllowedPathRegexKey = @"AllowedPathRegex";
static NSString *const kAllowedPathRegexKeyDeprecated = @"WhitelistRegex";
static NSString *const kBlockedPathRegexKey = @"BlockedPathRegex";
static NSString *const kBlockedPathRegexKeyDeprecated = @"BlacklistRegex";
static NSString *const kEnableAllEventUploadKey = @"EnableAllEventUpload";
static NSString *const kOverrideFileAccessActionKey = @"OverrideFileAccessAction";
static NSString *const kEnableBundlesKey = @"EnableBundles";

// The keys managed by a sync server.
static NSString *const kFullSyncLastSuccess = @"FullSyncLastSuccess";
static NSString *const kRuleSyncLastSuccess = @"RuleSyncLastSuccess";
static NSString *const kSyncCleanRequiredDeprecated = @"SyncCleanRequired";
static NSString *const kSyncTypeRequired = @"SyncTypeRequired";
static NSString *const kExportConfigurationKey = @"ExportConfiguration";
static NSString *const kModeTransitionKey = @"ModeTransition";

- (instancetype)init {
  return [self initWithSyncStateFile:kSyncStateFilePath
      stateFile:kStateFilePath
      oldStateFile:kOldStateFilePath
      syncStateAccessAuthorizer:^BOOL() {
        // Only access the sync state if a sync server is configured and running as root
        return self.syncBaseURL != nil && geteuid() == 0;
      }
      stateAccessAuthorizer:^BOOL() {
        return geteuid() == 0 && [[[NSProcessInfo processInfo] processName]
                                     isEqualToString:@"com.northpolesec.santa.daemon"];
      }];
}

- (instancetype)initWithSyncStateFile:(NSString *)syncStateFilePath
                            stateFile:(NSString *)stateFilePath
                         oldStateFile:(NSString *)oldStateFilePath
            syncStateAccessAuthorizer:(StateFileAccessAuthorizer)syncStateAccessAuthorizer
                stateAccessAuthorizer:(StateFileAccessAuthorizer)stateAccessAuthorizer {
  self = [super init];
  if (self) {
    Class number = [NSNumber class];
    Class re = [NSRegularExpression class];
    Class date = [NSDate class];
    Class string = [NSString class];
    Class data = [NSData class];
    Class array = [NSArray class];
    Class dictionary = [NSDictionary class];
    _syncServerKeyTypes = @{
      kClientModeKey : number,
      kEnableTransitiveRulesKey : number,
      kEnableTransitiveRulesKeyDeprecated : number,
      kAllowedPathRegexKey : re,
      kAllowedPathRegexKeyDeprecated : re,
      kBlockedPathRegexKey : re,
      kBlockedPathRegexKeyDeprecated : re,
      kBlockUSBMountKey : number,
      kRemountUSBModeKey : array,
      kFullSyncLastSuccess : date,
      kRuleSyncLastSuccess : date,
      kSyncCleanRequiredDeprecated : number,
      kSyncTypeRequired : number,
      kEnableAllEventUploadKey : number,
      kOverrideFileAccessActionKey : string,
      kEnableBundlesKey : number,
      kExportConfigurationKey : data,
      kModeTransitionKey : data,
    };
    _forcedConfigKeyTypes = @{
      kClientModeKey : number,
      kFailClosedKey : number,
      kEnableTransitiveRulesKey : number,
      kEnableTransitiveRulesKeyDeprecated : number,
      kFileChangesRegexKey : re,
      kFileChangesPrefixFiltersKey : array,
      kAllowedPathRegexKey : re,
      kAllowedPathRegexKeyDeprecated : re,
      kBlockedPathRegexKey : re,
      kBlockedPathRegexKeyDeprecated : re,
      kBlockUSBMountKey : number,
      kRemountUSBModeKey : array,
      kOnStartUSBOptions : string,
      kEnablePageZeroProtectionKey : number,
      kEnableBadSignatureProtectionKey : number,
      kEnableStandalonePasswordFallbackKey : number,
      kEnableSilentModeKey : number,
      kEnableSilentTTYModeKey : number,
      kAboutTextKey : string,
      kMoreInfoURLKey : string,
      kEventDetailURLKey : string,
      kEventDetailTextKey : string,
      kDismissTextKey : string,
      kUnknownBlockMessage : string,
      kBannedBlockMessage : string,
      kBannedUSBBlockMessage : string,
      kRemountUSBBlockMessage : string,
      kModeNotificationMonitor : string,
      kModeNotificationLockdown : string,
      kModeNotificationStandalone : string,
      kEnableNotificationSilences : number,
      kFunFontsOnSpecificDays : number,
      kStaticRulesKey : array,
      kSyncBaseURLKey : string,
      kSyncEnableProtoTransfer : number,
      kSyncEnableCleanSyncEventUpload : number,
      kSyncProxyConfigKey : dictionary,
      kSyncExtraHeadersKey : dictionary,
      kClientAuthCertificateFileKey : string,
      kClientAuthCertificatePasswordKey : string,
      kClientAuthCertificateCNKey : string,
      kClientAuthCertificateIssuerKey : string,
      kClientContentEncoding : string,
      kServerAuthRootsDataKey : data,
      kServerAuthRootsFileKey : string,
      kEnableStatsCollectionKey : number,
      kStatsOrganizationID : string,
      kMachineOwnerKey : string,
      kMachineOwnerGroupsKey : array,
      kMachineIDKey : string,
      kMachineOwnerPlistFileKey : string,
      kMachineOwnerPlistKeyKey : string,
      kMachineOwnerGroupsPlistKeyKey : string,
      kMachineIDPlistFileKey : string,
      kMachineIDPlistKeyKey : string,
      kEventLogType : string,
      kEventLogPath : string,
      kSpoolDirectory : string,
      kSpoolDirectoryFileSizeThresholdKB : number,
      kSpoolDirectorySizeThresholdMB : number,
      kSpoolDirectoryEventMaxFlushTimeSec : number,
      kFileAccessPolicy : dictionary,
      kFileAccessPolicyPlist : string,
      kFileAccessBlockMessage : string,
      kFileAccessPolicyUpdateIntervalSec : number,
      kFileAccessGlobalWindowSizeSec : number,
      kFileAccessGlobalLogsPerSec : number,
      kEnableTelemetryExport : number,
      kTelemetryExportIntervalSec : number,
      kTelemetryExportTimeoutSec : number,
      kTelemetryExportBatchThresholdSizeMB : number,
      kTelemetryExportMaxFilesPerBatch : number,
      kEnableMachineIDDecoration : number,
      kEnableForkAndExitLogging : number,
      kIgnoreOtherEndpointSecurityClients : number,
      kFCMProject : string,
      kFCMEntity : string,
      kFCMAPIKey : string,
      kEnableAPNS : number,
      kEnableNATS : number,
      kMetricFormat : string,
      kMetricURL : string,
      kMetricExportInterval : number,
      kMetricExportTimeout : number,
      kMetricExtraLabels : dictionary,
      kEnableAllEventUploadKey : number,
      kDisableUnknownEventUploadKey : number,
      kOverrideFileAccessActionKey : string,
      kEntitlementsPrefixFilterKey : array,
      kEntitlementsTeamIDFilterKey : array,
      kEnabledProcessAnnotations : array,
      kTelemetryKey : array,
    };

    _syncStateFilePath = syncStateFilePath;
    _stateFilePath = stateFilePath;
    _syncStateAccessAuthorizerBlock = syncStateAccessAuthorizer;
    _stateAccessAuthorizerBlock = stateAccessAuthorizer;

    // This is used to keep KVO on changes, but we use `CFPreferences*` for reading.
    _defaults = [NSUserDefaults standardUserDefaults];
    [_defaults addSuiteNamed:@"com.northpolesec.santa"];

    _configState = [self readForcedConfig];

    _syncState = [self readSyncStateFromDisk] ?: [NSMutableDictionary dictionary];
    if ([self migrateDeprecatedSyncStateKeys]) {
      // Save the updated sync state if any keys were migrated.
      [self saveSyncStateToDisk];
    }

    if (self.stateAccessAuthorizerBlock()) {
      [self migrateDeprecatedStatsStatePath:oldStateFilePath];
      _state = [self readStateFromDisk] ?: [NSDictionary dictionary];
    }

    [self startWatchingDefaults];
  }
  return self;
}

#pragma mark Singleton retriever

// The returned value is marked unsafe_unretained to avoid unnecessary retain/release handling.
// The object returned is guaranteed to exist for the lifetime of the process so there's no need
// to do this handling.
static SNTConfigurator *sharedConfigurator = nil;
+ (__unsafe_unretained instancetype)configurator {
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    sharedConfigurator = [[SNTConfigurator alloc] init];
  });
  return sharedConfigurator;
}

#ifdef DEBUG
- (instancetype)initWithStaticConfig:(NSDictionary *)config {
  self = [super init];
  if (self) {
    _configState = [config mutableCopy];
    _syncState = [config mutableCopy];
  }
  return self;
}

+ (void)overrideConfig:(NSDictionary *)config {
  (void)[SNTConfigurator configurator];  // burn the onceToken
  sharedConfigurator = [[SNTConfigurator alloc] initWithStaticConfig:config];
}
#endif

+ (NSSet *)syncAndConfigStateSet {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [[self syncStateSet] setByAddingObjectsFromSet:[self configStateSet]];
  });
  return set;
}

+ (NSSet *)syncStateSet {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [NSSet setWithObject:NSStringFromSelector(@selector(syncState))];
  });
  return set;
}

+ (NSSet *)configStateSet {
  static NSSet *set;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    set = [NSSet setWithObject:NSStringFromSelector(@selector(configState))];
  });
  return set;
}

#pragma mark KVO Dependencies

+ (NSSet *)keyPathsForValuesAffectingClientMode {
  return [[self syncAndConfigStateSet]
      setByAddingObject:NSStringFromSelector(@selector(inTemporaryMonitorMode))];
}

+ (NSSet *)keyPathsForValuesAffectingAllowlistPathRegex {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBlocklistPathRegex {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileChangesRegex {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileChangesPrefixFiltersKey {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingStaticRules {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncBaseURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncEnableProtoTransfer {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncExtraHeaders {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableCleanSyncEventUpload {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnablePageZeroProtection {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableStandalonePasswordFallback {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableSilentMode {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingAboutText {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMoreInfoURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventDetailURL {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventDetailText {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingDismissText {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingUnknownBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBannedBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingModeNotificationMonitor {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingModeNotificationLockdown {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableNotificationSilences {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFunFontsOnSpecificDays {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateFile {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificatePassword {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateCn {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncClientAuthCertificateIssuer {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncServerAuthRootsData {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncServerAuthRootsFile {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableStatsCollection {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingStatsOrganizationID {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMachineOwner {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMachineOwnerGroups {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingMachineID {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFullSyncLastSuccess {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingRuleSyncLastSuccess {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSyncTypeRequired {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventLogType {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEventLogPath {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectory {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectoryFileSizeThresholdKB {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectorySizeThresholdMB {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingSpoolDirectoryEventMaxFlushTimeSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessPolicy {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessPolicyPlist {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessPolicyUpdateIntervalSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessGlobalLogsPerSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFileAccessGlobalWindowSizeSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableMachineIDDecoration {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableTransitiveRules {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableAllEventUpload {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingDisableUnknownEventUpload {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableForkAndExitLogging {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingIgnoreOtherEndpointSecurityClients {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmProject {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmEntity {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmAPIKey {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingFcmEnabled {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableAPNS {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableNATS {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableBadSignatureProtection {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBlockUSBMount {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingBannedUSBBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingRemountUSBMode {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingRemountUSBBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingUsbBlockMessage {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingOverrideFileAccessActionKey {
  return [self syncAndConfigStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEntitlementsPrefixFilter {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEntitlementsTeamIDFilter {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingTelemetry {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableTelemetryExport {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingTelemetryExportIntervalSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingTelemetryExportTimeoutSec {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingTelemetryExportBatchThresholdSizeMB {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingTelemetryExportMaxFilesPerBatch {
  return [self configStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingEnableBundles {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingExportConfig {
  return [self syncStateSet];
}

+ (NSSet *)keyPathsForValuesAffectingModeTransition {
  return [self syncStateSet];
}

#pragma mark Public Interface

- (SNTClientMode)clientMode {
  if ([self inTemporaryMonitorMode]) {
    return SNTClientModeMonitor;
  }

  SNTClientMode cm = static_cast<SNTClientMode>([self.syncState[kClientModeKey] integerValue]);
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown || cm == SNTClientModeStandalone) {
    return cm;
  }

  cm = static_cast<SNTClientMode>([self.configState[kClientModeKey] integerValue]);
  if (cm == SNTClientModeMonitor || cm == SNTClientModeLockdown || cm == SNTClientModeStandalone) {
    return cm;
  }

  return SNTClientModeMonitor;
}

- (void)setSyncServerClientMode:(SNTClientMode)newMode {
  if (newMode == SNTClientModeMonitor || newMode == SNTClientModeLockdown ||
      newMode == SNTClientModeStandalone) {
    [self updateSyncStateForKey:kClientModeKey value:@(newMode)];
  }
}

- (void)enterTemporaryMonitorModeForSeconds:(uint32_t)duration {
  @synchronized(self) {
    //NB: Using continuous time so that the clock advances while the system is asleep
    uint64_t deadline = AddNanosecondsToMachTime(duration * NSEC_PER_SEC, mach_continuous_time());
    [self updateStateSynchronizedKey:kStateTempMonitorModeKey
                               value:@{
                                 kStateTempMonitorModeBootSessionUUIDKey :
                                     [SNTSystemInfo bootSessionUUID],
                                 kStateTempMonitorModeDeadlineKey : @(deadline),
                               }];
    self.inTemporaryMonitorMode = YES;
  }
}

- (void)leaveTemporaryMonitorMode {
  @synchronized(self) {
    self.inTemporaryMonitorMode = NO;

    // Clear the temporary Monitor Mode state now that it has ended
    [self updateStateSynchronizedKey:kStateTempMonitorModeKey value:nil];
  }
}

- (NSNumber *)temporaryMonitorModeStateSecondsRemaining {
  NSNumber *deadline = self.state[kStateTempMonitorModeKey][kStateTempMonitorModeDeadlineKey];
  if (!deadline) {
    return nil;
  }

  uint64_t deadlineMachTime = [deadline unsignedLongLongValue];
  uint64_t machTime = mach_continuous_time();

  // Check if time expired
  if (deadlineMachTime <= machTime) {
    return nil;
  }

  // Convert time remaining to seconds
  return @(MachTimeToNanos(deadlineMachTime - machTime) / NSEC_PER_SEC);
}

- (BOOL)failClosed {
  NSNumber *n = self.configState[kFailClosedKey];
  BOOL runningInLockdownClientMode =
      self.clientMode == SNTClientModeLockdown || self.clientMode == SNTClientModeStandalone;
  return [n boolValue] && runningInLockdownClientMode;
}

- (BOOL)enableTransitiveRules {
  NSNumber *n = self.syncState[kEnableTransitiveRulesKey];
  if (n) return [n boolValue];

  n = self.syncState[kEnableTransitiveRulesKeyDeprecated];
  if (n) return [n boolValue];

  n = self.configState[kEnableTransitiveRulesKeyDeprecated];
  if (n) return [n boolValue];

  return [self.configState[kEnableTransitiveRulesKey] boolValue];
}

- (void)setEnableTransitiveRules:(BOOL)enabled {
  [self updateSyncStateForKey:kEnableTransitiveRulesKey value:@(enabled)];
}

- (BOOL)enableBundles {
  return [self.syncState[kEnableBundlesKey] boolValue];
}

- (void)setEnableBundles:(BOOL)enable {
  [self updateSyncStateForKey:kEnableBundlesKey value:@(enable)];
}
- (SNTExportConfiguration *)exportConfig {
  return [SNTExportConfiguration deserialize:self.syncState[kExportConfigurationKey]];
}

- (void)setSyncServerExportConfig:(SNTExportConfiguration *)exportConfig {
  [self updateSyncStateForKey:kExportConfigurationKey value:[exportConfig serialize]];
}

- (SNTModeTransition *)modeTransition {
  return [SNTModeTransition deserialize:self.syncState[kModeTransitionKey]];
}

- (void)setSyncServerModeTransition:(SNTModeTransition *)modeTransition {
  if (modeTransition.type == SNTModeTransitionTypeRevoke) {
    // On revoke, set the value to nil to remove the key from the dictionary
    [self updateSyncStateForKey:kModeTransitionKey value:nil];
  } else {
    [self updateSyncStateForKey:kModeTransitionKey value:[modeTransition serialize]];
  }
}

- (NSRegularExpression *)allowedPathRegex {
  NSRegularExpression *r = self.syncState[kAllowedPathRegexKey];
  if (r) return r;

  r = self.syncState[kAllowedPathRegexKeyDeprecated];
  if (r) return r;

  r = self.configState[kAllowedPathRegexKey];
  if (r) return r;

  return self.configState[kAllowedPathRegexKeyDeprecated];
}

- (void)setSyncServerAllowedPathRegex:(NSRegularExpression *)re {
  [self updateSyncStateForKey:kAllowedPathRegexKey value:re];
}

- (NSRegularExpression *)blockedPathRegex {
  NSRegularExpression *r = self.syncState[kBlockedPathRegexKey];
  if (r) return r;

  r = self.syncState[kBlockedPathRegexKeyDeprecated];
  if (r) return r;

  r = self.configState[kBlockedPathRegexKey];
  if (r) return r;

  return self.configState[kBlockedPathRegexKeyDeprecated];
}

- (void)setSyncServerBlockedPathRegex:(NSRegularExpression *)re {
  [self updateSyncStateForKey:kBlockedPathRegexKey value:re];
}

- (NSRegularExpression *)fileChangesRegex {
  return self.configState[kFileChangesRegexKey];
}

- (NSArray *)fileChangesPrefixFilters {
  NSArray *filters = self.configState[kFileChangesPrefixFiltersKey];
  for (id filter in filters) {
    if (![filter isKindOfClass:[NSString class]]) {
      return nil;
    }
  }
  return filters;
}

- (void)setRemountUSBMode:(NSArray<NSString *> *)args {
  [self updateSyncStateForKey:kRemountUSBModeKey value:args];
}

- (NSArray<NSString *> *)remountUSBMode {
  NSArray<NSString *> *args = self.syncState[kRemountUSBModeKey];
  if (!args) {
    args = (NSArray<NSString *> *)self.configState[kRemountUSBModeKey];
  }
  for (id arg in args) {
    if (![arg isKindOfClass:[NSString class]]) {
      return nil;
    }
  }
  return args;
}

- (SNTDeviceManagerStartupPreferences)onStartUSBOptions {
  NSString *action = [self.configState[kOnStartUSBOptions] lowercaseString];

  if ([action isEqualToString:@"unmount"]) {
    return SNTDeviceManagerStartupPreferencesUnmount;
  } else if ([action isEqualToString:@"forceunmount"]) {
    return SNTDeviceManagerStartupPreferencesForceUnmount;
  } else if ([action isEqualToString:@"remount"]) {
    return SNTDeviceManagerStartupPreferencesRemount;
  } else if ([action isEqualToString:@"forceremount"]) {
    return SNTDeviceManagerStartupPreferencesForceRemount;
  } else {
    return SNTDeviceManagerStartupPreferencesNone;
  }
}

- (NSArray<NSDictionary *> *)staticRules {
  return self.configState[kStaticRulesKey];
}

- (NSURL *)syncBaseURL {
  NSString *urlString = self.configState[kSyncBaseURLKey];
  if (urlString.length == 0) {
    // Treat empty values as nil. This is depended upon by callers.
    return nil;
  }
  if (![urlString hasSuffix:@"/"]) {
    urlString = [urlString stringByAppendingString:@"/"];
  }
  NSURL *url = [NSURL URLWithString:urlString];
  return url;
}

- (BOOL)syncEnableProtoTransfer {
  NSNumber *number = self.configState[kSyncEnableProtoTransfer];
  return number ? [number boolValue] : NO;
}

- (NSDictionary *)syncProxyConfig {
  return self.configState[kSyncProxyConfigKey];
}

- (NSDictionary *)syncExtraHeaders {
  return self.configState[kSyncExtraHeadersKey];
}

- (BOOL)enablePageZeroProtection {
  NSNumber *number = self.configState[kEnablePageZeroProtectionKey];
  return number ? [number boolValue] : YES;
}

- (BOOL)enableBadSignatureProtection {
  NSNumber *number = self.configState[kEnableBadSignatureProtectionKey];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableStandalonePasswordFallback {
  NSNumber *number = self.configState[kEnableStandalonePasswordFallbackKey];
  return number ? [number boolValue] : YES;
}

- (BOOL)enableSilentMode {
  NSNumber *number = self.configState[kEnableSilentModeKey];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableSilentTTYMode {
  NSNumber *number = self.configState[kEnableSilentTTYModeKey];
  return number ? [number boolValue] : NO;
}

- (NSString *)aboutText {
  return self.configState[kAboutTextKey];
}

- (NSURL *)moreInfoURL {
  return [NSURL URLWithString:self.configState[kMoreInfoURLKey]];
}

- (NSString *)eventDetailURL {
  return self.configState[kEventDetailURLKey];
}

- (NSString *)eventDetailText {
  return self.configState[kEventDetailTextKey];
}

- (NSString *)dismissText {
  return self.configState[kDismissTextKey];
}

- (NSString *)unknownBlockMessage {
  return self.configState[kUnknownBlockMessage];
}

- (NSString *)bannedBlockMessage {
  return self.configState[kBannedBlockMessage];
}

- (NSString *)bannedUSBBlockMessage {
  return self.configState[kBannedUSBBlockMessage];
}

- (NSString *)remountUSBBlockMessage {
  return self.configState[kRemountUSBBlockMessage];
}

- (NSString *)modeNotificationMonitor {
  return self.configState[kModeNotificationMonitor];
}

- (NSString *)modeNotificationLockdown {
  return self.configState[kModeNotificationLockdown];
}

- (NSString *)modeNotificationStandalone {
  return self.configState[kModeNotificationStandalone];
}

- (BOOL)enableNotificationSilences {
  NSNumber *number = self.configState[kEnableNotificationSilences];
  return number ? [number boolValue] : YES;
}

- (BOOL)funFontsOnSpecificDays {
  return [self.configState[kFunFontsOnSpecificDays] boolValue];
}

- (NSString *)syncClientAuthCertificateFile {
  return self.configState[kClientAuthCertificateFileKey];
}

- (NSString *)syncClientAuthCertificatePassword {
  return self.configState[kClientAuthCertificatePasswordKey];
}

- (NSString *)syncClientAuthCertificateCn {
  return self.configState[kClientAuthCertificateCNKey];
}

- (NSString *)syncClientAuthCertificateIssuer {
  return self.configState[kClientAuthCertificateIssuerKey];
}

- (SNTSyncContentEncoding)syncClientContentEncoding {
  NSString *contentEncoding = [self.configState[kClientContentEncoding] lowercaseString];
  if ([contentEncoding isEqualToString:@"deflate"]) {
    return SNTSyncContentEncodingDeflate;
  } else if ([contentEncoding isEqualToString:@"gzip"]) {
    return SNTSyncContentEncodingGzip;
  } else if ([contentEncoding isEqualToString:@"none"]) {
    return SNTSyncContentEncodingNone;
  } else {
    // Ensure we have the same default zlib behavior Santa's always had otherwise.
    return SNTSyncContentEncodingDeflate;
  }
}

- (NSData *)syncServerAuthRootsData {
  return self.configState[kServerAuthRootsDataKey];
}

- (NSString *)syncServerAuthRootsFile {
  return self.configState[kServerAuthRootsFileKey];
}

- (BOOL)enableStatsCollection {
  NSNumber *e = self.configState[kEnableStatsCollectionKey];
  return ([e boolValue] || [self statsOrganizationID].length > 0);
}

- (NSString *)statsOrganizationID {
  return self.configState[kStatsOrganizationID];
}

- (NSDate *)fullSyncLastSuccess {
  return self.syncState[kFullSyncLastSuccess];
}

- (void)setFullSyncLastSuccess:(NSDate *)fullSyncLastSuccess {
  [self updateSyncStateForKey:kFullSyncLastSuccess value:fullSyncLastSuccess];
  self.ruleSyncLastSuccess = fullSyncLastSuccess;
}

- (NSDate *)ruleSyncLastSuccess {
  return self.syncState[kRuleSyncLastSuccess];
}

- (void)setRuleSyncLastSuccess:(NSDate *)ruleSyncLastSuccess {
  [self updateSyncStateForKey:kRuleSyncLastSuccess value:ruleSyncLastSuccess];
}

- (SNTSyncType)syncTypeRequired {
  if (self.syncState.count == 0) {
    return SNTSyncTypeCleanAll;
  }
  return (SNTSyncType)[self.syncState[kSyncTypeRequired] integerValue];
}

- (void)setSyncTypeRequired:(SNTSyncType)syncTypeRequired {
  [self updateSyncStateForKey:kSyncTypeRequired value:@(syncTypeRequired)];
}

- (NSString *)machineOwner {
  NSString *machineOwner = self.configState[kMachineOwnerKey];
  if (machineOwner) return machineOwner;

  NSString *plistPath = self.configState[kMachineOwnerPlistFileKey];
  NSString *plistKey = self.configState[kMachineOwnerPlistKeyKey];
  if (plistPath.length && plistKey.length) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineOwner = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }

  return machineOwner ?: @"";
}

- (NSArray<NSString *> *)machineOwnerGroups {
  NSArray<NSString *> *machineOwnerGroups = self.configState[kMachineOwnerGroupsKey];
  if (machineOwnerGroups.count) return machineOwnerGroups;

  NSString *plistPath = self.configState[kMachineOwnerPlistFileKey];
  NSString *plistKey = self.configState[kMachineOwnerGroupsPlistKeyKey];
  if (plistPath.length && plistKey.length) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineOwnerGroups = [plist[plistKey] isKindOfClass:[NSArray class]] ? plist[plistKey] : nil;
    for (NSString *group in machineOwnerGroups) {
      if (![group isKindOfClass:[NSString class]]) {
        machineOwnerGroups = nil;
        break;
      }
    }
  }

  return machineOwnerGroups;
}

- (NSString *)machineID {
  NSString *machineId = self.configState[kMachineIDKey];
  if (machineId) return machineId;

  NSString *plistPath = self.configState[kMachineIDPlistFileKey];
  NSString *plistKey = self.configState[kMachineIDPlistKeyKey];

  if (plistPath && plistKey) {
    NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
    machineId = [plist[plistKey] isKindOfClass:[NSString class]] ? plist[plistKey] : nil;
  }

  return machineId.length ? machineId : [SNTSystemInfo hardwareUUID];
}

- (SNTEventLogType)eventLogType {
  NSString *logType = [self.configState[kEventLogType] lowercaseString];
  if ([logType isEqualToString:@"protobuf"]) {
    return SNTEventLogTypeProtobuf;
  } else if ([logType isEqualToString:@"protobufstream"]) {
    return SNTEventLogTypeProtobufStream;
  } else if ([logType isEqualToString:@"protobufstreamgzip"]) {
    return SNTEventLogTypeProtobufStreamGzip;
  } else if ([logType isEqualToString:@"protobufstreamzstd"]) {
    return SNTEventLogTypeProtobufStreamZstd;
  } else if ([logType isEqualToString:@"syslog"]) {
    return SNTEventLogTypeSyslog;
  } else if ([logType isEqualToString:@"null"]) {
    return SNTEventLogTypeNull;
  } else if ([logType isEqualToString:@"json"]) {
    return SNTEventLogTypeJSON;
  } else if ([logType isEqualToString:@"file"]) {
    return SNTEventLogTypeFilelog;
  } else {
    return SNTEventLogTypeFilelog;
  }
}

- (NSString *)eventLogTypeRaw {
  return self.configState[kEventLogType] ?: @"file";
}

- (NSString *)eventLogPath {
  return self.configState[kEventLogPath] ?: @"/var/db/santa/santa.log";
}

- (NSString *)spoolDirectory {
  return self.configState[kSpoolDirectory] ?: @"/var/db/santa/spool";
}

- (NSUInteger)spoolDirectoryFileSizeThresholdKB {
  return self.configState[kSpoolDirectoryFileSizeThresholdKB]
             ? [self.configState[kSpoolDirectoryFileSizeThresholdKB] unsignedIntegerValue]
             : 250;
}

- (NSUInteger)spoolDirectorySizeThresholdMB {
  return self.configState[kSpoolDirectorySizeThresholdMB]
             ? [self.configState[kSpoolDirectorySizeThresholdMB] unsignedIntegerValue]
             : 100;
}

- (float)spoolDirectoryEventMaxFlushTimeSec {
  return self.configState[kSpoolDirectoryEventMaxFlushTimeSec]
             ? [self.configState[kSpoolDirectoryEventMaxFlushTimeSec] floatValue]
             : 15.0;
}

- (NSDictionary *)fileAccessPolicy {
  return self.configState[kFileAccessPolicy];
}

- (NSString *)fileAccessPolicyPlist {
  // This property is ignored when kFileAccessPolicy is set
  if (self.configState[kFileAccessPolicy]) {
    return nil;
  } else {
    return self.configState[kFileAccessPolicyPlist];
  }
}

- (NSString *)fileAccessBlockMessage {
  return self.configState[kFileAccessBlockMessage];
}

- (uint32_t)fileAccessPolicyUpdateIntervalSec {
  return self.configState[kFileAccessPolicyUpdateIntervalSec]
             ? [self.configState[kFileAccessPolicyUpdateIntervalSec] unsignedIntValue]
             : 60 * 10;
}

- (uint32_t)fileAccessGlobalLogsPerSec {
  return self.configState[kFileAccessGlobalLogsPerSec]
             ? [self.configState[kFileAccessGlobalLogsPerSec] unsignedIntValue]
             : 60;
}

- (uint32_t)fileAccessGlobalWindowSizeSec {
  return self.configState[kFileAccessGlobalWindowSizeSec]
             ? [self.configState[kFileAccessGlobalWindowSizeSec] unsignedIntValue]
             : 15;
}

- (BOOL)enableTelemetryExport {
  return [self.configState[kEnableTelemetryExport] boolValue];
}

- (uint32_t)telemetryExportIntervalSec {
  return self.configState[kTelemetryExportIntervalSec]
             ? [self.configState[kTelemetryExportIntervalSec] unsignedIntValue]
             : 60 * 15;
}

- (uint32_t)telemetryExportTimeoutSec {
  return self.configState[kTelemetryExportTimeoutSec]
             ? [self.configState[kTelemetryExportTimeoutSec] unsignedIntValue]
             : (5 * 60);
}

- (uint32_t)telemetryExportBatchThresholdSizeMB {
  return self.configState[kTelemetryExportBatchThresholdSizeMB]
             ? [self.configState[kTelemetryExportBatchThresholdSizeMB] unsignedIntValue]
             : 500;
}

- (uint32_t)telemetryExportMaxFilesPerBatch {
  return self.configState[kTelemetryExportMaxFilesPerBatch]
             ? [self.configState[kTelemetryExportMaxFilesPerBatch] unsignedIntValue]
             : 50;
}

- (BOOL)enableMachineIDDecoration {
  NSNumber *number = self.configState[kEnableMachineIDDecoration];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableCleanSyncEventUpload {
  NSNumber *number = self.configState[kSyncEnableCleanSyncEventUpload];
  return number ? [number boolValue] : NO;
}

- (BOOL)enableAllEventUpload {
  NSNumber *n = self.syncState[kEnableAllEventUploadKey];
  if (n) return [n boolValue];

  return [self.configState[kEnableAllEventUploadKey] boolValue];
}

- (void)setEnableAllEventUpload:(BOOL)enabled {
  [self updateSyncStateForKey:kEnableAllEventUploadKey value:@(enabled)];
}

- (BOOL)disableUnknownEventUpload {
  NSNumber *n = self.syncState[kDisableUnknownEventUploadKey];
  if (n) return [n boolValue];

  return [self.configState[kDisableUnknownEventUploadKey] boolValue];
}

- (void)setDisableUnknownEventUpload:(BOOL)enabled {
  [self updateSyncStateForKey:kDisableUnknownEventUploadKey value:@(enabled)];
}

- (BOOL)enableForkAndExitLogging {
  NSNumber *number = self.configState[kEnableForkAndExitLogging];
  return number ? [number boolValue] : NO;
}

// This method returns only the values that are of the expected string type.
// The reasoning is that if a filter is attempted to be set, this method should
// return some subset rather than `nil`. Since `nil` effectively means to log
// everything, returning it would be akin to "failing open" even though some
// filter configuration was attempted.
- (NSArray<NSString *> *)telemetry {
  NSArray *configuredEvents = self.configState[kTelemetryKey];
  if (!configuredEvents) {
    return nil;
  }

  NSMutableArray *events = [[NSMutableArray alloc] initWithCapacity:configuredEvents.count];

  for (id event in configuredEvents) {
    if ([event isKindOfClass:[NSString class]]) {
      [events addObject:event];
    }
  }

  return events;
}

- (BOOL)ignoreOtherEndpointSecurityClients {
  NSNumber *number = self.configState[kIgnoreOtherEndpointSecurityClients];
  return number ? [number boolValue] : NO;
}

- (NSString *)fcmProject {
  return self.configState[kFCMProject];
}

- (NSString *)fcmEntity {
  return self.configState[kFCMEntity];
}

- (NSString *)fcmAPIKey {
  return self.configState[kFCMAPIKey];
}

- (BOOL)fcmEnabled {
  return (self.fcmProject.length && self.fcmEntity.length && self.fcmAPIKey.length);
}

- (BOOL)enableAPNS {
  // TODO: Consider supporting enablement from the sync server.
  NSNumber *number = self.configState[kEnableAPNS];
  return [number boolValue];
}

- (BOOL)enableNATS {
  // TODO: Consider supporting enablement from the sync server.
  return [self.configState[kEnableNATS] boolValue];
}

- (void)setBlockUSBMount:(BOOL)enabled {
  [self updateSyncStateForKey:kBlockUSBMountKey value:@(enabled)];
}

- (BOOL)blockUSBMount {
  NSNumber *n = self.syncState[kBlockUSBMountKey];
  if (n) return [n boolValue];

  return [self.configState[kBlockUSBMountKey] boolValue];
}

- (void)setSyncServerOverrideFileAccessAction:(NSString *)action {
  NSString *a = [action lowercaseString];
  if ([a isEqualToString:@"auditonly"] || [a isEqualToString:@"disable"] ||
      [a isEqualToString:@"none"] || [a isEqualToString:@""]) {
    [self updateSyncStateForKey:kOverrideFileAccessActionKey value:action];
  }
}

- (SNTOverrideFileAccessAction)overrideFileAccessAction {
  NSString *action = [self.syncState[kOverrideFileAccessActionKey] lowercaseString];

  if (!action) {
    action = [self.configState[kOverrideFileAccessActionKey] lowercaseString];
    if (!action) {
      return SNTOverrideFileAccessActionNone;
    }
  }

  // Note: `auditonly` without an underscore is a deprecated, but still accepted form.
  if ([action isEqualToString:@"audit_only"] || [action isEqualToString:@"auditonly"]) {
    return SNTOverrideFileAccessActionAuditOnly;
  } else if ([action isEqualToString:@"disable"]) {
    return SNTOverrideFileAccessActionDiable;
  } else {
    return SNTOverrideFileAccessActionNone;
  }
}

///
/// Returns YES if all of the necessary options are set to export metrics, NO
/// otherwise.
///
- (BOOL)exportMetrics {
  return [self metricFormat] != SNTMetricFormatTypeUnknown &&
         ![self.configState[kMetricURL] isEqualToString:@""];
}

- (SNTMetricFormatType)metricFormat {
  NSString *normalized = [self.configState[kMetricFormat] lowercaseString];

  normalized = [normalized stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  if ([normalized isEqualToString:@"rawjson"]) {
    return SNTMetricFormatTypeRawJSON;
  } else if ([normalized isEqualToString:@"monarchjson"]) {
    return SNTMetricFormatTypeMonarchJSON;
  } else {
    return SNTMetricFormatTypeUnknown;
  }
}

- (NSURL *)metricURL {
  return [NSURL URLWithString:self.configState[kMetricURL]];
}

// Returns a default value of 30 (for 30 seconds).
- (NSUInteger)metricExportInterval {
  NSNumber *configuredInterval = self.configState[kMetricExportInterval];

  if (configuredInterval == nil) {
    return 30;
  }
  return [configuredInterval unsignedIntegerValue];
}

// Returns a default value of 30 (for 30 seconds).
- (NSUInteger)metricExportTimeout {
  NSNumber *configuredInterval = self.configState[kMetricExportTimeout];

  if (configuredInterval == nil) {
    return 30;
  }
  return [configuredInterval unsignedIntegerValue];
}

- (NSDictionary *)extraMetricLabels {
  return self.configState[kMetricExtraLabels];
}

- (NSArray<NSString *> *)enabledProcessAnnotations {
  NSArray<NSString *> *annotations = self.configState[kEnabledProcessAnnotations];
  for (id annotation in annotations) {
    if (![annotation isKindOfClass:[NSString class]]) {
      return nil;
    }
  }
  return annotations;
}

#pragma mark - Private

///
///  Update the syncState. Triggers a KVO event for all dependents.
///
- (void)updateSyncStateForKey:(NSString *)key value:(id)value {
  dispatch_async(dispatch_get_main_queue(), ^{
    NSMutableDictionary *syncState = self.syncState.mutableCopy;
    syncState[key] = value;
    self.syncState = syncState;
    [self saveSyncStateToDisk];
  });
}

///
///  Read the saved syncState.
///
- (NSMutableDictionary *)readSyncStateFromDisk {
  if (!self.syncStateAccessAuthorizerBlock()) {
    return nil;
  }

  NSMutableDictionary *syncState =
      [NSMutableDictionary dictionaryWithContentsOfFile:self.syncStateFilePath];
  for (NSString *key in syncState.allKeys) {
    if (self.syncServerKeyTypes[key] == [NSRegularExpression class]) {
      NSString *pattern = [syncState[key] isKindOfClass:[NSString class]] ? syncState[key] : nil;
      syncState[key] = [self expressionForPattern:pattern];
    } else if (![syncState[key] isKindOfClass:self.syncServerKeyTypes[key]]) {
      syncState[key] = nil;
      continue;
    }
  }

  return syncState;
}

///
///  Migrate any deprecated sync state keys/values to alternative keys/values.
///
///  Returns YES if any keys were migrated. Otherwise NO.
///
- (BOOL)migrateDeprecatedSyncStateKeys {
  // Currently only one key to migrate
  if (!self.syncState[kSyncCleanRequiredDeprecated]) {
    return NO;
  }

  NSMutableDictionary *syncState = self.syncState.mutableCopy;

  // If the kSyncTypeRequired key exists, its current value will take precedence.
  // Otherwise, migrate the old value to be compatible with the new logic.
  if (!self.syncState[kSyncTypeRequired]) {
    syncState[kSyncTypeRequired] = [self.syncState[kSyncCleanRequiredDeprecated] boolValue]
                                       ? @(SNTSyncTypeClean)
                                       : @(SNTSyncTypeNormal);
  }

  // Delete the deprecated key
  syncState[kSyncCleanRequiredDeprecated] = nil;

  self.syncState = syncState;

  return YES;
}

///
///  Saves the current effective syncState to disk.
///
- (void)saveSyncStateToDisk {
  if (!self.syncStateAccessAuthorizerBlock()) {
    return;
  }

  NSMutableDictionary *syncState = self.syncState.mutableCopy;
  syncState[kAllowedPathRegexKey] = [syncState[kAllowedPathRegexKey] pattern];
  syncState[kBlockedPathRegexKey] = [syncState[kBlockedPathRegexKey] pattern];
  [syncState writeToFile:self.syncStateFilePath atomically:YES];
  [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions : @0600}
                                   ofItemAtPath:self.syncStateFilePath
                                          error:NULL];
}

- (void)clearSyncState {
  self.syncState = [NSMutableDictionary dictionary];
  // TODO: Start a timer to flush the state to disk. On startup, Santa should
  // check for the presence of the state file and, if no SyncBaseURL is
  // configured, start the timer to clear sync state and flush to disk.
}

- (NSArray *)entitlementsPrefixFilter {
  return EnsureArrayOfStrings(self.configState[kEntitlementsPrefixFilterKey]);
}

- (NSArray *)entitlementsTeamIDFilter {
  return EnsureArrayOfStrings(self.configState[kEntitlementsTeamIDFilterKey]);
}

- (void)migrateDeprecatedStatsStatePath:(NSString *)oldPath {
  if (!self.stateAccessAuthorizerBlock()) {
    return;
  }

  // Attempt to load the new state file first. If that succeeds, no migration is necessary
  if ([NSDictionary dictionaryWithContentsOfFile:self.stateFilePath]) {
    return;
  }

  NSDictionary *oldState = [NSDictionary dictionaryWithContentsOfFile:oldPath];
  if (!oldState) {
    return;
  }

  if ([oldState[kStateStatsLastSubmissionAttemptKey] isKindOfClass:[NSDate class]] &&
      [oldState[kStateStatsLastSubmissionVersionKey] isKindOfClass:[NSString class]]) {
    NSDictionary *newState = @{
      kStateStatsKey : @{
        kStateStatsLastSubmissionAttemptKey : oldState[kStateStatsLastSubmissionAttemptKey],
        kStateStatsLastSubmissionVersionKey : oldState[kStateStatsLastSubmissionVersionKey],
      }
    };

    [newState writeToFile:self.stateFilePath atomically:YES];
    @synchronized(self) {
      [self saveStateToDiskSynchronized:newState];
    }
  }

  NSError *err;
  if (![[NSFileManager defaultManager] removeItemAtPath:oldPath error:&err]) {
    LOGW(@"Unable to remove old state file: %@", err);
  }
}

- (NSDictionary *)readStateFromDisk {
  if (!self.stateAccessAuthorizerBlock()) {
    return nil;
  }

  NSDictionary *state = [NSDictionary dictionaryWithContentsOfFile:self.stateFilePath];
  if (!state) {
    return nil;
  }

  // This acts as a filter, populated only with known state file data
  // so that unknown state data is removed.
  NSMutableDictionary *newState = [NSMutableDictionary dictionary];

  if ([state[kStateStatsKey] isKindOfClass:[NSDictionary class]]) {
    NSDictionary *stats = state[kStateStatsKey];
    if ([stats[kStateStatsLastSubmissionAttemptKey] isKindOfClass:[NSDate class]] &&
        [stats[kStateStatsLastSubmissionVersionKey] isKindOfClass:[NSString class]]) {
      _lastStatsSubmissionTimestamp = stats[kStateStatsLastSubmissionAttemptKey];
      _lastStatsSubmissionVersion = stats[kStateStatsLastSubmissionVersionKey];

      newState[kStateStatsKey] = @{
        kStateStatsLastSubmissionAttemptKey : _lastStatsSubmissionTimestamp,
        kStateStatsLastSubmissionVersionKey : _lastStatsSubmissionVersion,
      };
    }
  }

  if ([state[kStateTempMonitorModeKey] isKindOfClass:[NSDictionary class]]) {
    NSDictionary *tmm = state[kStateTempMonitorModeKey];
    // If the stored temp monitor mode boot session uuid matches, then carry over the
    // values. Otherwise they will get discarded.
    if ([tmm[kStateTempMonitorModeBootSessionUUIDKey] isKindOfClass:[NSString class]] &&
        [tmm[kStateTempMonitorModeDeadlineKey] isKindOfClass:[NSNumber class]] &&
        [tmm[kStateTempMonitorModeBootSessionUUIDKey]
            isEqualToString:[SNTSystemInfo bootSessionUUID]]) {
      newState[kStateTempMonitorModeKey] = @{
        kStateTempMonitorModeBootSessionUUIDKey : tmm[kStateTempMonitorModeBootSessionUUIDKey],
        kStateTempMonitorModeDeadlineKey : tmm[kStateTempMonitorModeDeadlineKey]
      };
    }
  }

  return newState;
}

- (void)saveStatsSubmissionAttemptTime:(NSDate *)timestamp version:(NSString *)version {
  @synchronized(self) {
    [self updateStateSynchronizedKey:kStateStatsKey
                               value:@{
                                 kStateStatsLastSubmissionAttemptKey : timestamp,
                                 kStateStatsLastSubmissionVersionKey : version,
                               }];
  }

  _lastStatsSubmissionTimestamp = timestamp;
  _lastStatsSubmissionVersion = version;
}

- (void)updateStateSynchronizedKey:(NSString *)key value:(NSDictionary *)value {
  NSMutableDictionary *newState = [self.state mutableCopy];

  newState[key] = value;
  self.state = newState;

  [self saveStateToDiskSynchronized:self.state];
}

- (BOOL)saveStateToDiskSynchronized:(NSDictionary *)state {
  if (!self.stateAccessAuthorizerBlock()) {
    return NO;
  }

  if (![state writeToFile:self.stateFilePath atomically:YES]) {
    LOGW(@"Unable to update state file");
    return NO;
  }

  return [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions : @0600}
                                          ofItemAtPath:self.stateFilePath
                                                 error:NULL];
}

#pragma mark - Private Defaults Methods

- (NSRegularExpression *)expressionForPattern:(NSString *)pattern {
  if (!pattern) return nil;
  if (![pattern hasPrefix:@"^"]) pattern = [@"^" stringByAppendingString:pattern];
  return [NSRegularExpression regularExpressionWithPattern:pattern options:0 error:NULL];
}

- (void)applyOverrides:(NSMutableDictionary *)forcedConfig {
  // Overrides should only be applied under debug builds.
#ifdef DEBUG
  if ([[[NSProcessInfo processInfo] processName] isEqualToString:@"xctest"] &&
      ![[[NSProcessInfo processInfo] environment] objectForKey:@"ENABLE_CONFIG_OVERRIDES"]) {
    // By default, config overrides are not applied when running tests to help
    // mitigate potential issues due to unexpected config values. This behavior
    // can be overriden if desired by using the env variable: `ENABLE_CONFIG_OVERRIDES`.
    //
    // E.g.:
    //   bazel test --test_env=ENABLE_CONFIG_OVERRIDES=1 ...other test args...
    return;
  }

  NSDictionary *overrides = [NSDictionary dictionaryWithContentsOfFile:kConfigOverrideFilePath];
  for (NSString *key in overrides) {
    id obj = overrides[key];
    if (![obj isKindOfClass:self.forcedConfigKeyTypes[key]] &&
        !(self.forcedConfigKeyTypes[key] == [NSRegularExpression class] &&
          [obj isKindOfClass:[NSString class]])) {
      continue;
    }

    forcedConfig[key] = obj;

    if (self.forcedConfigKeyTypes[key] == [NSRegularExpression class]) {
      NSString *pattern = [obj isKindOfClass:[NSString class]] ? obj : nil;
      forcedConfig[key] = [self expressionForPattern:pattern];
    }
  }
#endif
}

- (id)overriderValue:(id)value forKey:(NSString *)key {
  // Overrides should only be applied under debug builds.
  id overrideValue = value;
#ifdef DEBUG
  overrideValue =
      [NSDictionary dictionaryWithContentsOfFile:kConfigOverrideFilePath][key] ?: overrideValue;
#endif
  return overrideValue;
}

- (NSMutableDictionary *)readForcedConfig {
  NSMutableDictionary *forcedConfig = [NSMutableDictionary dictionary];
  for (NSString *key in self.forcedConfigKeyTypes) {
    id obj = [self forcedConfigValueForKey:key];
    forcedConfig[key] = [obj isKindOfClass:self.forcedConfigKeyTypes[key]] ? obj : nil;
    // Create the regex objects now
    if (self.forcedConfigKeyTypes[key] == [NSRegularExpression class]) {
      NSString *pattern = [obj isKindOfClass:[NSString class]] ? obj : nil;
      forcedConfig[key] = [self expressionForPattern:pattern];
    }
  }

  [self applyOverrides:forcedConfig];

  return forcedConfig;
}

- (id)forcedConfigValueForKey:(NSString *)key {
  CFStringRef keyRef = (__bridge CFStringRef)key;
  if (CFPreferencesAppValueIsForced(keyRef, kMobileConfigDomain)) {
    return CFBridgingRelease(CFPreferencesCopyAppValue(keyRef, kMobileConfigDomain));
  }
  return nil;
}

- (void)startWatchingDefaults {
  // santactl is not a long running daemon, it does not need to watch for config changes.
  NSString *processName = [[NSProcessInfo processInfo] processName];
  if ([processName isEqualToString:@"santactl"]) return;
  [[NSNotificationCenter defaultCenter] addObserver:self
                                           selector:@selector(defaultsChanged:)
                                               name:NSUserDefaultsDidChangeNotification
                                             object:nil];
#ifdef DEBUG
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
    [self watchOverridesFile];
  });
#endif
}

#ifdef DEBUG
- (void)watchOverridesFile {
  while (![[NSFileManager defaultManager] fileExistsAtPath:kConfigOverrideFilePath]) {
    [NSThread sleepForTimeInterval:0.2];
  }
  [self defaultsChanged:nil];

  int descriptor = open([kConfigOverrideFilePath fileSystemRepresentation], O_EVTONLY);
  if (descriptor < 0) {
    return;
  }

  dispatch_source_t source =
      dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, descriptor,
                             DISPATCH_VNODE_WRITE | DISPATCH_VNODE_RENAME | DISPATCH_VNODE_DELETE,
                             dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
  dispatch_source_set_event_handler(source, ^{
    dispatch_async(dispatch_get_main_queue(), ^{
      [self defaultsChanged:nil];
    });
    unsigned long events = dispatch_source_get_data(source);
    if ((events & DISPATCH_VNODE_DELETE) || (events & DISPATCH_VNODE_RENAME)) {
      dispatch_source_cancel(source);
    }
  });
  dispatch_source_set_cancel_handler(source, ^{
    close(descriptor);
    [self watchOverridesFile];
  });
  dispatch_resume(source);
}
#endif

- (void)defaultsChanged:(void *)v {
  SEL handleChange = @selector(handleChange);
  [NSObject cancelPreviousPerformRequestsWithTarget:self selector:handleChange object:nil];
  [self performSelector:handleChange withObject:nil afterDelay:1.0f];
}

///
///  Update the configState. Triggers a KVO event for all dependents.
///
- (void)handleChange {
  self.configState = [self readForcedConfig];
}

#pragma mark - Config Validation

- (nullable NSArray *)validateConfiguration {
  NSMutableArray *errors = [NSMutableArray array];

  [self.defaults.dictionaryRepresentation enumerateKeysAndObjectsUsingBlock:^(NSString *key, id obj,
                                                                              BOOL *stop) {
    // If the key is not forced it will be ignored, so we don't need to validate
    // it. This also has the effect of removing Apple keys that are present in
    // the user defaults preferences.
    if (!CFPreferencesAppValueIsForced((__bridge CFStringRef)key, kMobileConfigDomain)) return;

    // If the key is a 'standard' configuration profile key, skip it.
    static NSArray *profileKeys = @[
      @"_manualProfile",
      @"PayloadUUID",
    ];
    if ([profileKeys containsObject:key]) return;

    // Check that the key is known to us.
    id type = self.forcedConfigKeyTypes[key];
    if (!type) {
      [errors addObject:[NSString stringWithFormat:@"The key %@ is not recognized", key]];
      return;
    }

    // Check that the type of the value matches the expected type.
    id value = CFBridgingRelease(
        CFPreferencesCopyAppValue((__bridge CFStringRef)key, kMobileConfigDomain));
    value = [self overriderValue:value forKey:key];
    if (![value isKindOfClass:type] &&
        !(type == [NSRegularExpression class] && [value isKindOfClass:[NSString class]])) {
      [errors addObject:[NSString stringWithFormat:@"The key %@ has an unexpected type: %@", key,
                                                   [value class]]];
      return;
    }

    // If the type is a regex, check that it compiles.
    if (type == [NSRegularExpression class] && ![self expressionForPattern:value]) {
      [errors addObject:[NSString
                            stringWithFormat:@"The regular expression for key %@ does not compile",
                                             key]];
    }

    // If the key is StaticRules, validate the passed in rules.
    if ([key isEqualToString:kStaticRulesKey]) {
      // We've already validated that `value` is an NSArray
      [errors addObjectsFromArray:[self validateStaticRules:(NSArray *)value]];
    }
  }];
  return errors;
}

- (NSArray *)validateStaticRules:(NSArray *)rules {
  NSMutableArray *errors = [NSMutableArray array];
  [rules enumerateObjectsUsingBlock:^(id rule, NSUInteger idx, BOOL *stop) {
    if (![rule isKindOfClass:[NSDictionary class]]) {
      [errors addObject:[NSString stringWithFormat:@"StaticRule at index %lu has bad type: %@", idx,
                                                   [rule class]]];
      return;
    }

    NSError *error;
    (void)[[SNTRule alloc] initStaticRuleWithDictionary:rule error:&error];
    if (error) {
      [errors addObject:[NSString stringWithFormat:@"StaticRule at index %lu is invalid: %@", idx,
                                                   error.localizedDescription]];
    }
  }];
  return errors;
}

@end
