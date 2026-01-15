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

@class SNTExportConfiguration;
@class SNTModeTransition;
@class SNTRule;

///
///  Singleton that provides an interface for managing configuration values on disk
///  @note This class is designed as a singleton but that is not strictly enforced.
///  @note All properties are KVO compliant.
///
@interface SNTConfigurator : NSObject

#pragma mark - Daemon Settings

///
///  The operating mode. Defaults to MONITOR.
///
@property(readonly, nonatomic) SNTClientMode clientMode;

///
///  Set the operating mode as received from a sync server.
///
- (void)setSyncServerClientMode:(SNTClientMode)newMode;

///
///  Enable Fail Close mode. Defaults to NO.
///  This controls Santa's behavior when a failure occurs, such as an
///  inability to read a file and as a default response when deadlines
///  are about to expire. By default, to prevent bugs or misconfiguration
///  from rendering a machine inoperable Santa will fail open and allow
///  execution. With this setting enabled, Santa will fail closed if the client
///  is in LOCKDOWN mode, offering a higher level of security but with a higher
///  potential for causing problems.
///
@property(readonly, nonatomic) BOOL failClosed;

///
///  A set of static rules that should always apply. These can be used as a
///  fallback set of rules for management tools that should always be allowed to
///  run even if a sync server does something unexpected. It can also be used
///  as the sole source of rules, distributed with an MDM.
///
///  The value of this key should be an array containing dictionaries. Each
///  dictionary should contain the same keys used for syncing, e.g:
///
///  <key>StaticRules</key>
///  <array>
///    <dict>
///      <key>identifier</key>
///      <string>binary sha256, certificate sha256, team ID</string>
///      <key>rule_type</key>
///      <string>BINARY</string>  (one of BINARY, CERTIFICATE or TEAMID)
///      <key>policy</key>
///      <string>BLOCKLIST</string>  (one of ALLOWLIST, ALLOWLIST_COMPILER, BLOCKLIST,
///                                   SILENT_BLOCKLIST)
///    </dict>
///  </array>
///
///
@property(nullable, readonly, nonatomic) NSArray<NSDictionary *> *staticRules;

///
///  The regex of allowed paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(nullable, readonly, nonatomic) NSRegularExpression *allowedPathRegex;

///
///  Set the regex of allowed paths as received from a sync server.
///
- (void)setSyncServerAllowedPathRegex:(nonnull NSRegularExpression *)re;

///
///  The regex of blocked paths. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotall) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(nullable, readonly, nonatomic) NSRegularExpression *blockedPathRegex;

///
///  Set the regex of blocked paths as received from a sync server.
///
- (void)setSyncServerBlockedPathRegex:(nonnull NSRegularExpression *)re;

///
///  The regex of paths to log file changes for. Regexes are specified in ICU format.
///
///  The regex flags IXSM can be used, though the s (dotalL) and m (multiline) flags are
///  pointless as a path only ever has a single line.
///  If the regex doesn't begin with ^ to match from the beginning of the line, it will be added.
///
@property(nullable, readonly, nonatomic) NSRegularExpression *fileChangesRegex;

///
///  A list of ignore prefixes which are checked in-kernel.
///  This is more performant than FileChangesRegex when ignoring whole directory trees.
///
///  For example adding a prefix of "/private/tmp/" will turn off file change log generation
///  in-kernel for that entire tree. Since they are ignored by the kernel, they never reach santad
///  and are not seen by the fileChangesRegex. Note the trailing "/", without it any file or
///  directory starting with "/private/tmp" would be ignored.
///
///  By default "/." and "/dev/" are added.
///
///  Memory in the kernel is precious. A total of MAXPATHLEN (1024) nodes are allowed.
///  Using all 1024 nodes will result in santa-driver allocating ~2MB of wired memory.
///  An ASCII character uses 1 node. An UTF-8 encoded Unicode character uses 1-4 nodes.
///  Prefixes are added to the running config in-order, one by one. The prefix will be ignored if
///  (the running config's current size) + (the prefix's size) totals up to more than 1024 nodes.
///  The running config is stored in a prefix tree.
///  Prefixes that share prefixes are effectively de-duped; their shared node sized components only
///  take up 1 node. For example these 3 prefixes all have a common prefix of "/private/".
///  They will only take up 21 nodes instead of 39.
///
///  "/private/tmp/"
///  "/private/var/"
///  "/private/new/"
///
///                                                              -> [t] -> [m] -> [p] -> [/]
///
///  [/] -> [p] -> [r] -> [i] -> [v] -> [a] -> [t] -> [e] -> [/] -> [v] -> [a] -> [r] -> [/]
///
///                                                              -> [n] -> [e] -> [w] -> [/]
///
///  Prefixes with Unicode characters work similarly. Assuming a UTF-8 encoding these two prefixes
///  are actually the same for the first 3 nodes. They take up 7 nodes instead of 10.
///
///  "/🤘"
///  "/🖖"
///
///                          -> [0xa4] -> [0x98]
///
///  [/] -> [0xf0] -> [0x9f]
///
///                          -> [0x96] -> [0x96]
///
///  To disable file change logging completely add "/".
///  TODO(bur): Make this default if no FileChangesRegex is set.
///
///  Filters are only applied on santad startup.
///  TODO(bur): Support add / remove of filters while santad is running.
///
@property(nullable, readonly, nonatomic) NSArray *fileChangesPrefixFilters;

///
///  Enable __PAGEZERO protection, defaults to YES
///  If this flag is set to NO, 32-bit binaries that are missing
///  the __PAGEZERO segment will not be blocked.
///
@property(readonly, nonatomic) BOOL enablePageZeroProtection;

///
///  Enable bad signature protection, defaults to NO.
///  When enabled, a binary that is signed but has a bad signature (cert revoked, binary
///  tampered with, etc.) will be blocked regardless of client-mode unless a binary allowlist
///  rule exists.
///
@property(readonly, nonatomic) BOOL enableBadSignatureProtection;

///
///  Enable anti-tamper process suspend/resume protection.
///  When enabled, attempts to suspend or resume the Santa daemon process will be blocked.
///  Defaults to YES.
///  This will be removed in the near future.
///
@property(readonly, nonatomic) BOOL enableAntiTamperProcessSuspendResume;

///
///  Defines how event logs are stored. Options are:
///    SNTEventLogTypeSyslog "syslog": Sent to ASL or ULS (if built with the 10.12 SDK or later).
///    SNTEventLogTypeFilelog "file": Sent to a file on disk. Use eventLogPath to specify a path.
///    SNTEventLogTypeNull "null": Logs nothing
///    SNTEventLogTypeProtobuf "protobuf": Sent to a file on disk, using a maildir-like
///      format. Use spoolDirectory to specify a path. Use spoolDirectoryFileSizeThresholdKB,
///      spoolDirectorySizeThresholdMB and spoolDirectoryEventMaxFlushTimeSec to configure
///      additional settings.
///    SNTEventLogTypeProtobufStream "protobufstream": Similar to "protobuf", but formatted as a
///      coded output stream.
///    SNTEventLogTypeProtobufStreamGzip "protobufstreamgzip": Similar to "protobufstream", but
///      output is compressed as gzip.
///    SNTEventLogTypeProtobufStreamZstd "protobufstreamzstd": Similar to "protobufstream", but
///      output is compressed as zstd.
///    Defaults to SNTEventLogTypeFilelog.
///    For mobileconfigs use EventLogType as the key and syslog or filelog strings as the value.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) SNTEventLogType eventLogType;

///
/// Returns the raw value of the EventLogType configuration key instead of being
/// converted to the SNTEventLogType enum. If the key is not set, the default log
/// type is returned.
///
@property(nonnull, readonly, nonatomic) NSString *eventLogTypeRaw;

///
///  If eventLogType is set to Filelog, eventLogPath will provide the path to save logs.
///  Defaults to /var/db/santa/santa.log.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(nonnull, readonly, nonatomic) NSString *eventLogPath;

///
///  Array of strings of telemetry events that should be logged.
///
///  @note: This property is KVO compliant.
///
@property(nullable, readonly, nonatomic) NSArray<NSString *> *telemetry;

///
///  If eventLogType is set to protobuf, spoolDirectory will provide the base path used for
///  saving logs using a maildir-like format.
///  Defaults to /var/db/santa/spool.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(nonnull, readonly, nonatomic) NSString *spoolDirectory;

///
///  If eventLogType is set to protobuf, spoolDirectoryFileSizeThresholdKB sets the per-file size
///  limit for files saved in the spoolDirectory.
///  Defaults to 250.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSUInteger spoolDirectoryFileSizeThresholdKB;

///
///  If eventLogType is set to protobuf, spoolDirectorySizeThresholdMB sets the total size
///  limit for all files saved in the spoolDirectory.
///  Defaults to 100.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) NSUInteger spoolDirectorySizeThresholdMB;

///
///  If eventLogType is set to protobuf, spoolDirectoryEventMaxFlushTimeSec sets the maximum amount
///  of time an event will be stored in memory before being written to disk.
///  Defaults to 15.0.
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) float spoolDirectoryEventMaxFlushTimeSec;

///
///  If true, Santa will attempt to periodically export telemetry to configured location.
///  Defaults to false.
///
///  @note: This property is KVO compliant.
///
@property(readonly) BOOL enableTelemetryExport;

///
///  If enableTelemetryExport is true, this defines how often telemetry export is performed.
///  Defaults to 900 (15 minutes). Minimum allowed value is 60.
///
///  @note: This property is KVO compliant.
///
@property(readonly) uint32_t telemetryExportIntervalSec;

///
///  When exporting telemetry, this defines how long Santa will wait for a given batch to upload.
///  Defaults to 300 (5 minutes). Minimum allowed value is 60.
///
///  @note: This property is KVO compliant.
///
@property(readonly) uint32_t telemetryExportTimeoutSec;

///
///  This configuration key sets the threshold size in megabytes for grouping telemetry files
///  into export batches. When the accumulated size of files in a batch reaches or exceeds
///  this threshold, the batch is considered complete and ready for export.
///  Note: All files in a batch are written as a single combined file at the destination.
///  See also: TelemetryExportMaxFilesPerBatch
///  Defaults to 500.
///
///  @note: This property is KVO compliant.
///
@property(readonly) uint32_t telemetryExportBatchThresholdSizeMB;

///
///  Sets the maximum number of individual telemetry files that can be grouped into a single
///  export batch.
///  Note: All files in a batch are written as a single combined file at the destination.
///  See also: TelemetryExportBatchThresholdSizeMB
///  Defaults to 50.
///
///  @note: This property is KVO compliant.
///
@property(readonly) uint32_t telemetryExportMaxFilesPerBatch;

///
///  If set, contains the filesystem access policy configuration.
///
///  @note: The property fileAccessPolicyPlist will be ignored if
///         fileAccessPolicy is set.
///  @note: This property is KVO compliant.
///
@property(nullable, readonly, nonatomic) NSDictionary *fileAccessPolicy;

///
///  If set, contains the path to the filesystem access policy config plist.
///
///  @note: This property will be ignored if fileAccessPolicy is set.
///  @note: This property is KVO compliant.
///
@property(nullable, readonly, nonatomic) NSString *fileAccessPolicyPlist;

///
///  This is the message shown to the user when access to a file is blocked
///  by a binary due to some rule in the current File Access policy if that rule
///  doesn't provide a custom message. If this is not configured, a reasonable
///  default is provided.
///
///  @note: This property is KVO compliant.
///
@property(nullable, readonly, nonatomic) NSString *fileAccessBlockMessage;

///
///  If fileAccessPolicyPlist is set, fileAccessPolicyUpdateIntervalSec
///  sets the number of seconds between times that the configuration file is
///  re-read and policies reconstructed.
///  Defaults to 600 seconds (10 minutes)
///
///  @note: This property is KVO compliant, but should only be read once at santad startup.
///
@property(readonly, nonatomic) uint32_t fileAccessPolicyUpdateIntervalSec;

///
///  Sets the average logs per second that will be emitted by File Access
///  Authorization rule violations.
///  @note: Set to 0 to disable log rate limiting.
///  @note: Rate limiting only applies to logging. FAA rules that are not
///         audit only will still block operations that violate the rule.
///  @note: This property is KVO compliant.
///  See also: FileAccessGlobalWindowSizeSec
///  Defaults to 60.
///
@property(readonly) uint32_t fileAccessGlobalLogsPerSec;

///
///  Sets the window size over which the fileAccessGlobalLogsPerSec
///  setting is applied in order to allow for burts of logs.
///  @note: Set to 0 to disable log rate limiting.
///  @note: Rate limiting only applies to logging. FAA rules that are not
///         audit only will still block operations that violate the rule.
///  @note: This property is KVO compliant.
///  See also: FileAccessGlobalLogsPerSec
///  Defaults to 15.
///
@property(readonly) uint32_t fileAccessGlobalWindowSizeSec;

///
/// Enabling this appends the Santa machine ID to the end of each log line. If nothing
/// has been overridden, this is the host's UUID.
/// Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableMachineIDDecoration;

#pragma mark - GUI Settings

///
///  When in Standalone mode, Santa normally requires TouchID for authorization.
///  This is slightly safer than password authentication because it requires a physical
///  interaction that cannot be spoofed by tools that can type into the dialog.
///
///  However, for users on desktop machines or using clamshell mode standalone mode is
///  unusable without the ability to fallback to a password. If this option is enabled,
///  TouchID is preferred but password fallback is available.
///
///  Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableStandalonePasswordFallback;

///
///  When silent mode is enabled, Santa will never show notifications for
///  blocked processes.
///
///  This can be a very confusing experience for users, use with caution.
///
///  Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableSilentMode;

///
///  When silent TTY mode is enabled, Santa will not emit TTY notifications for
///  blocked processes.
///
///  Defaults to NO.
///
@property(readonly, nonatomic) BOOL enableSilentTTYMode;

///
/// The text to display when opening Santa.app.
/// If unset, the default text will be displayed.
///
@property(nullable, readonly, nonatomic) NSString *aboutText;

///
///  The URL to open when the user clicks "More Info..." when opening Santa.app.
///  If unset, the button will not be displayed.
///
@property(nullable, readonly, nonatomic) NSURL *moreInfoURL;

///
///  When the user gets a block notification, a button can be displayed which will
///  take them to a web page with more information about that event.
///
///  This property contains a kind of format string to be turned into the URL to send them to.
///  The following sequences will be replaced in the final URL:
///
///  %file_sha%    -- SHA-256 of the file that was blocked.
///  %machine_id%  -- ID of the machine.
///  %username%    -- executing user.
///  %serial%      -- System's serial number.
///  %uuid%        -- System's UUID.
///  %hostname%    -- System's full hostname.
///
///  @note: This is not an NSURL because the format-string parsing is done elsewhere.
///
///  If this item isn't set, the Open Event button will not be displayed.
///
@property(nullable, readonly, nonatomic) NSString *eventDetailURL;

///
///  Set the EventDetailURL as received from a sync server.
///
- (void)setSyncServerEventDetailURL:(nullable NSString *)eventDetailURL;

///
///  Related to the above property, this string represents the text to show on the button.
///
@property(nullable, readonly, nonatomic) NSString *eventDetailText;

///
///  Set the EventDetailText as received from a sync server.
///
- (void)setSyncServerEventDetailText:(nullable NSString *)eventDetailText;

///
///  This string represents the text to show on the "Dismiss" button in the UI instead of "Dismiss".
///
@property(nullable, readonly, nonatomic) NSString *dismissText;

///
///  In lockdown mode this is the message shown to the user when an unknown binary
///  is blocked. If this message is not configured, a reasonable default is provided.
///
@property(nullable, readonly, nonatomic) NSString *unknownBlockMessage;

///
///  This is the message shown to the user when a binary is blocked because of a rule,
///  if that rule doesn't provide a custom message. If this is not configured, a reasonable
///  default is provided.
///
@property(nullable, readonly, nonatomic) NSString *bannedBlockMessage;

///
/// This is the message shown to the user when a USB storage device's mount is denied
/// from the BlockUSBMount configuration setting. If not configured, a reasonable
/// default is provided.
///
@property(nullable, readonly, nonatomic) NSString *bannedUSBBlockMessage;

///
/// This is the message shown to the user when a USB storage device's mount is forcibly
/// remounted to a different set of permissions from the BlockUSB and RemountUSBMode
/// configuration settings. If not configured, a reasonable default is provided.
///
@property(nullable, readonly, nonatomic) NSString *remountUSBBlockMessage;

///
/// This is the message shown to the user when a network share mount is denied
/// due to the BlockNetworkMount configuration setting. If not configured, a
/// reasonable default is provided.
///
@property(nullable, readonly, nonatomic) NSString *bannedNetworkMountBlockMessage;

///
///  Set the message to be shown when a network mount is blocked as
///  received from a sync server.
///
- (void)setSyncServerBannedNetworkMountBlockMessage:(nullable NSString *)msg;

///
///  The notification text to display when the client goes into MONITOR mode.
///  Defaults to "Switching into Monitor mode"
///
@property(nullable, readonly, nonatomic) NSString *modeNotificationMonitor;

///
///  The notification text to display when the client goes into LOCKDOWN mode.
///  Defaults to "Switching into Lockdown mode"
///
@property(nullable, readonly, nonatomic) NSString *modeNotificationLockdown;

///
///  The notification text to display when the client goes into STANDALONE mode.
///  Defaults to "Switching into Standalone mode"
///
@property(nullable, readonly, nonatomic) NSString *modeNotificationStandalone;

///
///  If set to true, when a user is presented with a GUI notification there will be
///  a checkbox and dropdown to allow silencing these notifications for a short
///  period of time.
///
///  Defaults to true.
///
@property(readonly, nonatomic) BOOL enableNotificationSilences;

///
///  If this is set to true, the UI will use different fonts on April 1st, May 4th and October 31st.
///
@property(readonly, nonatomic) BOOL funFontsOnSpecificDays;

///
///  If set to true, the menu bar item will be shown.
///
///  Defaults to YES.
///
@property(readonly, nonatomic) BOOL enableMenuItem;

/// User defaults key for user override of the menu item enabled setting.
extern NSString *_Nonnull const kEnableMenuItemUserOverride;

#pragma mark - Sync Settings

///
/// Returns whether or not Santa is able to use private Sync V2 features
///
- (BOOL)isSyncV2Enabled;

///
///  The base URL of the sync server.
///
@property(nullable, readonly, nonatomic) NSURL *syncBaseURL;

///
///  If enabled, syncing will use binary protobufs for transfer instead
///  of JSON. Defaults to NO.
///
@property(readonly, nonatomic) BOOL syncEnableProtoTransfer;

///
///  Proxy settings for syncing.
///  This dictionary is passed directly to NSURLSession. The allowed keys
///  are loosely documented at
///  https://developer.apple.com/documentation/cfnetwork/global-proxy-settings-constants.
///
@property(nullable, readonly, nonatomic) NSDictionary *syncProxyConfig;

///
///  Extra headers to include in all requests made during syncing.
///  Keys and values must all be strings, any other type will be silently ignored.
///  Some headers cannot be set through this key, including:
///
///    * Content-Encoding
///    * Content-Length
///    * Content-Type
///    * Connection
///    * Host
///    * Proxy-Authenticate
///    * Proxy-Authorization
///    * WWW-Authenticate
///
///  The header "Authorization" is also documented by Apple to be one that will
///  be ignored but this is not really the case, at least at present. If you
///  are able to use a different header for this that would be safest but if not
///  using Authorization /should/ be fine.
///
@property(nullable, readonly, nonatomic) NSDictionary *syncExtraHeaders;

///
///  The machine owner.
///
@property(nullable, readonly, nonatomic) NSString *machineOwner;

///
///  The machine owner's groups.
///
@property(nullable, readonly, nonatomic) NSArray<NSString *> *machineOwnerGroups;

///
///  The last date of a successful full sync.
///
@property(nullable, nonatomic) NSDate *fullSyncLastSuccess;

///
///  The last date of a successful rule sync.
///
@property(nullable, nonatomic) NSDate *ruleSyncLastSuccess;

///
///  Type of sync required (e.g. normal, clean, etc.).
///
@property(nonatomic) SNTSyncType syncTypeRequired;

///
///  Full sync interval in seconds. Defaults to kDefaultFullSyncInterval.
///  If push notifications are being used, this interval will be ignored
///  in favor of pushNotificationsFullSyncInterval.
///
@property(readonly, nonatomic) NSUInteger fullSyncInterval;

///
///  Full sync interval in seconds while listening for push notifications.
///  Defaults to kDefaultPushNotificationsFullSyncInterval.
///
@property(readonly, nonatomic) NSUInteger pushNotificationsFullSyncInterval;

///
///  Enable statistics uploading to polaris.northpole.security.
///  See https://northpole.dev/deployment/stats for more info.
///
@property(readonly, nonatomic) BOOL enableStatsCollection;

///
///  Specifies an organization ID to send with collected statistics.
///  Setting this to anything other than a blank string will enable
///  statistics collection, regardless of the EnableStatsCollection key.
///
///  Only populate this field with a value provided to you by
///  North Pole Security, Inc.
///
@property(nullable, readonly, nonatomic) NSString *statsOrganizationID;

///
///  If YES, enables bundle detection for blocked events.
///  Its value is set by a sync server that supports bundles. Defaults to NO.
///
@property BOOL enableBundles;

///
///  Currently defined export configuration. Its value is set by a sync server.
///
@property(nullable, readonly) SNTExportConfiguration *exportConfig;

///
///  Set the export configuration as received from a sync server.
///
- (void)setSyncServerExportConfig:(nonnull SNTExportConfiguration *)exportConfig;

///
///  Currently defined mode transition configuration. Its value is set by a sync server.
///
@property(nullable, readonly) SNTModeTransition *modeTransition;

///
///  Set the mode transition configuration as received from a sync server.
///
- (void)setSyncServerModeTransition:(nonnull SNTModeTransition *)modeTransition;

///
///  Return if Santa is temporarily in Monitor Mode and will revert back
///  to Lockdown Mode after a configured time period.
///
@property(readonly) BOOL inTemporaryMonitorMode;

///
///  Set Santa to be in Monitor Mode temporarily
///
- (void)enterTemporaryMonitorMode:(nullable NSDictionary *)temporaryMonitorModeState;

///
///  Set Santa as having left temporary Monitor Mode
///
- (void)leaveTemporaryMonitorMode;

///
/// Returns the Temporary Monitor Mode state if it exists
///
- (nullable NSDictionary *)savedTemporaryMonitorModeState;

#pragma mark - USB Settings

///
/// USB Mount Blocking. Defaults to false.
///
@property(nonatomic, readonly) BOOL blockUSBMount;

///
///  Set the block USB mount state as received from a sync server.
///
- (void)setSyncServerBlockUSBMount:(BOOL)enabled;

///
/// Comma-separated `$ mount -o` arguments used for forced remounting of USB devices. Default
/// to fully allow/deny without remounting if unset.
///
@property(nullable, nonatomic) NSArray<NSString *> *remountUSBMode;

///
/// Network Mount Blocking. Defaults to false.
/// Note: This feature is only on macOS 15+.
///
@property(readonly) BOOL blockNetworkMount;

///
///  Set the block network mount state as received from a sync server.
///
- (void)setSyncServerBlockNetworkMount:(BOOL)enabled;

//
/// Set of hosts that are allowed to be mounted when blockNetworkMount is true.
///
@property(readonly, nullable) NSArray<NSString *> *allowedNetworkMountHosts;

///
///  Set the explicitly allowed hosts when network mounts are blocked.
///
- (void)setSyncServerAllowedNetworkMountHosts:(nullable NSArray<NSString *> *)hosts;

///
/// If set, defines the action that should be taken on existing USB mounts when
/// Santa starts up.
///
/// Supported values are:
///   * "Unmount": Unmount mass storage devices
///   * "ForceUnmount": Force unmount mass storage devices
///
///
/// Note: Existing mounts with mount flags that are a superset of RemountUSBMode
/// are unaffected and left mounted.
///
@property(readonly, nonatomic) SNTDeviceManagerStartupPreferences onStartUSBOptions;

///
/// If set, will override the action taken when a file access rule violation
/// occurs. This setting will apply across all rules in the file access policy.
///
/// Possible values are
///   * "AuditOnly": When a rule is violated, it will be logged, but the access
///     will not be blocked
///   * "Disable": No access will be logged or blocked.
///
/// If not set, no override will take place and the file acces spolicy will
/// apply as configured.
///
@property(readonly, nonatomic) SNTOverrideFileAccessAction overrideFileAccessAction;

///
///  Set the action that will override file access policy config action
///
- (void)setSyncServerOverrideFileAccessAction:(nonnull NSString *)action;

///
///  If set, this over-rides the default machine ID used for syncing.
///
@property(nullable, readonly, nonatomic) NSString *machineID;

#pragma mark Transitive Allowlist Settings

///
///  If YES, binaries marked with SNTRuleStateAllowCompiler rules are allowed to transitively
///  allow any executables that they produce.  If NO, SNTRuleStateAllowCompiler rules are
///  interpreted as if they were simply SNTRuleStateAllow rules.  Defaults to NO.
///
@property BOOL enableTransitiveRules;

#pragma mark Server Auth Settings

///
///  If set, this is valid PEM containing one or more certificates to be used to evaluate the
///  server's SSL chain, overriding the list of trusted CAs distributed with the OS.
///
@property(nullable, readonly, nonatomic) NSData *syncServerAuthRootsData;

///
///  This property is the same as the above but is a file on disk containing the PEM data.
///
@property(nullable, readonly, nonatomic) NSString *syncServerAuthRootsFile;

#pragma mark Client Auth Settings

///
///  If set, this contains the location of a PKCS#12 certificate to be used for sync authentication.
///
@property(nullable, readonly, nonatomic) NSString *syncClientAuthCertificateFile;

///
///  Contains the password for the pkcs#12 certificate.
///
@property(nullable, readonly, nonatomic) NSString *syncClientAuthCertificatePassword;

///
///  If set, this is the Common Name of a certificate in the System keychain to be used for
///  sync authentication. The corresponding private key must also be in the keychain.
///
@property(nullable, readonly, nonatomic) NSString *syncClientAuthCertificateCn;

///
///  If set, this is the Issuer Name of a certificate in the System keychain to be used for
///  sync authentication. The corresponding private key must also be in the keychain.
///
@property(nullable, readonly, nonatomic) NSString *syncClientAuthCertificateIssuer;

///
///  If true, syncs will upload events when a clean sync is requested. Defaults to false.
///
@property(readonly, nonatomic) BOOL enableCleanSyncEventUpload;

///
///  If true, events will be uploaded for all executions, even those that are allowed.
///  Use with caution, this generates a lot of events. Defaults to false.
///
@property(nonatomic) BOOL enableAllEventUpload;

///
///  If true, events will *not* be uploaded for ALLOW_UNKNOWN events for clients in Monitor mode.
///
@property(nonatomic) BOOL disableUnknownEventUpload;

///
///  If true, ignore actions from other endpoint security clients. Defaults to false. This only
///  applies when running as a sysx.
///
@property(readonly, nonatomic) BOOL ignoreOtherEndpointSecurityClients;

///
///  If true, compressed requests from "santactl sync" will set "Content-Encoding" to "zlib"
///  instead of the new default "deflate". If syncing with Upvote deployed at commit 0b4477d
///  or below, set this option to true.
///  Defaults to false.
///
@property(readonly, nonatomic) BOOL enableBackwardsCompatibleContentEncoding;

///
/// If set, "santactl sync" will use the supplied "Content-Encoding", possible
/// settings include "gzip", "deflate", "none". If empty defaults to "deflate".
///
@property(readonly, nonatomic) SNTSyncContentEncoding syncClientContentEncoding;

///
///  Contains the FCM project name.
///
@property(nullable, readonly, nonatomic) NSString *fcmProject;

///
///  Contains the FCM project entity.
///
@property(nullable, readonly, nonatomic) NSString *fcmEntity;

///
///  Contains the FCM project API key.
///
@property(nullable, readonly, nonatomic) NSString *fcmAPIKey;

///
///  True if fcmProject, fcmEntity and fcmAPIKey are all set. Defaults to false.
///
@property(readonly, nonatomic) BOOL fcmEnabled;

///
///  Set to true to use NATS push notifications. Defaults to true.
///
///  This can only be used with Workshop and SyncV2.
///
@property(readonly, nonatomic) BOOL enablePushNotifications;

///
/// True if metricsFormat and metricsURL are set. False otherwise.
///
@property(readonly, nonatomic) BOOL exportMetrics;

///
/// Format to export Metrics as.
///
@property(readonly, nonatomic) SNTMetricFormatType metricFormat;

///
/// URL describing where metrics are exported, defaults to nil.
///
@property(nullable, readonly, nonatomic) NSURL *metricURL;

///
/// Extra Metric Labels to add to the metrics payloads.
///
@property(nullable, readonly, nonatomic) NSDictionary *extraMetricLabels;

///
/// Duration in seconds of how often the metrics should be exported.
///
@property(readonly, nonatomic) NSUInteger metricExportInterval;

///
/// Duration in seconds for metrics export timeout. Defaults to 30;
///
@property(readonly, nonatomic) NSUInteger metricExportTimeout;

///
/// List of prefix strings for which individual entitlement keys with a matching
/// prefix should not be logged.
///
@property(nullable, readonly, nonatomic) NSArray<NSString *> *entitlementsPrefixFilter;

///
/// List of TeamIDs for which entitlements should not be logged. Use the string
/// "platform" to refer to platform binaries.
///
@property(nullable, readonly, nonatomic) NSArray<NSString *> *entitlementsTeamIDFilter;

///
/// List of enabled process annotations.
/// This property is not KVO compliant.
///
@property(nullable, readonly, nonatomic) NSArray<NSString *> *enabledProcessAnnotations;

///
///  Retrieve an initialized singleton configurator object using the default file path.
///
+ (nonnull instancetype)configurator NS_SWIFT_NAME(configurator());

///
///  Replace the shared configurator with a custom one using a static config.
///
#ifdef DEBUG
+ (void)overrideConfig:(nonnull NSDictionary *)config;
#endif

///
///  Clear the sync server configuration from the effective configuration.
///
- (void)clearSyncState;

///
///  Validate the configuration profile.
///
- (nullable NSArray *)validateConfiguration;

#pragma mark Stats Submission State

///
/// Timestamp of the last time a stats submission was attempted
///
@property(nullable, readonly, nonatomic) NSDate *lastStatsSubmissionTimestamp;

///
/// Santa version information from the last time a stats submission was attempted
///
@property(nullable, readonly, nonatomic) NSString *lastStatsSubmissionVersion;

///
/// Update the stats state file
///
- (void)saveStatsSubmissionAttemptTime:(nullable NSDate *)timestamp
                               version:(nullable NSString *)version;

///
/// Returns true if the system has rebooted since the last time santad was run.
///
@property(readonly, nonatomic) BOOL isFirstLaunchAfterBoot;

@end
