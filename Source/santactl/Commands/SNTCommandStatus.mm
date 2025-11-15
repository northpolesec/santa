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

#import <Foundation/Foundation.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTXPCControlInterface.h"
#include "Source/common/faa/WatchItems.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

NSString *StartupOptionToString(SNTDeviceManagerStartupPreferences pref) {
  switch (pref) {
    case SNTDeviceManagerStartupPreferencesUnmount: return @"Unmount";
    case SNTDeviceManagerStartupPreferencesForceUnmount: return @"ForceUnmount";
    case SNTDeviceManagerStartupPreferencesRemount: return @"Remount";
    case SNTDeviceManagerStartupPreferencesForceRemount: return @"ForceRemount";
    default: return @"None";
  }
}

NSString *FormatTimeRemaining(NSTimeInterval seconds) {
  NSDateComponentsFormatter *formatter = [[NSDateComponentsFormatter alloc] init];
  formatter.unitsStyle = NSDateComponentsFormatterUnitsStyleFull;
  formatter.allowedUnits =
      NSCalendarUnitDay | NSCalendarUnitHour | NSCalendarUnitMinute | NSCalendarUnitSecond;
  formatter.collapsesLargestUnit = NO;
  formatter.includesTimeRemainingPhrase = YES;
  formatter.includesApproximationPhrase = YES;
  formatter.maximumUnitCount = 2;

  return [formatter stringFromTimeInterval:seconds];
}

@interface SNTCommandStatus : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandStatus

REGISTER_COMMAND_NAME(@"status")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Show Santa status information.";
}

+ (NSString *)longHelpText {
  return (@"Provides details about Santa while it's running.\n"
          @"  Use --json to output in JSON format");
}

- (void)runWithArguments:(NSArray *)arguments {
  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];

  // Daemon status
  __block NSString *clientMode;
  __block uint64_t cpuEvents, ramEvents;
  __block double cpuPeak, ramPeak;

  [rop temporaryMonitorModeSecondsRemaining:^(NSNumber *val) {
    if (val) {
      clientMode = [@"Temporary Monitor Mode "
          stringByAppendingFormat:@"(%@)", FormatTimeRemaining([val unsignedLongLongValue])];
    } else {
      [rop clientMode:^(SNTClientMode cm) {
        switch (cm) {
          case SNTClientModeMonitor: clientMode = @"Monitor"; break;
          case SNTClientModeLockdown: clientMode = @"Lockdown"; break;
          case SNTClientModeStandalone: clientMode = @"Standalone"; break;
          default: clientMode = [NSString stringWithFormat:@"Unknown (%ld)", cm]; break;
        }
      }];
    }
  }];

  [rop watchdogInfo:^(uint64_t wd_cpuEvents, uint64_t wd_ramEvents, double wd_cpuPeak,
                      double wd_ramPeak) {
    cpuEvents = wd_cpuEvents;
    cpuPeak = wd_cpuPeak;
    ramEvents = wd_ramEvents;
    ramPeak = wd_ramPeak;
  }];

  BOOL fileLogging = ([[SNTConfigurator configurator] fileChangesRegex] != nil);
  NSString *eventLogType = [[[SNTConfigurator configurator] eventLogTypeRaw] lowercaseString];

  SNTConfigurator *configurator = [SNTConfigurator configurator];

  // Cache status
  __block uint64_t rootCacheCount = -1, nonRootCacheCount = -1;
  [rop cacheCounts:^(uint64_t rootCache, uint64_t nonRootCache) {
    rootCacheCount = rootCache;
    nonRootCacheCount = nonRootCache;
  }];

  // Database counts
  __block struct RuleCounts ruleCounts = {
      .binary = -1,
      .certificate = -1,
      .compiler = -1,
      .transitive = -1,
      .teamID = -1,
      .signingID = -1,
      .cdhash = -1,
      .fileAccess = -1,
  };
  [rop databaseRuleCounts:^(struct RuleCounts counts) {
    ruleCounts = counts;
  }];

  __block int64_t eventCount = -1;
  [rop databaseEventCount:^(int64_t count) {
    eventCount = count;
  }];

  // Static rule count
  __block int64_t staticRuleCount = -1;
  [rop staticRuleCount:^(int64_t count) {
    staticRuleCount = count;
  }];

  // Rules hash
  __block NSString *executionRulesHash;
  __block NSString *fileAccessRulesHash;
  [rop databaseRulesHash:^(NSString *execRulesHash, NSString *faaRulesHash) {
    executionRulesHash = execRulesHash;
    fileAccessRulesHash = faaRulesHash;
  }];

  // Sync status
  __block NSDate *fullSyncLastSuccess;
  [rop fullSyncLastSuccess:^(NSDate *date) {
    fullSyncLastSuccess = date;
  }];

  __block NSDate *ruleSyncLastSuccess;
  [rop ruleSyncLastSuccess:^(NSDate *date) {
    ruleSyncLastSuccess = date;
  }];

  __block BOOL syncCleanReqd = NO;
  [rop syncTypeRequired:^(SNTSyncType syncType) {
    syncCleanReqd = (syncType == SNTSyncTypeClean || syncType == SNTSyncTypeCleanAll);
  }];

  __block NSString *pushNotifications = @"Unknown";
  if ([[SNTConfigurator configurator] syncBaseURL]) {
    // The request to santad to discover whether push notifications are enabled
    // makes a call to santasyncservice. If it's unavailable the call can hang
    // so we run the request asynchronously with a semaphore timer; if we have
    // no response within 2s, give up and move on.
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      [rop pushNotificationStatus:^(SNTPushNotificationStatus response) {
        switch (response) {
          case SNTPushNotificationStatusDisabled: pushNotifications = @"Disabled"; break;
          case SNTPushNotificationStatusDisconnected: pushNotifications = @"Disconnected"; break;
          case SNTPushNotificationStatusConnected: pushNotifications = @"Connected"; break;
          default: break;
        }
        dispatch_semaphore_signal(sema);
      }];
    });
    dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
  }

  __block BOOL enableBundles = NO;
  if ([[SNTConfigurator configurator] syncBaseURL]) {
    [rop enableBundles:^(BOOL response) {
      enableBundles = response;
    }];
  }

  __block BOOL enableTransitiveRules = NO;
  [rop enableTransitiveRules:^(BOOL response) {
    enableTransitiveRules = response;
  }];

  __block BOOL watchItemsEnabled = NO;
  __block uint64_t watchItemsRuleCount = 0;
  __block NSString *watchItemsPolicyVersion = nil;
  __block NSString *watchItemsConfigPath = nil;
  __block NSTimeInterval watchItemsLastUpdateEpoch = 0;
  __block santa::WatchItems::DataSource watchItemsDataSource;
  [rop watchItemsState:^(BOOL enabled, uint64_t ruleCount, NSString *policyVersion,
                         santa::WatchItems::DataSource dataSource, NSString *configPath,
                         NSTimeInterval lastUpdateEpoch) {
    watchItemsEnabled = enabled;
    if (enabled) {
      watchItemsRuleCount = ruleCount;
      watchItemsPolicyVersion = policyVersion;
      watchItemsDataSource = dataSource;
      watchItemsConfigPath = configPath;
      watchItemsLastUpdateEpoch = lastUpdateEpoch;
    }
  }];

  __block BOOL blockUSBMount = NO;
  [rop blockUSBMount:^(BOOL response) {
    blockUSBMount = response;
  }];

  __block NSArray<NSString *> *remountUSBMode;
  [rop remountUSBMode:^(NSArray<NSString *> *response) {
    remountUSBMode = response;
  }];

  // Format dates
  NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
  dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";
  NSString *fullSyncLastSuccessStr = [dateFormatter stringFromDate:fullSyncLastSuccess] ?: @"Never";
  NSString *ruleSyncLastSuccessStr =
      [dateFormatter stringFromDate:ruleSyncLastSuccess] ?: fullSyncLastSuccessStr;

  NSString *watchItemsLastUpdateStr =
      [dateFormatter
          stringFromDate:[NSDate dateWithTimeIntervalSince1970:watchItemsLastUpdateEpoch]]
          ?: @"Never";

  NSString *syncURLStr = configurator.syncBaseURL.absoluteString;

  BOOL exportMetrics = configurator.exportMetrics;
  NSURL *metricsURLStr = configurator.metricURL;
  NSUInteger metricExportInterval = configurator.metricExportInterval;

  if ([arguments containsObject:@"--json"]) {
    NSMutableDictionary *stats = [@{
      @"daemon" : @{
        @"mode" : clientMode ?: @"null",
        @"log_type" : eventLogType,
        @"file_logging" : @(fileLogging),
        @"watchdog_cpu_events" : @(cpuEvents),
        @"watchdog_ram_events" : @(ramEvents),
        @"watchdog_cpu_peak" : @(cpuPeak),
        @"watchdog_ram_peak" : @(ramPeak),
        @"block_usb" : @(blockUSBMount),
        @"remount_usb_mode" : (blockUSBMount && remountUSBMode.count ? remountUSBMode : @""),
        @"on_start_usb_options" : StartupOptionToString(configurator.onStartUSBOptions),
        @"static_rules" : @(staticRuleCount),
      },
      @"cache" : @{
        @"root_cache_count" : @(rootCacheCount),
        @"non_root_cache_count" : @(nonRootCacheCount),
      },
      @"transitive_allowlisting" : @{
        @"enabled" : @(enableTransitiveRules),
        @"compiler_rules" : @(ruleCounts.compiler),
        @"transitive_rules" : @(ruleCounts.transitive),
      },
      @"rule_types" : @{
        @"binary_rules" : @(ruleCounts.binary),
        @"certificate_rules" : @(ruleCounts.certificate),
        @"teamid_rules" : @(ruleCounts.teamID),
        @"signingid_rules" : @(ruleCounts.signingID),
        @"cdhash_rules" : @(ruleCounts.cdhash),
      },
    } mutableCopy];

    if (syncURLStr.length) {
      stats[@"sync"] = [@{
        @"enabled" : @(YES),
        @"server" : syncURLStr ?: @"null",
        @"clean_required" : @(syncCleanReqd),
        @"last_successful_full" : fullSyncLastSuccessStr ?: @"null",
        @"last_successful_rule" : ruleSyncLastSuccessStr ?: @"null",
        @"push_notifications" : pushNotifications,
        @"bundle_scanning" : @(enableBundles),
        @"events_pending_upload" : @(eventCount),
        @"execution_rules_hash" : executionRulesHash ?: @"null",
      } mutableCopy];

      if (watchItemsDataSource == santa::WatchItems::DataSource::kDatabase) {
        stats[@"sync"][@"file_access_rules_hash"] = (fileAccessRulesHash ?: @"null");
      }
    } else {
      stats[@"sync"] = @{
        @"enabled" : @(NO),
      };
    }

    if (watchItemsEnabled) {
      stats[@"watch_items"] = [@{
        @"enabled" : @(watchItemsEnabled),
        @"data_source" : santa::WatchItems::DataSourceName(watchItemsDataSource),
        @"rule_count" : @(watchItemsRuleCount),
        @"last_policy_update" : watchItemsLastUpdateStr ?: @"null",
      } mutableCopy];

      if (watchItemsPolicyVersion.length > 0) {
        stats[@"watch_items"][@"policy_version"] = watchItemsPolicyVersion;
      }

      if (watchItemsDataSource == santa::WatchItems::DataSource::kDetachedConfig) {
        stats[@"watch_items"][@"config_path"] = watchItemsConfigPath ?: @"null";
      }
    } else {
      stats[@"watch_items"] = @{
        @"enabled" : @(watchItemsEnabled),
      };
    }

    if (exportMetrics) {
      stats[@"metrics"] = @{
        @"enabled" : @(YES),
        @"server" : [metricsURLStr absoluteString] ?: @"null",
        @"export_interval_seconds" : @(metricExportInterval),
      };
    } else {
      stats[@"metrics"] = @{
        @"enabled" : @(NO),
      };
    }

    NSData *statsData = [NSJSONSerialization dataWithJSONObject:stats
                                                        options:NSJSONWritingPrettyPrinted
                                                          error:nil];
    NSString *statsStr = [[NSString alloc] initWithData:statsData encoding:NSUTF8StringEncoding];
    printf("%s\n", [statsStr UTF8String]);
  } else {
    printf(">>> Daemon Info\n");
    printf("  %-25s | %s\n", "Mode", [clientMode UTF8String]);
    printf("  %-25s | %s\n", "Log Type", [eventLogType UTF8String]);
    printf("  %-25s | %s\n", "File Logging", (fileLogging ? "Yes" : "No"));
    printf("  %-25s | %s\n", "USB Blocking", (blockUSBMount ? "Yes" : "No"));
    if (blockUSBMount && remountUSBMode.count > 0) {
      printf("  %-25s | %s\n", "USB Remounting Mode",
             [[remountUSBMode componentsJoinedByString:@", "] UTF8String]);
    }
    printf("  %-25s | %s\n", "On Start USB Options",
           StartupOptionToString(configurator.onStartUSBOptions).UTF8String);
    printf("  %-25s | %lld\n", "Static Rules", staticRuleCount);
    printf("  %-25s | %lld  (Peak: %.2f%%)\n", "Watchdog CPU Events", cpuEvents, cpuPeak);
    printf("  %-25s | %lld  (Peak: %.2fMB)\n", "Watchdog RAM Events", ramEvents, ramPeak);

    printf(">>> Cache Info\n");
    printf("  %-25s | %lld\n", "Root cache count", rootCacheCount);
    printf("  %-25s | %lld\n", "Non-root cache count", nonRootCacheCount);

    printf(">>> Transitive Allowlisting\n");
    printf("  %-25s | %s\n", "Enabled", (enableTransitiveRules ? "Yes" : "No"));
    printf("  %-25s | %lld\n", "Compiler Rules", ruleCounts.compiler);
    printf("  %-25s | %lld\n", "Transitive Rules", ruleCounts.transitive);

    printf(">>> Rule Types\n");
    printf("  %-25s | %lld\n", "Binary Rules", ruleCounts.binary);
    printf("  %-25s | %lld\n", "Certificate Rules", ruleCounts.certificate);
    printf("  %-25s | %lld\n", "TeamID Rules", ruleCounts.teamID);
    printf("  %-25s | %lld\n", "SigningID Rules", ruleCounts.signingID);
    printf("  %-25s | %lld\n", "CDHash Rules", ruleCounts.cdhash);

    printf(">>> Watch Items\n");
    printf("  %-25s | %s\n", "Enabled", (watchItemsEnabled ? "Yes" : "No"));
    if (watchItemsEnabled) {
      printf("  %-25s | %s\n", "Data Source",
             santa::WatchItems::DataSourceName(watchItemsDataSource).UTF8String);
      if (watchItemsDataSource == santa::WatchItems::DataSource::kDetachedConfig) {
        printf("  %-25s | %s\n", "Config Path", (watchItemsConfigPath ?: @"null").UTF8String);
      }
      if (watchItemsPolicyVersion.length > 0) {
        printf("  %-25s | %s\n", "Policy Version", watchItemsPolicyVersion.UTF8String);
      }
      printf("  %-25s | %llu\n", "Rule Count", watchItemsRuleCount);
      printf("  %-25s | %s\n", "Last Policy Update", watchItemsLastUpdateStr.UTF8String);
    }

    printf(">>> Sync\n");
    printf("  %-25s | %s\n", "Enabled", syncURLStr.length ? "Yes" : "No");
    if (syncURLStr.length) {
      printf("  %-25s | %s\n", "Sync Server", [syncURLStr UTF8String]);
      printf("  %-25s | %s\n", "Clean Sync Required", (syncCleanReqd ? "Yes" : "No"));
      printf("  %-25s | %s\n", "Last Successful Full Sync", [fullSyncLastSuccessStr UTF8String]);
      printf("  %-25s | %s\n", "Last Successful Rule Sync", [ruleSyncLastSuccessStr UTF8String]);
      printf("  %-25s | %s\n", "Push Notifications", [pushNotifications UTF8String]);
      printf("  %-25s | %s\n", "Bundle Scanning", (enableBundles ? "Yes" : "No"));
      printf("  %-25s | %lld\n", "Events Pending Upload", eventCount);
      printf("  %-25s | %s\n", "Execution Rules Hash", [executionRulesHash UTF8String]);
      if (watchItemsDataSource == santa::WatchItems::DataSource::kDatabase) {
        printf("  %-25s | %s\n", "File Access Rules Hash",
               [(fileAccessRulesHash ?: @"null") UTF8String]);
      }
    }

    printf(">>> Metrics\n");
    printf("  %-25s | %s\n", "Enabled", exportMetrics ? "Yes" : "No");
    if (exportMetrics) {
      printf("  %-25s | %s\n", "Metrics Server", [[metricsURLStr absoluteString] UTF8String]);
      printf("  %-25s | %lu\n", "Export Interval (seconds)", metricExportInterval);
    }
  }

  exit(0);
}

@end
