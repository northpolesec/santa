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

#import <Foundation/Foundation.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTXPCUnprivilegedControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandVersion : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandVersion

REGISTER_COMMAND_NAME(@"version")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Show Santa component versions.";
}

+ (NSString *)longHelpText {
  return (@"Show versions of all Santa components.\n"
          @"  Use --json to output in JSON format.");
}

- (void)runWithArguments:(NSArray *)arguments {
  // Best-effort connection to santad for querying santanetd info.
  // Skip XPC queries if the connection fails to avoid unnecessary timeouts.
  [self.daemonConn resume];

  NSDictionary *loadedNetdInfo = nil;
  BOOL netExtEnabled = NO;
  if (self.daemonConn.isConnected) {
    loadedNetdInfo = [self queryLoadedNetdBundleInfo];
    netExtEnabled = [self queryNetworkExtensionEnabled];
  }
  NSString *loadedNetdVersion = [self composeVersionsFromDict:loadedNetdInfo];
  NSString *bundledNetdVersion = [self santanetdBundledVersion];

  if ([arguments containsObject:@"--json"]) {
    NSMutableDictionary *versions = [@{
      @"santad" : [self santadVersion],
      @"santactl" : [self santactlVersion],
      @"SantaGUI" : [self santaAppVersion],
    } mutableCopy];

    if (loadedNetdVersion.length > 0) {
      versions[@"santanetd"] = loadedNetdVersion;
      if (bundledNetdVersion.length > 0 &&
          ![loadedNetdVersion isEqualToString:bundledNetdVersion]) {
        versions[@"santanetd_bundled"] = bundledNetdVersion;
      }
    } else if (bundledNetdVersion.length > 0 && netExtEnabled) {
      versions[@"santanetd"] = bundledNetdVersion;
    }

    NSData *versionsData = [NSJSONSerialization dataWithJSONObject:versions
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:nil];
    NSString *versionsStr = [[NSString alloc] initWithData:versionsData
                                                  encoding:NSUTF8StringEncoding];
    printf("%s\n", [versionsStr UTF8String]);
  } else {
    printf("%-20s | %s\n", "santad", [[self santadVersion] UTF8String]);
    printf("%-20s | %s\n", "santactl", [[self santactlVersion] UTF8String]);
    printf("%-20s | %s\n", "SantaGUI", [[self santaAppVersion] UTF8String]);

    if (loadedNetdVersion.length > 0) {
      if (bundledNetdVersion.length > 0 &&
          ![loadedNetdVersion isEqualToString:bundledNetdVersion]) {
        printf("%-20s | %s (bundled: %s)\n", "santanetd (BETA)", [loadedNetdVersion UTF8String],
               [bundledNetdVersion UTF8String]);
      } else {
        printf("%-20s | %s\n", "santanetd (BETA)", [loadedNetdVersion UTF8String]);
      }
    } else if (bundledNetdVersion.length > 0 && netExtEnabled) {
      printf("%-20s | %s\n", "santanetd (BETA)", [bundledNetdVersion UTF8String]);
    }
  }
  exit(0);
}

- (NSDictionary *)queryLoadedNetdBundleInfo {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  self.daemonConn.invalidationHandler = ^{
    dispatch_semaphore_signal(sema);
  };

  __block NSDictionary *result = nil;
  [[self.daemonConn remoteObjectProxy]
      networkExtensionLoadedBundleVersionInfo:^(NSDictionary *bundleInfo) {
        result = bundleInfo;
        dispatch_semaphore_signal(sema);
      }];

  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
  return result;
}

- (BOOL)queryNetworkExtensionEnabled {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  self.daemonConn.invalidationHandler = ^{
    dispatch_semaphore_signal(sema);
  };

  __block BOOL enabled = NO;
  [[self.daemonConn remoteObjectProxy] networkExtensionEnabled:^(BOOL result) {
    enabled = result;
    dispatch_semaphore_signal(sema);
  }];

  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC));
  return enabled;
}

- (NSString *)composeVersionsFromDict:(NSDictionary *)dict {
  if (!dict[@"CFBundleVersion"]) return @"";
  NSString *productVersion = dict[@"CFBundleShortVersionString"];
  NSString *buildVersion = [[dict[@"CFBundleVersion"] componentsSeparatedByString:@"."] lastObject];

  NSString *commitHash = dict[@"SNTCommitHash"];
  if (commitHash.length > 8) {
    commitHash = [commitHash substringToIndex:8];
  }

  return [NSString
      stringWithFormat:@"%@ (build %@, commit %@)", productVersion, buildVersion, commitHash];
}

- (NSString *)santadVersion {
  SNTFileInfo *daemonInfo = [[SNTFileInfo alloc] initWithPath:@(kSantaDPath)];
  return [self composeVersionsFromDict:daemonInfo.infoPlist];
}

- (NSString *)santaAppVersion {
  SNTFileInfo *guiInfo = [[SNTFileInfo alloc] initWithPath:@(kSantaAppPath)];
  return [self composeVersionsFromDict:guiInfo.infoPlist];
}

- (NSString *)santactlVersion {
  return [self composeVersionsFromDict:[[NSBundle mainBundle] infoDictionary]];
}

- (NSString *)santanetdBundledVersion {
  SNTFileInfo *netdInfo = [[SNTFileInfo alloc] initWithPath:@(kSantaNetdPath)];
  return [self composeVersionsFromDict:netdInfo.infoPlist];
}

@end
