/// Copyright 2015 Google Inc. All rights reserved.
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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLiteDetector.h"
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

+ (NSString*)shortHelpText {
  return @"Show Santa component versions.";
}

+ (NSString*)longHelpText {
  return (@"Show versions of all Santa components.\n"
          @"  Options:\n"
          @"    --json: Output in JSON format.");
}

- (void)runWithArguments:(NSArray*)arguments {
  BOOL isLite = santa::SNTIsLiteInstall();
  BOOL hasNetd = [[NSFileManager defaultManager] fileExistsAtPath:@(kSantaNetdPath)];

  // Best-effort connection to santad for querying santanetd info.
  // Skip XPC queries if the connection fails to avoid unnecessary timeouts.
  NSDictionary* loadedNetdInfo = nil;
  BOOL netExtEnabled = NO;
  [self.daemonConn resume];
  if (self.daemonConn.isConnected) {
    loadedNetdInfo = [self queryLoadedNetdBundleInfo];
    netExtEnabled = [self queryNetworkExtensionEnabled];
  }
  NSString* loadedNetdVersion = [self composeVersionsFromDict:loadedNetdInfo];
  NSString* bundledNetdVersion = hasNetd ? [self santanetdBundledVersion] : @"";

  if ([arguments containsObject:@"--json"]) {
    NSMutableDictionary* versions = [@{
      @"santad" : [self santadVersion],
      @"santactl" : [self santactlVersion],
      @"SantaGUI" : [self santaAppVersion],
    } mutableCopy];

    if (isLite) {
      versions[@"edition"] = @"Lite";
    }

    if (loadedNetdVersion.length > 0) {
      versions[@"santanetd"] = loadedNetdVersion;
      if (bundledNetdVersion.length > 0 &&
          ![loadedNetdVersion isEqualToString:bundledNetdVersion]) {
        versions[@"santanetd_bundled"] = bundledNetdVersion;
      }
    } else if (bundledNetdVersion.length > 0 && netExtEnabled) {
      versions[@"santanetd"] = bundledNetdVersion;
    }

    NSData* versionsData = [NSJSONSerialization dataWithJSONObject:versions
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:nil];
    NSString* versionsStr = [[NSString alloc] initWithData:versionsData
                                                  encoding:NSUTF8StringEncoding];
    printf("%s\n", [versionsStr UTF8String]);
  } else {
    if (isLite) {
      printf("%-20s | %s\n", "Edition", "Lite");
    }
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

- (NSDictionary*)queryLoadedNetdBundleInfo {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  self.daemonConn.invalidationHandler = ^{
    dispatch_semaphore_signal(sema);
  };

  __block NSDictionary* result = nil;
  [[self.daemonConn remoteObjectProxy]
      networkExtensionLoadedBundleVersionInfo:^(NSDictionary* bundleInfo) {
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

- (NSString*)composeVersionWithShortVersion:(NSString*)productVersion
                                fullVersion:(NSString*)fullVersion
                                 commitHash:(NSString*)commitHash {
  if (!fullVersion.length) return @"";
  NSString* buildVersion = [[fullVersion componentsSeparatedByString:@"."] lastObject];

  if (commitHash.length > 8) {
    commitHash = [commitHash substringToIndex:8];
  }

  return [NSString
      stringWithFormat:@"%@ (build %@, commit %@)", productVersion, buildVersion, commitHash];
}

// Compose a version string from a plist dictionary whose values are read type-safely. Used for
// dictionaries that don't come from an SNTFileInfo: the netext bundle info returned over XPC and
// santactl's own mainBundle.
- (NSString*)composeVersionsFromDict:(NSDictionary*)dict {
  NSString* (^string)(NSString*) = ^NSString*(NSString* key) {
    id value = dict[key];
    return [value isKindOfClass:[NSString class]] ? value : nil;
  };
  return [self composeVersionWithShortVersion:string(@"CFBundleShortVersionString")
                                  fullVersion:string(@"CFBundleVersion")
                                   commitHash:string(@"SNTCommitHash")];
}

- (NSString*)composeVersionsFromFileInfo:(SNTFileInfo*)fileInfo {
  return [self composeVersionWithShortVersion:[fileInfo bundleShortVersionString]
                                  fullVersion:[fileInfo bundleVersion]
                                   commitHash:[fileInfo infoPlistStringForKey:@"SNTCommitHash"]];
}

- (NSString*)santadVersion {
  return [self composeVersionsFromFileInfo:[[SNTFileInfo alloc] initWithPath:@(kSantaDPath)]];
}

- (NSString*)santaAppVersion {
  return [self composeVersionsFromFileInfo:[[SNTFileInfo alloc] initWithPath:@(kSantaAppPath)]];
}

- (NSString*)santactlVersion {
  return [self composeVersionsFromDict:[[NSBundle mainBundle] infoDictionary]];
}

- (NSString*)santanetdBundledVersion {
  return [self composeVersionsFromFileInfo:[[SNTFileInfo alloc] initWithPath:@(kSantaNetdPath)]];
}

@end
