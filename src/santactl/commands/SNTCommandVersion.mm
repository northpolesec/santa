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

#import "src/common/MOLXPCConnection.h"
#import "src/common/SNTCommonEnums.h"
#import "src/common/SNTConfigurator.h"
#import "src/common/SNTFileInfo.h"
#import "src/santactl/SNTCommand.h"
#import "src/santactl/SNTCommandController.h"

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
  if ([arguments containsObject:@"--json"]) {
    NSDictionary *versions = @{
      @"santad" : [self santadVersion],
      @"santactl" : [self santactlVersion],
      @"SantaGUI" : [self santaAppVersion],
    };
    NSData *versionsData = [NSJSONSerialization dataWithJSONObject:versions
                                                           options:NSJSONWritingPrettyPrinted
                                                             error:nil];
    NSString *versionsStr = [[NSString alloc] initWithData:versionsData
                                                  encoding:NSUTF8StringEncoding];
    printf("%s\n", [versionsStr UTF8String]);
  } else {
    printf("%-15s | %s\n", "santad", [[self santadVersion] UTF8String]);
    printf("%-15s | %s\n", "santactl", [[self santactlVersion] UTF8String]);
    printf("%-15s | %s\n", "SantaGUI", [[self santaAppVersion] UTF8String]);
  }
  exit(0);
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

@end
