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

#include <libproc.h>
#include <unistd.h>

#include <optional>
#include <vector>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SystemResources.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandDoctor : SNTCommand <SNTCommandProtocol>
@end

void print(NSString *format, ...) {
  va_list args;
  va_start(args, format);

  if (isatty(STDOUT_FILENO)) {
    if ([format hasPrefix:@"[-]"]) {
      format = [NSString stringWithFormat:@"\033[31m%@\033[0m\n", format];
    } else if ([format hasPrefix:@"[+]"]) {
      format = [NSString stringWithFormat:@"\033[32m%@\033[0m\n", format];
    } else {
      format = [NSString stringWithFormat:@"%@\n", format];
    }
  }
  vfprintf(stdout, format.UTF8String, args);
  va_end(args);
}

@implementation SNTCommandDoctor

REGISTER_COMMAND_NAME(@"doctor")

+ (BOOL)requiresRoot {
  // This command requires root in order to retrieve all the data it needs.
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"TODO";
}

+ (NSString *)longHelpText {
  return @"TODO";
}

- (void)runWithArguments:(NSArray *)arguments {
  BOOL err = NO;
  err |= [self validateProcesses];
  err |= [self validateConfiguration];
  exit(err);
}

- (BOOL)validateProcesses {
  print(@"=> Validating processes...");

  BOOL foundSanta = NO, foundSantad = NO, foundSantaSyncService = NO;

  std::optional<std::vector<pid_t>> pidList = GetPidList();
  if (!pidList.has_value()) {
    print(@"[-] Failed to retrieve processes");
    return YES;
  }

  for (pid_t pid : pidList.value()) {
    // Copies the contents of info.pbi_name or info.pbi_comm into buffer.
    // Since pbi_comm is limited to first 15 chars, pbi_name is preferred.
    char name[2 * MAXCOMLEN];
    proc_name(pid, name, sizeof(name));

    NSString *nsName = @(name);
    if ([nsName isEqualToString:@"Santa"]) foundSanta = YES;
    if ([nsName isEqualToString:@"com.northpolesec.santa.daemon"]) foundSantad = YES;
    if ([nsName isEqualToString:@"santasyncservice"]) foundSantaSyncService = YES;
  }

  if (!foundSanta) {
    print(@"[-] Santa GUI process doesn't seem to be running");
  }
  if (!foundSantad) {
    print(@"[-] Santa system extension doesn't seem to be running");
  }
  if ([SNTConfigurator configurator].syncBaseURL.absoluteString.length && !foundSantaSyncService) {
    print(@"[-] Santa sync service doesn't seem to be running");
  }
  if (foundSanta && foundSantad && foundSantaSyncService) {
    print(@"[+] No issues detected");
  }

  print(@"");

  return (!foundSanta || !foundSantad || !foundSantaSyncService);
}

- (BOOL)validateConfiguration {
  print(@"=> Validating configuration...");
  NSArray *errors = [[SNTConfigurator configurator] validateConfiguration];
  if (!errors.count) {
    print(@"[+] No configuration errors detected");
    return NO;
  }

  for (NSString *e in errors) {
    print(@"[-] %s", [e UTF8String]);
  }

  print(@"");
  return YES;
}

@end
