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
#import <SystemConfiguration/SystemConfiguration.h>

#include <libproc.h>
#include <unistd.h>

#include <optional>
#include <vector>

#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCSyncServiceInterface.h"
#import "Source/common/SystemResources.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandDoctor : SNTCommand <SNTCommandProtocol, SNTSyncServiceLogReceiverXPC>
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

// Returns YES if a user is logged in at the GUI console, NO otherwise.
// When at the login screen (no user logged in), console user will be "loginwindow" with uid 0.
BOOL IsConsoleUserLoggedIn() {
  uid_t uid;
  CFBridgingRelease(SCDynamicStoreCopyConsoleUser(NULL, &uid, NULL));
  // uid 0 indicates no user is logged in (loginwindow or root)
  return uid > 0;
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
  return @"Check your system for potential problems.";
}

+ (NSString *)longHelpText {
  return @"Doctor checks your system for potential problems and prints out details of any problems "
         @"that it finds.\n"
         @"\n"
         @"Will exit with a non-zero exit code if any problems are found.\n"
         @"\n"
         @"Note that this is intended to help debug support personnel issues which Santa is unable "
         @"to resolve itself.";
}

- (void)runWithArguments:(NSArray *)arguments {
  BOOL err = NO;
  err |= [self validateProcesses];
  err |= [self validateConfiguration];
  err |= [self validateSync];
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

  foundSanta = foundSanta || !IsConsoleUserLoggedIn();
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
    print(@"");
    return NO;
  }

  for (NSString *e in errors) {
    print(@"[-] %s", [e UTF8String]);
  }

  print(@"");
  return YES;
}

- (void)didReceiveLog:(NSString *)log withType:(os_log_type_t)logType {
  print(@"    %s", log.UTF8String);
}

- (BOOL)validateSync {
  print(@"=> Validating sync...");

  SNTConfigurator *config = [SNTConfigurator configurator];

  NSURL *syncBaseURL = config.syncBaseURL;
  if (!syncBaseURL) {
    print(@"[+] Sync is disabled");
    print(@"");
    // Don't treat this as an error.
    return YES;
  }
  print(@"[+] Sync is enabled");
  print(@"[+] Machine ID: %s", config.machineID.UTF8String ?: "(not set)");
  print(@"[+] Machine Owner: %s", config.machineOwner.UTF8String ?: "(not set)");

  if (![syncBaseURL.scheme isEqualToString:@"https"]) {
    print(@"[-] Sync is not using HTTPS");
  } else {
    print(@"[+] Sync is using HTTPS");
  }

  MOLXPCConnection *conn = [SNTXPCSyncServiceInterface configuredConnection];
  [conn resume];

  NSXPCListener *logListener = [NSXPCListener anonymousListener];
  MOLXPCConnection *lr = [[MOLXPCConnection alloc] initServerWithListener:logListener];
  lr.exportedObject = self;
  lr.unprivilegedInterface =
      [NSXPCInterface interfaceWithProtocol:@protocol(SNTSyncServiceLogReceiverXPC)];
  [lr resume];

  dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
  __block BOOL err = NO;

  id<SNTSyncServiceXPC> proxy = conn.remoteObjectProxy;
  if (!proxy) {
    print(@"[-] Failed to connect to sync service");
    print(@"");
    return YES;
  }

  [proxy checkSyncServerStatus:logListener.endpoint
                         reply:^(NSInteger statusCode, NSString *description) {
                           if (statusCode == 0) {
                             print(@"[-] Failed to retrieve preflight data: %s",
                                   description.UTF8String);
                             err = YES;
                           } else if (statusCode == 301) {
                             print(@"[?] %s", description.UTF8String);
                           } else if (statusCode == 200 || statusCode == 400) {
                             // Treat a 400 as OK: we didn't populate any data or set an
                             // appropriate Content-Type.
                             print(@"[+] Preflight request succeeded");
                           } else {
                             print(@"[-] HTTP response code: %ld %s", (long)statusCode,
                                   description.UTF8String);
                             err = YES;
                           }
                           dispatch_semaphore_signal(semaphore);
                         }];
  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

  [conn invalidate];

  print(@"");

  return err;
}

@end
