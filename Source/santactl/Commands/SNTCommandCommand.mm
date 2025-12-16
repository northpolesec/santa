/// Copyright 2025 North Pole Security, Inc.
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

// This command currently only exists in debug builds
#ifdef DEBUG

#import "Source/santactl/SNTCommand.h"

#include <cstdlib>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTKillCommand.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandCommand : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandCommand

REGISTER_COMMAND_NAME(@"command")

+ (BOOL)requiresRoot {
  return YES;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Trigger Santa commands. Debug only.";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl command <command> [options]\n"
          @"  One of:\n"
          @"    kill: Kill processes based on given identifier information.\n"
          @"\n"
          @"  Kill Options:\n"
          @"    --process {pid} {pidversion}: Kill a specific process.\n"
          @"    --cdhash {cdhash}: Kill all processes matching the given cdhash.\n"
          @"    --signingid {signingid}: Formatted as \"TeamID:SigningID\". Kill all\n"
          @"                             processes matching the given TeamID/SigningID.\n"
          @"                             Use TeamID \"platform\" to target platform bianries.\n"
          @"    --teamid {teamid}: Kill all processes matching the given TeamID\n"
          @"\n");
}

- (void)runWithArguments:(NSArray *)arguments {
  if (!arguments.count) {
    [self printErrorUsageAndExit:@"No arguments"];
  }

  enum class Operation {
    kUnknown,
    kKill,
  };

  Operation operation = Operation::kUnknown;
  NSString *arg = arguments[0];

  if ([arg caseInsensitiveCompare:@"kill"] == NSOrderedSame) {
    operation = Operation::kKill;
  } else {
    [self printErrorUsageAndExit:[@"Unknown operation: " stringByAppendingString:arg]];
  }

  switch (operation) {
    case Operation::kKill: {
      [self killWithArguments:[arguments subarrayWithRange:NSMakeRange(1, arguments.count - 1)]];
      break;
    }
    default: [self printErrorUsageAndExit:@"No operation provided"];
  }

  // Individual operation handlers control exiting with success or failure
  exit(EXIT_FAILURE);
}

- (void)killWithArguments:(NSArray *)arguments {
  SNTKillRequest *killRequest = nil;
  NSString *uuid = [[NSUUID UUID] UUIDString];

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--process"] == NSOrderedSame) {
      if (i + 2 >= arguments.count) {
        [self printErrorUsageAndExit:@"--process requires two arguments: <pid> <pidversion>"];
      }

      killRequest =
          [[SNTKillRequestRunningProcess alloc] initWithUUID:uuid
                                                         pid:[arguments[++i] intValue]
                                                  pidversion:[arguments[++i] intValue]
                                             bootSessionUUID:[SNTSystemInfo bootSessionUUID]];
      if (!killRequest) {
        [self printErrorUsageAndExit:@"Invalid parameters to kill by process"];
      }
    } else if ([arg caseInsensitiveCompare:@"--cdhash"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--cdhash requires an argument"];
      }

      killRequest = [[SNTKillRequestCDHash alloc] initWithUUID:uuid cdHash:arguments[i]];
      if (!killRequest) {
        [self printErrorUsageAndExit:@"Invalid parameters to kill by cdhash"];
      }
    } else if ([arg caseInsensitiveCompare:@"--signingid"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--signingid requires an argument"];
      }

      killRequest = [[SNTKillRequestSigningID alloc] initWithUUID:uuid signingID:arguments[i]];
      if (!killRequest) {
        [self printErrorUsageAndExit:@"Invalid parameters to kill by process"];
      }
    } else if ([arg caseInsensitiveCompare:@"--teamid"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--teamid requires an argument"];
      }

      killRequest = [[SNTKillRequestTeamID alloc] initWithUUID:uuid teamID:arguments[i]];
      if (!killRequest) {
        [self printErrorUsageAndExit:@"Invalid parameters to kill by process"];
      }
    } else {
      [self printErrorUsageAndExit:[@"Unknown argument: " stringByAppendingString:arg]];
    }
  }

  if (!killRequest) {
    [self printErrorUsageAndExit:@"No kill request specified"];
  }

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  TEE_LOGI(@"Sending kill request to santad. Waiting for a response...");

  __block SNTKillResponse *resp;
  [[self.daemonConn remoteObjectProxy] killProcesses:killRequest
                                               reply:^(SNTKillResponse *response) {
                                                 resp = response;
                                                 dispatch_semaphore_signal(sema);
                                               }];

  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 90 * NSEC_PER_SEC)) != 0) {
    TEE_LOGE(@"Teimed out waiting for response from santa");
    exit(EXIT_FAILURE);
  }

  if (!resp) {
    TEE_LOGE(@"Received a nil response");
    exit(EXIT_FAILURE);
  } else if (resp.error != SNTKillResponseErrorNone) {
    switch (resp.error) {
      case SNTKillResponseErrorListPids: TEE_LOGE(@"Error: Failed to list pids"); break;
      case SNTKillResponseErrorInvalidRequest: TEE_LOGE(@"Error: Invalid request"); break;
      default: TEE_LOGE(@"Unknown error: %ld", resp.error); break;
    }
    exit(EXIT_FAILURE);
  }

  bool hadError = false;
  TEE_LOGI(@"Killed %ld process(es)", resp.killedProcesses.count);
  for (SNTKilledProcess *proc in resp.killedProcesses) {
    if (proc.error == SNTKilledProcessErrorNone) {
      TEE_LOGI(@"Killed pid: %d, pidversion: %d", proc.pid, proc.pidversion);
    } else {
      hadError = true;
      TEE_LOGE(@"Failed to kill pid: %d (pidversion: %d) Error: %ld", proc.pid, proc.pidversion,
               proc.error);
    }
  }

  exit(hadError ? EXIT_FAILURE : EXIT_SUCCESS);
}

@end

#endif  // DEBUG
