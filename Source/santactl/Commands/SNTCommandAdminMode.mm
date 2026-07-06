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

#include <unistd.h>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandAdminMode : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandAdminMode

REGISTER_COMMAND_NAME(@"adminmode")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString*)shortHelpText {
  return @"Temporarily gain administrator rights if eligible.";
}

+ (NSString*)longHelpText {
  return (@"Usage: santactl adminmode [options]\n"
          @"  Requests a temporary, time-limited grant of administrator rights for the\n"
          @"  current user. Available only when the machine has been configured to allow\n"
          @"  admin elevation. Authorization (and a justification, if required by policy)\n"
          @"  is requested through the Santa GUI.\n"
          @"  Options:\n"
          @"    --duration {minutes}: An optional number of minutes of temporary admin\n"
          @"                          rights to request. May also be given as a duration\n"
          @"                          string (e.g. 30m, 2h). By default, uses the time\n"
          @"                          allotted by policy.\n"
          @"    --cancel: End the active temporary admin session and drop admin rights.\n"
          @"\n");
}

+ (NSSet<NSString*>*)aliases {
  return [NSSet setWithArray:@[ @"am" ]];
}

- (void)runWithArguments:(NSArray*)arguments {
  // Admin Mode elevates the invoking user, whom the daemon resolves from the XPC
  // peer's identity. Under sudo that identity is root, which is already an
  // administrator, so the daemon would reject the request with a terse
  // "already an administrator" error. Fail early with a clearer pointer instead.
  if (getuid() == 0) {
    TEE_LOGE(@"Run adminmode as your own user, not with sudo. It elevates the invoking user, "
             @"and under sudo the daemon sees only root (already an administrator).");
    exit(EXIT_FAILURE);
  }

  // A request of 0 minutes resolves to the policy-configured default on the daemon.
  NSTimeInterval requestedDuration = 0;
  bool shouldCancel = false;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString* arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--duration"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--duration requires an argument"];
      }

      arg = arguments[i];
      if (arg.length == 0) {
        [self printErrorUsageAndExit:
                  @"--duration requires a whole number argument or duration string"];
      }

      requestedDuration = [self parseTimeInterval:arg];
      if (requestedDuration <= 0) {
        [self printErrorUsageAndExit:
                  @"--duration requires a whole number argument or duration string"];
      }
    } else if ([arg caseInsensitiveCompare:@"--cancel"] == NSOrderedSame) {
      shouldCancel = true;
    }
  }

  // Default to failure: if the XPC transport dies before the reply block runs
  // (the request can block for up to ~90s on the GUI authorization prompt), the
  // block never executes and we must not exit success on an uninitialized value.
  __block BOOL success = NO;

  if (shouldCancel) {
    [[self.daemonConn synchronousRemoteObjectProxy] cancelTemporaryAdminMode:^(NSError* err) {
      success = (err == nil);
      if (err) {
        TEE_LOGE(@"Unable to cancel Admin Mode: %@", err.localizedDescription);
        return;
      }

      TEE_LOGI(@"Temporary Admin Mode cancelled");
    }];
  } else {
    TEE_LOGI(@"Requesting temporary Admin Mode; respond to the authorization prompt if shown...");
    [[self.daemonConn synchronousRemoteObjectProxy]
        requestTemporaryAdminModeWithDurationMinutes:@(requestedDuration)
                                               reply:^(uint32_t minutes, NSError* err) {
                                                 success = (err == nil);
                                                 if (err) {
                                                   TEE_LOGE(@"Unable to enter Admin Mode: %@",
                                                            err.localizedDescription);
                                                   return;
                                                 }

                                                 TEE_LOGI(@"Admin Mode temporarily authorized "
                                                          @"for %u %@",
                                                          minutes,
                                                          minutes > 1 ? @"minutes" : @"minute");
                                               }];
  }

  exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}

@end
