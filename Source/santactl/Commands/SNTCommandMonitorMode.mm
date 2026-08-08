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

#import <Foundation/Foundation.h>

#include <cstdint>
#include <optional>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandMonitorMode : SNTCommand <SNTCommandProtocol>
@end

// Resolves a --duration argument to whole minutes; a bare integer means minutes,
// matching the documented flag. SNTAdminModeDurationMinutes is the deliberate
// twin of this function, so changes here usually belong there too.
NSNumber* SNTMonitorModeDurationMinutes(NSString* arg, NSError** error) {
  std::optional<int64_t> seconds = [SNTCommand parseTimeInterval:arg
                                                     defaultUnit:SNTDurationUnitMinutes
                                                           error:error];
  if (!seconds.has_value()) {
    return nil;
  }
  if (*seconds <= 0) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"--duration must be greater than zero"];
    return nil;
  }
  if (*seconds % 60 != 0) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"--duration must be a whole number of minutes (e.g. 30m, 2h, 1d)"];
    return nil;
  }
  return @(*seconds / 60);
}

@implementation SNTCommandMonitorMode

REGISTER_COMMAND_NAME(@"monitormode")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString*)shortHelpText {
  return @"Temporarily switch to Monitor Mode if eligible.";
}

+ (NSString*)longHelpText {
  return (@"Usage: santactl monitormode [options]\n"
          @"  Options:\n"
          @"    --duration {minutes}: An optional number of minutes of temporary Monitor Mode\n"
          @"                          to request. By default, will use configured time allotted\n"
          @"                          by policy.\n"
          @"    --cancel: End temporary Monitor Mode and revert to Lockdown Mode.\n"
          @"\n");
}

+ (NSSet<NSString*>*)aliases {
  return [NSSet setWithArray:@[ @"mm" ]];
}

- (void)runWithArguments:(NSArray*)arguments {
  // A request of 0 minutes resolves to the policy-configured default on the daemon.
  NSNumber* requestedDuration = @0;
  bool shouldCancel = false;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString* arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--duration"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--duration requires an argument"];
      }

      arg = arguments[i];

      NSError* err = nil;
      NSNumber* minutes = SNTMonitorModeDurationMinutes(arg, &err);
      if (!minutes) {
        [self printErrorUsageAndExit:err.localizedDescription];
      }
      requestedDuration = minutes;
    } else if ([arg caseInsensitiveCompare:@"--cancel"] == NSOrderedSame) {
      shouldCancel = true;
    }
  }

  __block BOOL success = NO;

  if (shouldCancel) {
    [[self.daemonConn synchronousRemoteObjectProxy] cancelTemporaryMonitorMode:^(NSError* err) {
      success = (err == nil);
      if (err) {
        TEE_LOGE(@"Unable cancel Monitor Mode: %@", err.localizedDescription);
        return;
      }
    }];
  } else {
    [[self.daemonConn synchronousRemoteObjectProxy]
        requestTemporaryMonitorModeWithDurationMinutes:requestedDuration
                                                 reply:^(uint32_t minutes, NSError* err) {
                                                   success = (err == nil);
                                                   if (err) {
                                                     TEE_LOGE(@"Unable to enter Monitor Mode: %@",
                                                              err.localizedDescription);
                                                     return;
                                                   }

                                                   TEE_LOGI(@"Monitor Mode temporarily authorized "
                                                            @"for %u %@",
                                                            minutes,
                                                            minutes > 1 ? @"minutes" : @"minute");
                                                 }];
  }

  exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}

@end
