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

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandMonitorMode : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandMonitorMode

REGISTER_COMMAND_NAME(@"monitormode")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return YES;
}

+ (NSString *)shortHelpText {
  return @"Temporarily switch to Monitor Mode if eligible.";
}

+ (NSString *)longHelpText {
  return (@"Usage: santactl monitormode [options]\n"
          @"  Options:\n"
          @"    --duration {minutes}: An optional number of minutes of temporary Monitor Mode\n"
          @"                          to request. By default, will use configured time allotted\n"
          @"                          by policy.\n"
          @"    --cancel: End temporary Monitor Mode and revert to Lockdown Mode.\n"
          @"\n");
}

+ (NSSet<NSString *> *)aliases {
  return [NSSet setWithArray:@[ @"mm" ]];
}

- (void)runWithArguments:(NSArray *)arguments {
  NSNumber *requestedDuration;
  bool shouldCancel = false;

  // Parse arguments
  for (NSUInteger i = 0; i < arguments.count; ++i) {
    NSString *arg = arguments[i];

    if ([arg caseInsensitiveCompare:@"--duration"] == NSOrderedSame) {
      if (++i > arguments.count - 1) {
        [self printErrorUsageAndExit:@"--duration requires an argument"];
      }

      arg = arguments[i];
      if (arg.length == 0) {
        [self printErrorUsageAndExit:@"--duration requires a whole number argument"];
      }

      NSCharacterSet *nonDigitCharacterSet =
          [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
      if ([arg rangeOfCharacterFromSet:nonDigitCharacterSet].location != NSNotFound) {
        [self printErrorUsageAndExit:@"--duration requires a whole number argument"];
      }

      NSInteger val = [arg integerValue];
      if (val <= 0) {
        [self printErrorUsageAndExit:@"--duration must be greater than 0"];
      }

      requestedDuration = @(val);
    } else if ([arg caseInsensitiveCompare:@"--cancel"] == NSOrderedSame) {
      shouldCancel = true;
    }
  }

  __block BOOL success;

  if (shouldCancel) {
    [[self.daemonConn synchronousRemoteObjectProxy] cancelTemporaryMonitorMode:^(NSError *err) {
      success = (err == nil);
      if (err) {
        TEE_LOGE(@"Unable cancel Monitor Mode: %@", err.localizedDescription);
        return;
      }
    }];
  } else {
    [[self.daemonConn synchronousRemoteObjectProxy]
        requestTemporaryMonitorModeWithDuration:requestedDuration
                                          reply:^(uint32_t minutes, NSError *err) {
                                            success = (err == nil);
                                            if (err) {
                                              TEE_LOGE(@"Unable to enter Monitor Mode: %@",
                                                       err.localizedDescription);
                                              return;
                                            }

                                            TEE_LOGI(
                                                @"Monitor Mode temporarily authorized for %u %@",
                                                minutes, minutes > 1 ? @"minutes" : @"minute");
                                          }];
  }

  exit(success ? EXIT_SUCCESS : EXIT_FAILURE);
}

@end
