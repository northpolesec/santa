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

// Parse a time interval string into a number of minutes.
// e.g. "10m" -> 10, "2h" -> 120, "3d" -> 3600
- (NSTimeInterval)parseTimeInterval:(NSString *)duration {
  NSScanner *scanner = [NSScanner scannerWithString:duration];
  scanner.charactersToBeSkipped = nil;
  NSString *unit = nil;

  NSInteger intValue = 0;
  NSUInteger locationBeforeScan = scanner.scanLocation;
  if ([scanner scanInteger:&intValue]) {
    NSUInteger locationAfterInteger = scanner.scanLocation;

    // Verify that we actually scanned something and didn't skip whitespace
    if (locationAfterInteger == locationBeforeScan) {
      return 0;  // Invalid: no integer found
    }

    // Check if we're at the end (no unit specified)
    if ([scanner isAtEnd]) {
      return intValue;
    }

    // Verify the next character is immediately adjacent (no whitespace)
    unichar nextChar = [duration characterAtIndex:locationAfterInteger];
    if ([[NSCharacterSet whitespaceAndNewlineCharacterSet] characterIsMember:nextChar]) {
      return 0;  // Invalid: whitespace between integer and unit
    }

    // Scan exactly one character from the unit set
    NSString *scannedUnit = nil;
    NSUInteger locationBeforeUnit = scanner.scanLocation;
    if ([scanner scanCharactersFromSet:[NSCharacterSet characterSetWithCharactersInString:@"smhd"]
                            intoString:&scannedUnit]) {
      NSUInteger locationAfterUnit = scanner.scanLocation;

      // Ensure unit is exactly one character and we're at the end
      if (scannedUnit.length == 1 && locationAfterUnit == locationBeforeUnit + 1 &&
          [scanner isAtEnd]) {
        unit = scannedUnit;
      } else {
        return 0;  // Invalid: unit is not exactly one char or there's more content
      }
    } else {
      return 0;  // Invalid: characters after integer that aren't a valid unit
    }

    if ([unit isEqualToString:@"m"]) {
      return intValue;
    }
    if ([unit isEqualToString:@"h"]) {
      return intValue * 60;
    }
    if ([unit isEqualToString:@"d"]) {
      return intValue * (60 * 24);
    }
  }
  return 0;
}

- (void)runWithArguments:(NSArray *)arguments {
  NSTimeInterval requestedDuration;
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
        [self printErrorUsageAndExit:
                  @"--duration requires a whole number argument or duration string"];
      }

      // Check if the next argument is a single-character unit (suggesting split input like "100 m")
      if (i + 1 < arguments.count) {
        NSString *nextArg = arguments[i + 1];
        if (nextArg.length == 1 && [@"smhd" rangeOfString:nextArg].location != NSNotFound) {
          [self printErrorUsageAndExit:
                    @"--duration requires a whole number argument or duration string"];
        }
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
        requestTemporaryMonitorModeWithDurationMinutes:@(requestedDuration)
                                                 reply:^(uint32_t minutes, NSError *err) {
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
