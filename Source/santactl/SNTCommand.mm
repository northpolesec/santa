/// Copyright 2017 Google Inc. All rights reserved.
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

#import "Source/santactl/SNTCommand.h"

#import "Source/common/SNTLogging.h"

@implementation SNTCommand

+ (void)runWithArguments:(NSArray*)arguments daemonConnection:(MOLXPCConnection*)daemonConn {
  id cmd = [[self alloc] initWithDaemonConnection:daemonConn];
  [cmd runWithArguments:arguments];
}

- (instancetype)initWithDaemonConnection:(MOLXPCConnection*)daemonConn {
  self = [super init];
  if (self) {
    _daemonConn = daemonConn;
  }
  return self;
}

- (void)runWithArguments:(NSArray*)arguments {
  // This method must be overridden.
  [self doesNotRecognizeSelector:_cmd];
}

- (void)printErrorUsageAndExit:(NSString*)error {
  // Only send the error string to both the system logger and stderr, not the usage string
  TEE_LOGE(@"%@\n\n", error);
  fprintf(stderr, "%s\n", [[[self class] longHelpText] UTF8String]);
  exit(1);
}

// Parse a time interval string into a number of minutes.
// e.g. "10m" -> 10, "2h" -> 120, "3d" -> 4320
- (NSTimeInterval)parseTimeInterval:(NSString*)duration {
  NSScanner* scanner = [NSScanner scannerWithString:duration];
  scanner.charactersToBeSkipped = nil;
  NSString* unit = nil;

  NSInteger intValue = 0;
  if ([scanner scanInteger:&intValue]) {
    // Check if we're at the end (no unit specified)
    if ([scanner isAtEnd]) {
      return intValue;
    }

    // Scan exactly one character from the unit set
    NSString* scannedUnit = nil;
    if ([scanner scanCharactersFromSet:[NSCharacterSet characterSetWithCharactersInString:@"smhd"]
                            intoString:&scannedUnit]) {
      // Ensure unit is exactly one character and we're at the end
      if (scannedUnit.length == 1 && [scanner isAtEnd]) {
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

@end
