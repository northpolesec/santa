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

#import "Source/common/SNTError.h"
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

+ (std::optional<int64_t>)parseTimeInterval:(NSString*)duration
                                defaultUnit:(SNTDurationUnit)defaultUnit
                                      error:(NSError**)error {
  if (duration.length == 0) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration: empty string"];
    return std::nullopt;
  }

  NSScanner* scanner = [NSScanner scannerWithString:duration];
  scanner.charactersToBeSkipped = nil;

  NSInteger intValue = 0;
  if (![scanner scanInteger:&intValue]) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": expected a number", duration];
    return std::nullopt;
  }

  // scanInteger saturates at NSIntegerMax/Min and still returns YES, so a value
  // pinned to either extreme is input the scanner could not read faithfully.
  if (intValue == NSIntegerMax || intValue == NSIntegerMin) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": value out of range", duration];
    return std::nullopt;
  }

  SNTDurationUnit unit = defaultUnit;

  if (![scanner isAtEnd]) {
    NSString* scannedUnit = nil;
    if (![scanner scanCharactersFromSet:[NSCharacterSet characterSetWithCharactersInString:@"smhd"]
                             intoString:&scannedUnit]) {
      [SNTError
          populateError:error
               withCode:SNTErrorCodeInvalidDuration
                 format:@"invalid duration \"%@\": unknown unit '%@' (expected s, m, h, or d)",
                        duration, [duration substringFromIndex:scanner.scanLocation]];
      return std::nullopt;
    }
    if (scannedUnit.length != 1) {
      [SNTError
          populateError:error
               withCode:SNTErrorCodeInvalidDuration
                 format:@"invalid duration \"%@\": unit must be a single character", duration];
      return std::nullopt;
    }
    if (![scanner isAtEnd]) {
      [SNTError populateError:error
                     withCode:SNTErrorCodeInvalidDuration
                       format:@"invalid duration \"%@\": unexpected trailing content after unit",
                              duration];
      return std::nullopt;
    }
    switch ([scannedUnit characterAtIndex:0]) {
      case 's': unit = SNTDurationUnitSeconds; break;
      case 'm': unit = SNTDurationUnitMinutes; break;
      case 'h': unit = SNTDurationUnitHours; break;
      case 'd': unit = SNTDurationUnitDays; break;
      default:
        // Unreachable: the charset scan above only ever admits 's', 'm', 'h', or 'd'.
        [SNTError
            populateError:error
                 withCode:SNTErrorCodeInvalidDuration
                   format:@"invalid duration \"%@\": unknown unit '%@' (expected s, m, h, or d)",
                          duration, scannedUnit];
        return std::nullopt;
    }
  }

  int64_t multiplier = 0;
  switch (unit) {
    case SNTDurationUnitNone:
      [SNTError
          populateError:error
               withCode:SNTErrorCodeInvalidDuration
                 format:@"invalid duration \"%@\": a unit is required (s, m, h, or d)", duration];
      return std::nullopt;
    case SNTDurationUnitSeconds: multiplier = 1; break;
    case SNTDurationUnitMinutes: multiplier = 60; break;
    case SNTDurationUnitHours: multiplier = 60 * 60; break;
    case SNTDurationUnitDays: multiplier = 60 * 60 * 24; break;
  }

  if (multiplier == 0) {  // Unreachable for a valid SNTDurationUnit.
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": unsupported unit", duration];
    return std::nullopt;
  }

  // The product is checked, not just the scanned integer. int64_t rather than
  // NSTimeInterval keeps it exact: a float carrier reaches callers as an
  // NSNumber whose accessors disagree, so one check can be read back larger.
  int64_t seconds = 0;
  if (__builtin_mul_overflow((int64_t)intValue, multiplier, &seconds)) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": value out of range", duration];
    return std::nullopt;
  }

  return seconds;
}

@end
