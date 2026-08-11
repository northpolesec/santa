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

#include <cctype>
#include <cerrno>
#include <cstdlib>

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
  const char* str = duration.UTF8String;
  if (!str || *str == '\0') {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration: empty string"];
    return std::nullopt;
  }
  // strtoll skips leading whitespace; reject it so " 10s" cannot parse as "10s".
  if (isspace((unsigned char)*str)) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": leading whitespace", duration];
    return std::nullopt;
  }

  errno = 0;
  char* suffix = NULL;
  long long value = strtoll(str, &suffix, 10);
  if (suffix == str) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": expected a number", duration];
    return std::nullopt;
  }
  if (errno == ERANGE) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": value out of range", duration];
    return std::nullopt;
  }

  SNTDurationUnit unit = defaultUnit;
  if (*suffix != '\0') {
    if (suffix[1] != '\0') {
      [SNTError populateError:error
                     withCode:SNTErrorCodeInvalidDuration
                       format:@"invalid duration \"%@\": unexpected trailing content after unit",
                              duration];
      return std::nullopt;
    }
    switch (*suffix) {
      case 's': unit = SNTDurationUnitSeconds; break;
      case 'm': unit = SNTDurationUnitMinutes; break;
      case 'h': unit = SNTDurationUnitHours; break;
      case 'd': unit = SNTDurationUnitDays; break;
      default:
        [SNTError populateError:error
                       withCode:SNTErrorCodeInvalidDuration
                         format:@"invalid duration \"%@\": unknown unit '%c' (expected s, m, h, "
                                @"or d)",
                                duration, *suffix];
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

  // Catches a defaultUnit outside the enum, which would otherwise resolve to a
  // multiplier of zero and return a wrong value rather than an error. The switch
  // above stays exhaustive so -Wswitch still flags a genuinely unhandled case.
  if (multiplier == 0) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": unsupported unit", duration];
    return std::nullopt;
  }

  // The product is checked, not just the parsed integer. int64_t rather than
  // NSTimeInterval keeps it exact: a float carrier reaches callers as an
  // NSNumber whose accessors disagree, so one check can be read back larger.
  int64_t seconds = 0;
  if (__builtin_mul_overflow((int64_t)value, multiplier, &seconds)) {
    [SNTError populateError:error
                   withCode:SNTErrorCodeInvalidDuration
                     format:@"invalid duration \"%@\": value out of range", duration];
    return std::nullopt;
  }

  return seconds;
}

+ (NSNumber*)parseWholeMinutes:(NSString*)duration error:(NSError**)error {
  std::optional<int64_t> seconds = [self parseTimeInterval:duration
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

@end
