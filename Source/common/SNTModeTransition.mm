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

#import "Source/common/SNTModeTransition.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTLogging.h"

// Semi-arbitrary min/max values for max minutes.
// Max minutes must be less than 30 days (in minutes).
static constexpr uint32_t kMinMonitorModeMinutes = 1;
static constexpr uint32_t kMaxMonitorModeMinutes = 1 * 60 * 24 * 30;

@interface SNTModeTransition ()
@property(readwrite) NSNumber *maxMinutes;
@property(readwrite) NSNumber *defaultDurationMinutes;
@end

@implementation SNTModeTransition

- (instancetype)initRevocation {
  self = [super init];
  if (self) {
    _type = SNTModeTransitionTypeRevoke;
  }
  return self;
}

- (instancetype)initOnDemandMinutes:(uint32_t)minutes {
  return [self initOnDemandMinutes:minutes defaultDuration:0];
}

- (instancetype)initOnDemandMinutes:(uint32_t)minutes defaultDuration:(uint32_t)defaultDuration {
  if (minutes == 0) {
    return nil;
  }

  self = [super init];
  if (self) {
    _type = SNTModeTransitionTypeOnDemand;
    _maxMinutes = [self clampMinutes:minutes];
    _defaultDurationMinutes = [self clampDefaultDuration:defaultDuration];
  }
  return self;
}

- (NSNumber *)clampMinutes:(uint64_t)minutesVal {
  if (minutesVal < kMinMonitorModeMinutes) {
    return @(kMinMonitorModeMinutes);
  } else if (minutesVal > kMaxMonitorModeMinutes) {
    return @(kMaxMonitorModeMinutes);
  } else {
    return @(minutesVal);
  }
}

- (NSNumber *)clampDefaultDuration:(uint64_t)durationVal {
  if (durationVal == 0 || durationVal > [self.maxMinutes unsignedLongLongValue]) {
    return self.maxMinutes;
  } else {
    return @(durationVal);
  }
}

- (uint32_t)getDurationMinutes:(NSNumber *)requestedDuration {
  uint64_t durationVal = [requestedDuration unsignedLongLongValue];
  if (durationVal == 0) {
    return [self.defaultDurationMinutes unsignedIntValue];
  } else if (durationVal > [self.maxMinutes unsignedLongLongValue]) {
    return [self.maxMinutes unsignedIntValue];
  } else {
    return [requestedDuration unsignedIntValue];
  }
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, type);
  ENCODE(coder, maxMinutes);
  ENCODE(coder, defaultDurationMinutes);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [self init];
  if (self) {
    DECODE_SELECTOR(decoder, type, NSNumber, intValue);
    DECODE(decoder, maxMinutes, NSNumber);
    DECODE(decoder, defaultDurationMinutes, NSNumber);

    self.maxMinutes = [self clampMinutes:[_maxMinutes unsignedLongLongValue]];
    self.defaultDurationMinutes =
        [self clampDefaultDuration:[_defaultDurationMinutes unsignedLongLongValue]];
  }
  return self;
}

- (NSData *)serialize {
  NSError *error;
  NSData *data = [NSKeyedArchiver archivedDataWithRootObject:self
                                       requiringSecureCoding:YES
                                                       error:&error];
  if (error) {
    LOGE(@"Mode Transition serialization failed: %@", error.localizedDescription);
    return nil;
  }

  return data;
}

+ (instancetype)deserialize:(NSData *)data {
  if (!data) {
    return nil;
  }

  NSError *error;
  id object = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTModeTransition class]
                                                fromData:data
                                                   error:&error];
  if (error) {
    LOGE(@"Mode Transition deserialization failed: %@", error.localizedDescription);
    return nil;
  }

  return object;
}

@end
