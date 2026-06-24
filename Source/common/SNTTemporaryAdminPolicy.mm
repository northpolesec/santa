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

#import "Source/common/SNTTemporaryAdminPolicy.h"

#import "Source/common/CoderMacros.h"
#import "Source/common/SNTLogging.h"

@interface SNTTemporaryAdminPolicy ()
@property(readwrite) NSNumber* maxMinutes;
@property(readwrite) NSNumber* defaultDurationMinutes;
@property(readwrite) BOOL requireJustification;
@end

@implementation SNTTemporaryAdminPolicy

- (instancetype)initRevocation {
  self = [super init];
  if (self) _type = SNTTemporaryAdminPolicyTypeRevoke;
  return self;
}

- (instancetype)initOnDemandMinutes:(uint32_t)minutes
                    defaultDuration:(uint32_t)defaultDuration
               requireJustification:(BOOL)requireJustification {
  if (minutes == 0) return nil;
  self = [super init];
  if (self) {
    _type = SNTTemporaryAdminPolicyTypeOnDemand;
    _maxMinutes = [self clampMinutes:minutes];
    _defaultDurationMinutes = [self clampDefaultDuration:defaultDuration];
    _requireJustification = requireJustification;
  }
  return self;
}

- (NSNumber*)clampMinutes:(uint64_t)v {
  if (v < kMinTemporaryAdminMinutes) return @(kMinTemporaryAdminMinutes);
  if (v > kMaxTemporaryAdminMinutes) return @(kMaxTemporaryAdminMinutes);
  return @(v);
}

- (NSNumber*)clampDefaultDuration:(uint64_t)v {
  if (v == 0 || v > [self.maxMinutes unsignedLongLongValue]) return self.maxMinutes;
  return @(v);
}

- (uint32_t)getDurationMinutes:(NSNumber*)requestedDuration {
  uint64_t v = [requestedDuration unsignedLongLongValue];
  if (v == 0) return [self.defaultDurationMinutes unsignedIntValue];
  if (v > [self.maxMinutes unsignedLongLongValue]) return [self.maxMinutes unsignedIntValue];
  return [requestedDuration unsignedIntValue];
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  ENCODE_BOXABLE(coder, type);
  ENCODE(coder, maxMinutes);
  ENCODE(coder, defaultDurationMinutes);
  ENCODE_BOXABLE(coder, requireJustification);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, type, NSNumber, intValue);
    DECODE(decoder, maxMinutes, NSNumber);
    DECODE(decoder, defaultDurationMinutes, NSNumber);
    DECODE_SELECTOR(decoder, requireJustification, NSNumber, boolValue);
    self.maxMinutes = [self clampMinutes:[_maxMinutes unsignedLongLongValue]];
    self.defaultDurationMinutes =
        [self clampDefaultDuration:[_defaultDurationMinutes unsignedLongLongValue]];
  }
  return self;
}

- (NSData*)serialize {
  NSError* error;
  NSData* data = [NSKeyedArchiver archivedDataWithRootObject:self
                                       requiringSecureCoding:YES
                                                       error:&error];
  if (error) {
    LOGE(@"Temporary Admin Policy serialization failed: %@", error.localizedDescription);
    return nil;
  }
  return data;
}

+ (instancetype)deserialize:(NSData*)data {
  if (!data) return nil;
  NSError* error;
  id object = [NSKeyedUnarchiver unarchivedObjectOfClass:[SNTTemporaryAdminPolicy class]
                                                fromData:data
                                                   error:&error];
  if (error) {
    LOGE(@"Temporary Admin Policy deserialization failed: %@", error.localizedDescription);
    return nil;
  }
  return object;
}

@end
