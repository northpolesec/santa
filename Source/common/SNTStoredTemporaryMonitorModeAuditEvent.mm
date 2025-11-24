/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/common/SNTStoredTemporaryMonitorModeAuditEvent.h"
#include <Foundation/Foundation.h>

#import "Source/common/CoderMacros.h"

@interface SNTStoredTemporaryMonitorModeAuditEvent ()
// These events should never get dropped due to a conflict. E.g., if a session is refreshed
// multiple times, each refresh should be reported. This property will be used to compute a
// random UUID on each instatiation to prevent caching.
@property(readonly) NSUUID *uniqueUuid;
@end
;

@implementation SNTStoredTemporaryMonitorModeEnterAuditEvent

- (instancetype)initWithUUID:(NSString *)uuid
                     seconds:(uint32_t)seconds
                      reason:(SNTTemporaryMonitorModeEnterReason)reason {
  self = [super initWithUUID:uuid];
  if (self) {
    _seconds = seconds;
    _reason = reason;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, reason);
  ENCODE_BOXABLE(coder, seconds);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, seconds, NSNumber, unsignedIntValue);
  }
  return self;
}

- (NSString *)uniqueID {
  return [self.uniqueUuid UUIDString];
}

- (BOOL)unactionableEvent {
  // These events should always be stored
  return NO;
}

@end

@implementation SNTStoredTemporaryMonitorModeLeaveAuditEvent

- (instancetype)initWithUUID:(NSString *)uuid reason:(SNTTemporaryMonitorModeLeaveReason)reason {
  self = [super initWithUUID:uuid];
  if (self) {
    _reason = reason;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, reason);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
  }
  return self;
}

- (NSString *)uniqueID {
  return [self.uniqueUuid UUIDString];
}

- (BOOL)unactionableEvent {
  // These events should always be stored
  return NO;
}

@end

// NB: Intentionally not implementing SNTStoredEvent base class methods:
//   - (NSString *)uniqueID
//   - (BOOL)unactionableEvent
// This class should not be directly instantiated. The default base class implementation
// for these methods will throw, making it so attempting to instantiate this is not very useful.
@implementation SNTStoredTemporaryMonitorModeAuditEvent

- (instancetype)initWithUUID:(NSString *)uuid {
  self = [super init];
  if (self) {
    _uuid = uuid;
    _uniqueUuid = [NSUUID UUID];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, uuid);
  ENCODE(coder, uniqueUuid);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, uuid, NSString);
    DECODE(decoder, uniqueUuid, NSUUID);
  }
  return self;
}

@end
