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

#import "Source/common/CoderMacros.h"

@implementation SNTStoredTemporaryMonitorModeEnterAuditEvent

- (instancetype)initWithSeconds:(uint32_t)seconds
                         reason:(SNTTemporaryMonitorModeEnterReason)reason {
  self = [super init];
  if (self) {
    _reason = reason;
    _seconds = seconds;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, reason);
  ENCODE_BOXABLE(coder, seconds);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, seconds, NSNumber, unsignedIntValue);
  }
  return self;
}

@end

@implementation SNTStoredTemporaryMonitorModeLeaveAuditEvent

- (instancetype)initWithReason:(SNTTemporaryMonitorModeLeaveReason)reason {
  self = [super init];
  if (self) {
    _reason = reason;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  ENCODE_BOXABLE(coder, reason);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
  }
  return self;
}

@end

@implementation SNTStoredTemporaryMonitorModeAuditEvent

- (instancetype)init {
  self = [super init];
  if (self) {
    _uuid = [[NSUUID UUID] UUIDString];
  }
  return self;
}

- (instancetype)initWithUUID:(NSString *)uuid {
  self = [super init];
  if (self) {
    _uuid = uuid;
  }
  return self;
}

- (instancetype)initEnterWithSeconds:(uint32_t)seconds
                              reason:(SNTTemporaryMonitorModeEnterReason)reason {
  self = [self init];
  if (self) {
    _type = SNTStoredTemporaryMonitorModeAuditEventTypeEnter;
    _auditEvent = [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc] initWithSeconds:seconds
                                                                                 reason:reason];
  }
  return self;
}

- (instancetype)initEnterWithUUID:(NSString *)uuid
                          seconds:(uint32_t)seconds
                           reason:(SNTTemporaryMonitorModeEnterReason)reason {
  self = [self initWithUUID:uuid];
  if (self) {
    _type = SNTStoredTemporaryMonitorModeAuditEventTypeEnter;
    _auditEvent = [[SNTStoredTemporaryMonitorModeEnterAuditEvent alloc] initWithSeconds:seconds
                                                                                 reason:reason];
  }
  return self;
}

- (instancetype)initLeaveWithUUID:(NSString *)uuid
                           reason:(SNTTemporaryMonitorModeLeaveReason)reason {
  self = [self initWithUUID:uuid];
  if (self) {
    _type = SNTStoredTemporaryMonitorModeAuditEventTypeLeave;
    _auditEvent = [[SNTStoredTemporaryMonitorModeLeaveAuditEvent alloc] initWithReason:reason];
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder *)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, uuid);
  ENCODE_BOXABLE(coder, type);
  ENCODE(coder, auditEvent);
}

- (instancetype)initWithCoder:(NSCoder *)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, uuid, NSString);
    DECODE_SELECTOR(decoder, type, NSNumber, integerValue);

    NSSet *auditEventClasses =
        [NSSet setWithObjects:[SNTStoredTemporaryMonitorModeEnterAuditEvent class],
                              [SNTStoredTemporaryMonitorModeLeaveAuditEvent class], nil];
    DECODE_SET(decoder, auditEvent, auditEventClasses);
  }
  return self;
}

- (NSString *)uniqueID {
  return [NSString stringWithFormat:@"%@|%ld", self.uuid, self.type];
}

- (BOOL)unactionableEvent {
  // These events should always be stored
  return NO;
}

@end
