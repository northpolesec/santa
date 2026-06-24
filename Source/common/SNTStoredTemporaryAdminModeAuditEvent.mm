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

#import "Source/common/SNTStoredTemporaryAdminModeAuditEvent.h"

#import "Source/common/CoderMacros.h"

@implementation SNTStoredTemporaryAdminModeEnterAuditEvent

- (instancetype)initWithUUID:(NSString*)uuid
                    username:(NSString*)username
                     seconds:(uint32_t)seconds
                      reason:(SNTTemporaryAdminModeEnterReason)reason
           userJustification:(NSString*)userJustification {
  self = [super initWithUUID:uuid username:username];
  if (self) {
    _seconds = seconds;
    _reason = reason;
    _userJustification = userJustification;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, reason);
  ENCODE_BOXABLE(coder, seconds);
  ENCODE(coder, userJustification);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
    DECODE_SELECTOR(decoder, seconds, NSNumber, unsignedIntValue);
    DECODE(decoder, userJustification, NSString);
  }
  return self;
}

@end

@implementation SNTStoredTemporaryAdminModeLeaveAuditEvent

- (instancetype)initWithUUID:(NSString*)uuid
                    username:(NSString*)username
                      reason:(SNTTemporaryAdminModeLeaveReason)reason {
  self = [super initWithUUID:uuid username:username];
  if (self) _reason = reason;
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, reason);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
  return self;
}

@end

@implementation SNTStoredTemporaryAdminModeDeniedAuditEvent

- (instancetype)initWithUUID:(NSString*)uuid
                    username:(NSString*)username
                      reason:(SNTTemporaryAdminModeDeniedReason)reason {
  self = [super initWithUUID:uuid username:username];
  if (self) {
    _reason = reason;
  }
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE_BOXABLE(coder, reason);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE_SELECTOR(decoder, reason, NSNumber, integerValue);
  }
  return self;
}

@end

// NB: Intentionally not implementing SNTStoredEvent base class methods:
//   - (NSString *)uniqueID
//   - (BOOL)unactionableEvent
// This class should not be directly instantiated. These methods are provided by
// SNTTimedSessionAuditEvent and are inherited by the concrete subclasses above.
@implementation SNTStoredTemporaryAdminModeAuditEvent

- (instancetype)initWithUUID:(NSString*)uuid username:(NSString*)username {
  self = [super initWithUUID:uuid];
  if (self) _username = username;
  return self;
}

+ (BOOL)supportsSecureCoding {
  return YES;
}

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, username);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) DECODE(decoder, username, NSString);
  return self;
}

@end
