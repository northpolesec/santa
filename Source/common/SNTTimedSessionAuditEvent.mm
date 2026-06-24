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

#import "Source/common/SNTTimedSessionAuditEvent.h"

#import "Source/common/CoderMacros.h"

@interface SNTTimedSessionAuditEvent ()
@property(readonly) NSUUID* uniqueUuid;
@end

@implementation SNTTimedSessionAuditEvent

- (instancetype)initWithUUID:(NSString*)uuid {
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

- (void)encodeWithCoder:(NSCoder*)coder {
  [super encodeWithCoder:coder];
  ENCODE(coder, uuid);
  ENCODE(coder, uniqueUuid);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super initWithCoder:decoder];
  if (self) {
    DECODE(decoder, uuid, NSString);
    DECODE(decoder, uniqueUuid, NSUUID);
  }
  return self;
}

// Hoisted from the per-feature events (identical in TMM and TAM): never drop a
// timed-session audit event, and key its DB identity on the per-instance UUID.
- (NSString*)uniqueID {
  return [self.uniqueUuid UUIDString];
}

- (BOOL)unactionableEvent {
  return NO;
}

@end
