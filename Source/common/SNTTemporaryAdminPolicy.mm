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
+ (NSSet<NSString*>*)normalizeAllowedAdmins:(NSArray<NSString*>*)raw;
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
  return [self initOnDemandMinutes:minutes
                   defaultDuration:defaultDuration
              requireJustification:requireJustification
                     allowedAdmins:nil];
}

- (instancetype)initOnDemandMinutes:(uint32_t)minutes
                    defaultDuration:(uint32_t)defaultDuration
               requireJustification:(BOOL)requireJustification
                      allowedAdmins:(NSArray<NSString*>*)allowedAdmins {
  if (minutes == 0) return nil;
  self = [super init];
  if (self) {
    _type = SNTTemporaryAdminPolicyTypeOnDemand;
    _maxMinutes = [self clampMinutes:minutes];
    _defaultDurationMinutes = [self clampDefaultDuration:defaultDuration];
    _requireJustification = requireJustification;
    // nil vs empty is the whole point: nil means the server never sent the
    // wrapper, empty means it sent one naming nobody.
    _enforcesAdminGroup = (allowedAdmins != nil);
    _allowedAdminUsernames =
        allowedAdmins ? [SNTTemporaryAdminPolicy normalizeAllowedAdmins:allowedAdmins] : nil;
  }
  return self;
}

// The single canonical form for allowlist comparison. BOTH sides go through
// this: the entries the server sent, and the usernames read back from the
// directory. Workshop and opendirectoryd can hold the same visible name in
// different Unicode compositions, and comparing raw strings would miss — which
// demotes the account with nothing logged and nothing wrong-looking in the UI.
+ (NSString*)normalizedUsername:(NSString*)name {
  return [name stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
      .precomposedStringWithCanonicalMapping.lowercaseString;
}

+ (NSSet<NSString*>*)normalizeAllowedAdmins:(NSArray<NSString*>*)raw {
  NSMutableSet<NSString*>* out = [NSMutableSet set];
  for (id entry in raw) {
    if (![entry isKindOfClass:[NSString class]]) continue;
    NSString* normalized = [SNTTemporaryAdminPolicy normalizedUsername:entry];
    if (normalized.length == 0) continue;
    // "scheme:value" is reserved for a future uid: form. A macOS posix name can
    // never contain ':' (it is the passwd field separator), so nothing valid is
    // lost, and an entry only a newer Santa understands is ignored here rather
    // than matched as a literal username. Workshop rejects these at save time;
    // this is the belt for a third-party sync server.
    if ([normalized containsString:@":"]) {
      LOGW(@"Temporary Admin Mode: ignoring unsupported allowlist entry %@", normalized);
      continue;
    }
    [out addObject:normalized];
  }
  return out;
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
  ENCODE_BOXABLE(coder, enforcesAdminGroup);
  ENCODE(coder, allowedAdminUsernames);
}

- (instancetype)initWithCoder:(NSCoder*)decoder {
  self = [super init];
  if (self) {
    DECODE_SELECTOR(decoder, type, NSNumber, intValue);
    DECODE(decoder, maxMinutes, NSNumber);
    DECODE(decoder, defaultDurationMinutes, NSNumber);
    DECODE_SELECTOR(decoder, requireJustification, NSNumber, boolValue);
    DECODE_SELECTOR(decoder, enforcesAdminGroup, NSNumber, boolValue);
    DECODE_SET(decoder, allowedAdminUsernames,
               ([NSSet setWithObjects:[NSSet class], [NSString class], nil]));
    // Keep the nil/empty distinction exact across a round trip, including for
    // archives written by an older build that had neither key.
    if (!_enforcesAdminGroup) {
      _allowedAdminUsernames = nil;
    } else if (_allowedAdminUsernames == nil) {
      _allowedAdminUsernames = [NSSet set];
    }
    // Revoke policies carry no duration fields; preserve their nil values so the
    // decoded object stays symmetric with -initRevocation. Only on-demand policies
    // have minutes to clamp.
    if (_type != SNTTemporaryAdminPolicyTypeRevoke) {
      self.maxMinutes = [self clampMinutes:[_maxMinutes unsignedLongLongValue]];
      self.defaultDurationMinutes =
          [self clampDefaultDuration:[_defaultDurationMinutes unsignedLongLongValue]];
    }
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
