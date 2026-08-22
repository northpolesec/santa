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

#import <Foundation/Foundation.h>

static constexpr uint32_t kMinTemporaryAdminMinutes = 1;
static constexpr uint32_t kMaxTemporaryAdminMinutes = 1 * 60 * 24 * 30;

typedef NS_ENUM(NSInteger, SNTTemporaryAdminPolicyType) {
  SNTTemporaryAdminPolicyTypeUnspecified = 0,
  SNTTemporaryAdminPolicyTypeRevoke,
  SNTTemporaryAdminPolicyTypeOnDemand,
};

@interface SNTTemporaryAdminPolicy : NSObject <NSSecureCoding>
@property(readonly) SNTTemporaryAdminPolicyType type;
@property(readonly) NSNumber* maxMinutes;
@property(readonly) NSNumber* defaultDurationMinutes;
@property(readonly) BOOL requireJustification;

/// Whether the sync server sent the allowed-admins wrapper. NO means the server
/// does not implement admin-group enforcement, and Santa must fall back to the
/// one-shot capture behavior rather than treating an empty list as "allow none".
@property(readonly) BOOL enforcesAdminGroup;

/// The accounts allowed to hold standing admin, lowercased and trimmed. nil
/// exactly when enforcesAdminGroup is NO; an empty set means "allow none".
@property(readonly) NSSet<NSString*>* allowedAdminUsernames;

- (instancetype)initRevocation;
- (instancetype)initOnDemandMinutes:(uint32_t)minutes
                    defaultDuration:(uint32_t)defaultDuration
               requireJustification:(BOOL)requireJustification;
- (instancetype)initOnDemandMinutes:(uint32_t)minutes
                    defaultDuration:(uint32_t)defaultDuration
               requireJustification:(BOOL)requireJustification
                      allowedAdmins:(NSArray<NSString*>*)allowedAdmins;
- (instancetype)init NS_UNAVAILABLE;

- (NSData*)serialize;
+ (instancetype)deserialize:(NSData*)data;
- (uint32_t)getDurationMinutes:(NSNumber*)requestedDuration;

/// The canonical form used for every allowlist comparison: trimmed, canonically
/// precomposed and lowercased. Callers matching a directory username against
/// `allowedAdminUsernames` MUST put it through this first.
+ (NSString*)normalizedUsername:(NSString*)name;
@end
