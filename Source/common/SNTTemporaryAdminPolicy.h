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

- (instancetype)initRevocation;
- (instancetype)initOnDemandMinutes:(uint32_t)minutes
                    defaultDuration:(uint32_t)defaultDuration
               requireJustification:(BOOL)requireJustification;
- (instancetype)init NS_UNAVAILABLE;

- (NSData*)serialize;
+ (instancetype)deserialize:(NSData*)data;
- (uint32_t)getDurationMinutes:(NSNumber*)requestedDuration;
@end
