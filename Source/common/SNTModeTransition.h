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

#include <Foundation/Foundation.h>

typedef NS_ENUM(NSInteger, SNTModeTransitionType) {
  SNTModeTransitionTypeUnspecified = 0,
  SNTModeTransitionTypeRevoke,
  SNTModeTransitionTypeOnDemand,
};

@interface SNTModeTransition : NSObject <NSSecureCoding>

@property(readonly) SNTModeTransitionType type;
@property(readonly) NSNumber *maxMinutes;
@property(readonly) NSNumber *defaultDurationMinutes;

- (instancetype)initRevocation;
- (instancetype)initOnDemandMinutes:(uint32_t)minutes;
- (instancetype)initOnDemandMinutes:(uint32_t)minutes defaultDuration:(uint32_t)defaultDuration;
- (instancetype)init NS_UNAVAILABLE;

- (NSData *)serialize;
+ (instancetype)deserialize:(NSData *)data;

// Given a requested duration, return a valid duration properly clamped by
// the `minutes` and `defaultDurationMinutes`.
- (uint32_t)getDurationMinutes:(NSNumber *)requestedDuration;

@end
