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

/// One rule time window, in one of two forms. The recurring form carries the
/// strings exactly as the rule wrote them; the absolute form carries resolved
/// instants. Exactly one form is populated.
@interface SNTRuleTimeWindow : NSObject <NSSecureCoding>

NS_ASSUME_NONNULL_BEGIN

@property(nullable) NSArray<NSNumber*>* days;  // 0=Sunday through 6=Saturday
@property(nullable) NSString* startOfDay;      // "HH:MM"
@property(nullable) NSString* endOfDay;        // "HH:MM"
// Named zoneName, not zone: -zone is an NSObject protocol requirement, and a
// member of that name on an NSObject subclass is unreachable from Swift.
@property(nullable) NSString* zoneName;  // "local", IANA name, or [+-]HH:MM
@property(nullable) NSDate* startDate;   // absolute form
@property(nullable) NSDate* endDate;     // absolute form
@property BOOL open;                     // whether the asked instant was inside

- (NSString*)displayStringWithLocale:(NSLocale*)locale;
- (NSString*)displayString;  // displayStringWithLocale: with the current locale

NS_ASSUME_NONNULL_END

@end
