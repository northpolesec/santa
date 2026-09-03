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

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRuleTimeWindow.h"

/// What the timed rule kill warning dialog shows, assembled by santad at
/// warning time from the matched running process. Only application and
/// deadline are guaranteed; everything else is best effort.
@interface SNTTimedRuleKillDetails : NSObject <NSSecureCoding>

NS_ASSUME_NONNULL_BEGIN

@property NSString* application;
@property NSDate* deadline;
@property SNTRuleType ruleType;
@property(nullable) NSString* publisher;
@property(nullable) NSString* user;
@property(nullable) NSString* path;
@property(nullable) NSString* signingID;
@property(nullable) NSString* cdhash;
@property(nullable) NSString* parentName;
@property(nullable) NSNumber* ppid;
@property(nullable) SNTRuleTimeWindow* timeWindow;

NS_ASSUME_NONNULL_END

@end
