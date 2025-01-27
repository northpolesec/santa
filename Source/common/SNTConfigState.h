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

#import <Foundation/Foundation.h>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"

@interface SNTConfigState : NSObject <NSSecureCoding>

//
// Properties here mirror the SNTConfigurator at a point in time
//
@property(readonly) SNTClientMode clientMode;
@property(readonly) BOOL enableNotificationSilences;

- (instancetype)initWithConfig:(SNTConfigurator *)config;

@end
