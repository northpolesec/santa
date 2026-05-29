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

#import "Source/common/SNTNetworkFlowRule.h"
#import "Source/common/ne/SNTNetworkExtensionSettings.h"

/// The full network-extension config santad hands to santanetd: settings plus the network-flow
/// ruleset. Delivered both in the registration reply (seeding a freshly-started santanetd) and as
/// the runtime update payload.
@interface SNTNetworkExtensionConfig : NSObject <NSSecureCoding>

@property(readonly) SNTNetworkExtensionSettings* settings;

/// At registration this is the full ruleset. On a runtime update, nil means "rules unchanged —
/// keep the existing index" (vs. an empty array, which means "no rules").
@property(readonly, copy) NSArray<SNTNetworkFlowRule*>* networkFlowRules;

- (instancetype)initWithSettings:(SNTNetworkExtensionSettings*)settings
                networkFlowRules:(NSArray<SNTNetworkFlowRule*>*)networkFlowRules;

@end
