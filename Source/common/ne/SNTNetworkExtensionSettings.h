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

/// Action applied to network flows that match no NetworkFlowRule.
typedef NS_ENUM(NSInteger, SNTNetworkFlowDefaultAction) {
  SNTNetworkFlowDefaultActionUnspecified = 0,  // treated as Allow
  SNTNetworkFlowDefaultActionAllow = 1,
  SNTNetworkFlowDefaultActionDeny = 2,
};

/// Settings passed from the daemon (santa) to the network extension (santanetd) over XPC.
///
/// This class conforms to NSSecureCoding, allowing it to be passed directly as a typed
/// argument in XPC protocol methods. NSKeyedArchiver's keyed format provides inherent
/// forward/backward compatibility: old receivers ignore unknown keys, new receivers get
/// nil/0/NO for missing keys.
@interface SNTNetworkExtensionSettings : NSObject <NSSecureCoding>

@property(readonly) BOOL enable;
@property(readonly) SNTNetworkFlowDefaultAction flowDefaultAction;

- (instancetype)initWithEnable:(BOOL)enable
             flowDefaultAction:(SNTNetworkFlowDefaultAction)flowDefaultAction;

@end
