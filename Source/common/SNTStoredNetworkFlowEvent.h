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

#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredProcess.h"

/// Outcome of a network flow policy decision. Values are aligned to the v2 proto
/// NetworkFlowDecision so santasyncservice maps by a plain cast. The 4-way engine
/// decision collapses here: both deny variants map to Block (the silent bit, set
/// separately, distinguishes them for dialog routing).
typedef NS_ENUM(int32_t, SNTNetworkFlowDecision) {
  SNTNetworkFlowDecisionUnspecified = 0,
  SNTNetworkFlowDecisionAllow = 1,
  SNTNetworkFlowDecisionBlock = 2,
  SNTNetworkFlowDecisionAudit = 3,
};

/// Flow direction. Values aligned to the v2 proto NetworkFlowDirection.
typedef NS_ENUM(int32_t, SNTNetworkFlowDirection) {
  SNTNetworkFlowDirectionUnspecified = 0,
  SNTNetworkFlowDirectionAny = 1,
  SNTNetworkFlowDirectionOutgoing = 2,
  SNTNetworkFlowDirectionIncoming = 3,
};

/// Socket address family. Values aligned to the v2 proto NetworkFlowSocketFamily
/// (which match Darwin AF_INET / AF_INET6).
typedef NS_ENUM(int32_t, SNTNetworkFlowSocketFamily) {
  SNTNetworkFlowSocketFamilyUnspecified = 0,
  SNTNetworkFlowSocketFamilyINET = 2,
  SNTNetworkFlowSocketFamilyINET6 = 30,
};

/// A per-flow policy decision event, mirroring the v2 proto NetworkFlowEvent.
@interface SNTStoredNetworkFlowEvent : SNTStoredEvent <NSSecureCoding>

// Flow.
@property(nullable) NSString* remoteAddress;
@property uint16_t remotePort;
@property(nullable) NSString* localAddress;
@property uint16_t localPort;
@property int protocol;  // IANA protocol number (6=TCP, 17=UDP, ...)
@property SNTNetworkFlowSocketFamily socketFamily;
@property SNTNetworkFlowDirection direction;
@property(nullable) NSString* hostname;
@property(nullable) NSDate* flowTime;

// Outcome.
@property SNTNetworkFlowDecision decision;
@property int64_t ruleId;
@property(nullable) NSArray<NSNumber*>* competingRuleIds;  // capped at 10, precedence-ordered
@property uint32_t totalCompetingRuleCount;

// Process (originating; .parent = lightweight parent).
@property(nullable) SNTStoredProcess* process;

// santad-local, NOT mapped to the proto: drives the loud-deny dialog only.
@property BOOL silent;

@end
