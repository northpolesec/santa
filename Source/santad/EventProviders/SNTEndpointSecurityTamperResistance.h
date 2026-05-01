/// Copyright 2022 Google Inc. All rights reserved.
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

#include <memory>

#include "Source/common/es/ESMetricsObserver.h"
#include "Source/common/es/EndpointSecurityAPI.h"
#import "Source/common/es/SNTEndpointSecurityClient.h"
#import "Source/common/es/SNTEndpointSecurityEventHandler.h"
#include "Source/santad/Logs/EndpointSecurity/Logger.h"

NS_ASSUME_NONNULL_BEGIN

/// ES Client focused on mitigating accidental or malicious tampering of Santa and its components.
@interface SNTEndpointSecurityTamperResistance
    : SNTEndpointSecurityClient <SNTEndpointSecurityEventHandler>

/// Set the signing IDs to protect from pid_suspend/pid_resume.
/// Accepts an NSArray of NSStrings but stores internally as a hash set for O(1) lookup.
- (void)setAntiSuspendSigningIDs:(nullable NSArray<NSString*>*)antiSuspendSigningIDs;

/// When YES, signals delegated by launchd on behalf of any Apple platform
/// binary may target santad, in addition to the hardcoded allowlist.
/// Synchronized for safe concurrent access; live-updated from KVO.
@property(atomic) BOOL allowDelegatedSignals;

- (instancetype)initWithESAPI:(std::shared_ptr<santa::EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::ESMetricsObserver>)metrics
                       logger:(std::shared_ptr<santa::Logger>)logger
        antiSuspendSigningIDs:(nullable NSArray<NSString*>*)antiSuspendSigningIDs
        allowDelegatedSignals:(BOOL)allowDelegatedSignals;

@end

NS_ASSUME_NONNULL_END
