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

#import <Cocoa/Cocoa.h>

#import "Source/gui/SNTMessageWindowController.h"

NS_ASSUME_NONNULL_BEGIN

@class SNTConfigBundle;
@class SNTStoredNetworkFlowEvent;

/// Informational dialog shown when a network flow is loudly denied.
@interface SNTNetworkFlowMessageWindowController : SNTMessageWindowController <NSWindowDelegate>

- (instancetype)initWithEvent:(SNTStoredNetworkFlowEvent*)event
                 configBundle:(SNTConfigBundle*)configBundle;

@property(readonly) SNTStoredNetworkFlowEvent* event;

@end

NS_ASSUME_NONNULL_END
