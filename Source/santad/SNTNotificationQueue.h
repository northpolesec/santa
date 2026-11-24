/// Copyright 2016 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#include "Source/common/RingBuffer.h"
#import "Source/common/SNTConfigState.h"

@class SNTStoredExecutionEvent;
@class MOLXPCConnection;

using NotificationReplyBlock = void (^)(BOOL);

/// The notifier owner uid while no GUI connection is registered. It matches no real uid, so
/// anything keyed on the owner (Temporary Admin Mode) fails closed without a GUI.
extern const uid_t kSNTNotifierNoOwner;

@interface SNTNotificationQueue : NSObject

/// The connection to the registered GUI, or nil. Set with -setNotifierConnection:ownerUID:.
@property(readonly) MOLXPCConnection* notifierConnection;

/// The uid of the user whose session registered `notifierConnection`. Every prompt sent over
/// the connection is answered in that session, so an approval obtained through it can only vouch
/// for this user. kSNTNotifierNoOwner while no connection is registered.
@property(readonly) uid_t notifierOwnerUID;

/// Replaces the GUI connection. `ownerUID` is the euid of the XPC peer that registered the
/// listener, resolved by the daemon from the peer's audit token, never taken from the payload.
- (void)setNotifierConnection:(MOLXPCConnection*)notifierConnection ownerUID:(uid_t)ownerUID;

- (instancetype)initWithRingBuffer:
    (std::unique_ptr<santa::RingBuffer<NSMutableDictionary*>>)pendingNotifications
    NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

- (void)addEvent:(SNTStoredExecutionEvent*)event
        withCustomMessage:(NSString*)message
                customURL:(NSString*)url
    eventDetailButtonText:(NSString*)eventDetailButtonText
              configState:(SNTConfigState*)configState
                 andReply:(void (^)(BOOL authenticated))reply;

- (void)authorizeTemporaryMonitorMode:(void (^)(BOOL authenticated))reply;

/// Asks the GUI to authorize a Temporary Admin Mode grant for `uid`. The request is refused
/// (reply NO, no prompt) unless `uid` owns the registered connection. The owner is read together
/// with the connection.
- (void)authorizeTemporaryAdminModeForUID:(uid_t)uid
                   requiringJustification:(BOOL)requireJustification
                                    reply:(void (^)(BOOL authenticated, NSString* reason))reply;

@end
