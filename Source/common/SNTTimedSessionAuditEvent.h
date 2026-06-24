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

// Shared base for timer-bounded-session audit events (Temporary Monitor Mode,
// Temporary Admin Mode). Not instantiated directly. Carries the session UUID and
// a per-instance unique UUID so repeated events (e.g. refreshes) are never
// de-duplicated. Provides uniqueID/unactionableEvent for all subclasses.
@interface SNTTimedSessionAuditEvent : SNTStoredEvent <NSSecureCoding>
@property(readonly) NSString* uuid;
- (instancetype)initWithUUID:(NSString*)uuid;
- (instancetype)init NS_UNAVAILABLE;
@end
