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

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>

// Collaborator the Recorder calls for login-window LOCK / LOGOUT events. The protocol is kept in
// its own header so the Recorder stays unaware of Temporary Admin Mode internals (mirrors the
// SNTCompilerController collaborator pattern).
@protocol SNTLoginWindowSessionHandler <NSObject>
// Called for ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK / _LOGOUT only. `username` is the login-window
// session user. Must return quickly (runs on the ES handler thread).
- (void)handleLoginWindowSessionEvent:(es_event_type_t)eventType username:(NSString*)username;
@end
