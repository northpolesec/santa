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

#include "Source/common/TelemetryEventMap.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <map>

using santa::ESEventToTelemetryEvent;
using santa::TelemetryConfigToBitmask;
using santa::TelemetryEvent;

@interface TelemetryEventMapTest : XCTestCase
@end

@implementation TelemetryEventMapTest

- (void)testTelemetryConfigToBitmask {
  // Ensure that each named event returns an expected flags value.
  // Some items have mixed case to ensure case insensitive matching.
  std::map<std::string_view, TelemetryEvent> eventNameToMask = {
      {"ExeCUTion", TelemetryEvent::kExecution},
      {"FoRk", TelemetryEvent::kFork},
      {"eXIt", TelemetryEvent::kExit},
      {"close", TelemetryEvent::kClose},
      {"rename", TelemetryEvent::kRename},
      {"unlink", TelemetryEvent::kUnlink},
      {"link", TelemetryEvent::kLink},
      {"ExchangeData", TelemetryEvent::kExchangeData},
      {"disk", TelemetryEvent::kDisk},
      {"bundle", TelemetryEvent::kBundle},
      {"allowList", TelemetryEvent::kAllowlist},
      {"fileAccess", TelemetryEvent::kFileAccess},
      {"codesigninginvalidated", TelemetryEvent::kCodesigningInvalidated},
      {"loginwindowsession", TelemetryEvent::kLoginWindowSession},
      {"loginlogout", TelemetryEvent::kLoginLogout},
      {"screensharing", TelemetryEvent::kScreenSharing},
      {"openssh", TelemetryEvent::kOpenSSH},
      {"authentication", TelemetryEvent::kAuthentication},

      // special cases
      {"none", TelemetryEvent::kNone},
      {"everything", TelemetryEvent::kEverything},
  };

  for (const auto &[event_name, want] : eventNameToMask) {
    TelemetryEvent got =
        TelemetryConfigToBitmask(@[ [NSString stringWithUTF8String:event_name.data()] ], false);
    XCTAssertEqual(got, want);
  }

  // Test some arbitrary sets of events return expected bitmasks
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"everything" ], true), TelemetryEvent::kEverything);
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"none" ], true), TelemetryEvent::kNone);
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"execution", @"fork", @"exit" ], true),
                 TelemetryEvent::kExecution | TelemetryEvent::kFork | TelemetryEvent::kExit);
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"bundle", @"close", @"allowList" ], false),
                 TelemetryEvent::kBundle | TelemetryEvent::kClose | TelemetryEvent::kAllowlist);

  // When telemetry config is nil, returned bitmask is dependent
  // upon enableForkAndExitLogging being true or false
  XCTAssertEqual(TelemetryConfigToBitmask(nil, true), TelemetryEvent::kEverything);
  XCTAssertEqual(TelemetryConfigToBitmask(nil, false),
                 TelemetryEvent::kEverything & ~TelemetryEvent::kFork & ~TelemetryEvent::kExit);
}

- (void)testESEventToTelemetryEvent {
  std::map<es_event_type_t, TelemetryEvent> esEventToTelemetryEvent = {
      {ES_EVENT_TYPE_NOTIFY_CLOSE, TelemetryEvent::kClose},
      {ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED, TelemetryEvent::kCodesigningInvalidated},
      {ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA, TelemetryEvent::kExchangeData},
      {ES_EVENT_TYPE_NOTIFY_EXEC, TelemetryEvent::kExecution},
      {ES_EVENT_TYPE_NOTIFY_EXIT, TelemetryEvent::kExit},
      {ES_EVENT_TYPE_NOTIFY_FORK, TelemetryEvent::kFork},
      {ES_EVENT_TYPE_NOTIFY_LINK, TelemetryEvent::kLink},
      {ES_EVENT_TYPE_NOTIFY_RENAME, TelemetryEvent::kRename},
      {ES_EVENT_TYPE_NOTIFY_UNLINK, TelemetryEvent::kUnlink},
      {ES_EVENT_TYPE_NOTIFY_AUTHENTICATION, TelemetryEvent::kAuthentication},
      {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN, TelemetryEvent::kLoginLogout},
      {ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT, TelemetryEvent::kLoginLogout},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN, TelemetryEvent::kLoginWindowSession},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT, TelemetryEvent::kLoginWindowSession},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK, TelemetryEvent::kLoginWindowSession},
      {ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK, TelemetryEvent::kLoginWindowSession},
      {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH, TelemetryEvent::kScreenSharing},
      {ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH, TelemetryEvent::kScreenSharing},
      {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN, TelemetryEvent::kOpenSSH},
      {ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT, TelemetryEvent::kOpenSSH},
  };

  // Ensure ESEventToTelemetryEvent returns TelemetryEvent::kNone for
  // everything except for the events defined in the above map.
  for (int event = 0; event < ES_EVENT_TYPE_LAST; event++) {
    TelemetryEvent wantTelemetryEvent = TelemetryEvent::kNone;

    auto search = esEventToTelemetryEvent.find((es_event_type_t)event);
    if (search != esEventToTelemetryEvent.end()) {
      wantTelemetryEvent = search->second;
    }

    XCTAssertEqual(ESEventToTelemetryEvent((es_event_type_t)event), wantTelemetryEvent);
  }
}

@end
