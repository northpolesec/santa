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

#include "src/common/TelemetryEventMap.h"

#include <EndpointSecurity/ESTypes.h>
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <map>
#include <string_view>

#include "src/common/Platform.h"

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
      {"clone", TelemetryEvent::kClone},
      {"copyfile", TelemetryEvent::kCopyfile},
      {"gatekeeperoverride", TelemetryEvent::kGatekeeperOverride},
      {"LaunchItem", TelemetryEvent::kLaunchItem},
      {"TCCModification", TelemetryEvent::kTCCModification},
      {"XProtect", TelemetryEvent::kXProtect},

      // special cases
      {"none", TelemetryEvent::kNone},
      {"everything", TelemetryEvent::kEverything},
  };

  for (const auto &[event_name, want] : eventNameToMask) {
    TelemetryEvent got =
        TelemetryConfigToBitmask(@[ [NSString stringWithUTF8String:event_name.data()] ]);
    XCTAssertEqual(got, want);
  }

  // Test some arbitrary sets of events return expected bitmasks
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"everything" ]), TelemetryEvent::kEverything);
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"none" ]), TelemetryEvent::kNone);
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"execution", @"fork", @"exit" ]),
                 TelemetryEvent::kExecution | TelemetryEvent::kFork | TelemetryEvent::kExit);
  XCTAssertEqual(TelemetryConfigToBitmask(@[ @"bundle", @"close", @"allowList" ]),
                 TelemetryEvent::kBundle | TelemetryEvent::kClose | TelemetryEvent::kAllowlist);

  // When telemetry config is nil, all events should be set
  XCTAssertEqual(TelemetryConfigToBitmask(nil), TelemetryEvent::kEverything);
}

- (void)testESEventToTelemetryEvent {
  std::map<es_event_type_t, TelemetryEvent> esEventToTelemetryEvent = {
      {ES_EVENT_TYPE_NOTIFY_CLONE, TelemetryEvent::kClone},
      {ES_EVENT_TYPE_NOTIFY_CLOSE, TelemetryEvent::kClose},
      {ES_EVENT_TYPE_NOTIFY_COPYFILE, TelemetryEvent::kCopyfile},
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
      {ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, TelemetryEvent::kLaunchItem},
      {ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE, TelemetryEvent::kLaunchItem},
      {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED, TelemetryEvent::kXProtect},
      {ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED, TelemetryEvent::kXProtect},
#if HAVE_MACOS_15
      {ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE, TelemetryEvent::kGatekeeperOverride},
#endif  // HAVE_MACOS_15
#if HAVE_MACOS_15_4
      {ES_EVENT_TYPE_NOTIFY_TCC_MODIFY, TelemetryEvent::kTCCModification},
#endif  // HAVE_MACOS_15_4
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
