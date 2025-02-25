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

#include <string_view>

#include "Source/common/Platform.h"
#include "Source/common/String.h"
#include "absl/container/flat_hash_map.h"

namespace santa {

static inline TelemetryEvent EventNameToMask(std::string_view event) {
  static absl::flat_hash_map<std::string_view, TelemetryEvent> event_name_to_mask = {
      {"execution", TelemetryEvent::kExecution},
      {"fork", TelemetryEvent::kFork},
      {"exit", TelemetryEvent::kExit},
      {"close", TelemetryEvent::kClose},
      {"rename", TelemetryEvent::kRename},
      {"unlink", TelemetryEvent::kUnlink},
      {"link", TelemetryEvent::kLink},
      {"exchangedata", TelemetryEvent::kExchangeData},
      {"disk", TelemetryEvent::kDisk},
      {"bundle", TelemetryEvent::kBundle},
      {"allowlist", TelemetryEvent::kAllowlist},
      {"fileaccess", TelemetryEvent::kFileAccess},
      {"codesigninginvalidated", TelemetryEvent::kCodesigningInvalidated},
      {"loginwindowsession", TelemetryEvent::kLoginWindowSession},
      {"loginlogout", TelemetryEvent::kLoginLogout},
      {"screensharing", TelemetryEvent::kScreenSharing},
      {"openssh", TelemetryEvent::kOpenSSH},
      {"authentication", TelemetryEvent::kAuthentication},
      {"clone", TelemetryEvent::kClone},
      {"copyfile", TelemetryEvent::kCopyfile},
      {"gatekeeperoverride", TelemetryEvent::kGatekeeperOverride},

      // special cases
      {"none", TelemetryEvent::kNone},
      {"everything", TelemetryEvent::kEverything},
  };

  auto search = event_name_to_mask.find(event);
  if (search != event_name_to_mask.end()) {
    return search->second;
  } else {
    return TelemetryEvent::kNone;
  }
}

TelemetryEvent TelemetryConfigToBitmask(NSArray<NSString *> *telemetry,
                                        BOOL enableForkAndExitLogging) {
  TelemetryEvent mask = TelemetryEvent::kNone;

  if (telemetry) {
    for (NSString *event_name in telemetry) {
      mask |= EventNameToMask(santa::NSStringToUTF8StringView([event_name lowercaseString]));
    }
  } else {
    mask = TelemetryEvent::kEverything;

    if (enableForkAndExitLogging == false) {
      mask &= (~TelemetryEvent::kFork & ~TelemetryEvent::kExit);
    }
  }

  return mask;
}

TelemetryEvent ESEventToTelemetryEvent(es_event_type_t event) {
  switch (event) {
    case ES_EVENT_TYPE_NOTIFY_CLONE: return TelemetryEvent::kClone;
    case ES_EVENT_TYPE_NOTIFY_CLOSE: return TelemetryEvent::kClose;
    case ES_EVENT_TYPE_NOTIFY_COPYFILE: return TelemetryEvent::kCopyfile;
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED: return TelemetryEvent::kCodesigningInvalidated;
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA: return TelemetryEvent::kExchangeData;
    case ES_EVENT_TYPE_NOTIFY_EXEC: return TelemetryEvent::kExecution;
    case ES_EVENT_TYPE_NOTIFY_EXIT: return TelemetryEvent::kExit;
    case ES_EVENT_TYPE_NOTIFY_FORK: return TelemetryEvent::kFork;
    case ES_EVENT_TYPE_NOTIFY_LINK: return TelemetryEvent::kLink;
    case ES_EVENT_TYPE_NOTIFY_RENAME: return TelemetryEvent::kRename;
    case ES_EVENT_TYPE_NOTIFY_UNLINK: return TelemetryEvent::kUnlink;
    case ES_EVENT_TYPE_NOTIFY_AUTHENTICATION: return TelemetryEvent::kAuthentication;
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN: return TelemetryEvent::kLoginLogout;
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT: return TelemetryEvent::kLoginLogout;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: return TelemetryEvent::kLoginWindowSession;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGOUT: return TelemetryEvent::kLoginWindowSession;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK: return TelemetryEvent::kLoginWindowSession;
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK: return TelemetryEvent::kLoginWindowSession;
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH: return TelemetryEvent::kScreenSharing;
    case ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH: return TelemetryEvent::kScreenSharing;
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: return TelemetryEvent::kOpenSSH;
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT: return TelemetryEvent::kOpenSSH;
#if HAVE_MACOS_15
    case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE: return TelemetryEvent::kGatekeeperOverride;
#endif  // HAVE_MACOS_15
    default: return TelemetryEvent::kNone;
  }
}

}  // namespace santa
