/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"

#include <EndpointSecurity/ESTypes.h>
#include <bsm/libbsm.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/errno.h>
#include <unistd.h>

#include <algorithm>
#include <tuple>
#include <unordered_set>

#import "Source/common/SNTLogging.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::EndpointSecurityAPI;
using santa::EventDisposition;
using santa::Logger;
using santa::Message;
using santa::SetPairPathAndType;
using santa::WatchItemPathType;

// The ES client process (com.northpolesec.santa.daemon) will be the only process allowed to
// modify these file paths.
constexpr std::pair<std::string_view, WatchItemPathType> kProtectedFiles[] = {
    {"/private/var/db/santa/rules.db", WatchItemPathType::kLiteral},
    {"/private/var/db/santa/events.db", WatchItemPathType::kLiteral},
    {"/private/var/db/santa/sync-state.plist", WatchItemPathType::kLiteral},
    {"/Applications/Santa.app", WatchItemPathType::kPrefix},
    {"/Library/LaunchAgents/com.northpolesec.santa.", WatchItemPathType::kPrefix},
    {"/Library/LaunchDaemons/com.northpolesec.santa.", WatchItemPathType::kPrefix},
};

void RemoveLegacyLaunchdPlists() {
  constexpr std::string_view legacyPlists[] = {
      "/Library/LaunchDaemons/com.google.santad.plist",
      "/Library/LaunchDaemons/com.google.santa.bundleservice.plist",
      "/Library/LaunchDaemons/com.google.santa.metricservice.plist",
      "/Library/LaunchDaemons/com.google.santa.syncservice.plist",
      "/Library/LaunchAgents/com.google.santa.plist",
      // Assume that NPS Santa has already migrated any existing Google newsyslog
      // config and we can simply remove a new config file that was just laid
      // down as part of a Google Santa install that is being prevented from running.
      "/private/etc/newsyslog.d/com.google.santa.newsyslog.conf",
  };

  for (const auto &plist : legacyPlists) {
    // Note: As currently written, all legacy plists will be removed when any of the individual
    // plists are attempted to be loaded. This is a bit overkill in that each plist will be removed
    // 5 times, but not a big deal. If the unlink error is that the file doesn't exist, the log
    // warning is suppressed.
    int flag = 0;
    if (@available(macOS 14.0, *)) {
      // Support for AT_SYMLINK_NOFOLLOW_ANY in unlinkat(2) wasn't introduced until macOS 14.
      flag = AT_SYMLINK_NOFOLLOW_ANY;
    }
    if (unlinkat(AT_FDCWD, plist.data(), flag) != 0 && errno != ENOENT) {
      LOGW(@"Unable to remove legacy plist \"%s\": %d: %s", plist.data(), errno, strerror(errno));
    }
  }
}

/// Return a pair of whether or not to allow the exec and whether or not the ES response should be
/// cached. If the exec is not launchctl, the response can be cached, otherwise the response should
/// not be cached.
std::pair<es_auth_result_t, bool> ValidateLaunchctlExec(const Message &esMsg) {
  es_string_token_t exec_path = esMsg->event.exec.target->executable->path;
  if (strncmp(exec_path.data, "/bin/launchctl", exec_path.length) != 0) {
    return {ES_AUTH_RESULT_ALLOW, true};
  }

  // Ensure there are at least 2 arguments after the command
  std::shared_ptr<EndpointSecurityAPI> esApi = esMsg.ESAPI();
  uint32_t argCount = esApi->ExecArgCount(&esMsg->event.exec);
  if (argCount < 2) {
    return {ES_AUTH_RESULT_ALLOW, false};
  }

  // Check for some allowed subcommands
  es_string_token_t arg = esApi->ExecArg(&esMsg->event.exec, 1);
  static const std::unordered_set<std::string> safe_commands{
      "blame", "help", "hostinfo", "list", "plist", "print", "procinfo",
  };
  if (safe_commands.find(std::string(arg.data, arg.length)) != safe_commands.end()) {
    return {ES_AUTH_RESULT_ALLOW, false};
  }

  for (int i = 2; i < argCount; i++) {
    es_string_token_t arg = esApi->ExecArg(&esMsg->event.exec, i);

    if (strnstr(arg.data, "com.northpolesec.santa.daemon", arg.length) != NULL) {
      LOGW(@"Preventing attempt to kill Santa daemon by launchctl");
      return {ES_AUTH_RESULT_DENY, false};
    }

    // If legacy plists paths are found, assume a load is being attempted. Block the exec and
    // delete all of the plists.
    if (strnstr(arg.data, "/Library/LaunchDaemons/com.google.santa", arg.length) != NULL ||
        strnstr(arg.data, "/Library/LaunchAgents/com.google.santa.plist", arg.length) != NULL) {
      LOGW(@"Preventing load of legacy Santa component");
      RemoveLegacyLaunchdPlists();
      return {ES_AUTH_RESULT_DENY, false};
    }
  }

  return {ES_AUTH_RESULT_ALLOW, false};
}

@implementation SNTEndpointSecurityTamperResistance {
  std::shared_ptr<Logger> _logger;
}

- (instancetype)initWithESAPI:(std::shared_ptr<EndpointSecurityAPI>)esApi
                      metrics:(std::shared_ptr<santa::Metrics>)metrics
                       logger:(std::shared_ptr<Logger>)logger {
  self = [super initWithESAPI:std::move(esApi)
                      metrics:std::move(metrics)
                    processor:santa::Processor::kTamperResistance];
  if (self) {
    _logger = logger;

    [self establishClientOrDie];
  }
  return self;
}

- (NSString *)description {
  return @"Tamper Resistance";
}

- (void)handleMessage:(Message &&)esMsg
    recordEventMetrics:(void (^)(EventDisposition))recordEventMetrics {
  es_auth_result_t result = ES_AUTH_RESULT_ALLOW;
  bool cacheable = true;
  switch (esMsg->event_type) {
    case ES_EVENT_TYPE_AUTH_UNLINK: {
      if ([SNTEndpointSecurityTamperResistance
              isProtectedPath:esMsg->event.unlink.target->path.data]) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to delete important Santa files!");
      }
      break;
    }

    case ES_EVENT_TYPE_AUTH_RENAME: {
      if ([SNTEndpointSecurityTamperResistance
              isProtectedPath:esMsg->event.rename.source->path.data]) {
        result = ES_AUTH_RESULT_DENY;
        LOGW(@"Preventing attempt to rename important Santa files!");
        break;
      }

      if (esMsg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
        if ([SNTEndpointSecurityTamperResistance
                isProtectedPath:esMsg->event.rename.destination.existing_file->path.data]) {
          result = ES_AUTH_RESULT_DENY;
          LOGW(@"Preventing attempt to overwrite important Santa files!");
          break;
        }
      }

      break;
    }

    case ES_EVENT_TYPE_AUTH_OPEN: {
      if ((esMsg->event.open.fflag & FWRITE) &&
          [SNTEndpointSecurityTamperResistance isProtectedPath:esMsg->event.open.file->path.data]) {
        LOGW(@"Preventing attempt to open important Santa files as writable!");
        result = ES_AUTH_RESULT_DENY;
        break;
      }
      if ([SNTEndpointSecurityTamperResistance
              isLiteralProtectedPath:esMsg->event.open.file->path.data]) {
        LOGW(@"Preventing attempt to open sensitive Santa files as readable!");
        result = ES_AUTH_RESULT_DENY;
        break;
      }

      result = ES_AUTH_RESULT_ALLOW;
      // OPEN events are not currently cacheable because we haven't yet implemented a method to
      // respond with a subset of allowed flags. This could be changed in the future if desired, but
      // currently this is not a hot enough path to worry about.
      cacheable = false;
      break;
    }

    case ES_EVENT_TYPE_AUTH_SIGNAL: {
      if (esMsg->event.signal.sig == 0) {
        // Signal 0 doesn't actually get sent to the process, it is only used to
        // check if the process exists. Because of this, we don't need to block it.
        break;
      }

      // Only block signals sent to us and not from launchd.
      pid_t sourcePid = audit_token_to_pid(esMsg->process->audit_token);
      pid_t targetPid = audit_token_to_pid(esMsg->event.signal.target->audit_token);
      if (targetPid == getpid() && sourcePid != 1) {
        LOGW(@"Preventing attempt to signal Santa daemon: signal %d, sending pid: %d",
             esMsg->event.signal.sig, sourcePid);
        result = ES_AUTH_RESULT_DENY;
      }
      break;
    }

    case ES_EVENT_TYPE_AUTH_EXEC: {
      std::tie(result, cacheable) = ValidateLaunchctlExec(esMsg);
      break;
    }

    default:
      // Unexpected event type, this is a programming error
      [NSException raise:@"Invalid event type"
                  format:@"Invalid tamper resistance event type: %d", esMsg->event_type];
  }

  // Do not cache denied operations so that each tamper attempt is logged.
  [self respondToMessage:esMsg
          withAuthResult:result
               cacheable:(cacheable && result == ES_AUTH_RESULT_ALLOW)];

  // For this client, a processed event is one that was found to be violating anti-tamper policy
  recordEventMetrics(result == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                   : EventDisposition::kDropped);
}

- (void)enable {
  [super enableTargetPathWatching];

  // Get the set of protected paths
  SetPairPathAndType protectedPaths = [SNTEndpointSecurityTamperResistance getProtectedPaths];
  protectedPaths.insert({"/Library/SystemExtensions", WatchItemPathType::kPrefix});
  protectedPaths.insert({"/bin/launchctl", WatchItemPathType::kLiteral});

  // Begin watching the protected set
  [super muteTargetPaths:protectedPaths];

  [super subscribeAndClearCache:{
                                    ES_EVENT_TYPE_AUTH_SIGNAL,
                                    ES_EVENT_TYPE_AUTH_EXEC,
                                    ES_EVENT_TYPE_AUTH_UNLINK,
                                    ES_EVENT_TYPE_AUTH_RENAME,
                                    ES_EVENT_TYPE_AUTH_OPEN,
  }];
}

+ (SetPairPathAndType)getProtectedPaths {
  SetPairPathAndType protectedPathsCopy;

  for (size_t i = 0; i < sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]); ++i) {
    protectedPathsCopy.insert({std::string(kProtectedFiles[i].first), kProtectedFiles[i].second});
  }

  return protectedPathsCopy;
}

+ (bool)isProtectedPath:(const std::string_view)path {
  // TODO(mlw): These values should come from `SNTDatabaseController`. But right
  // now they live as NSStrings. We should make them `std::string_view` types
  // in order to use them here efficiently, but will need to make the
  // `SNTDatabaseController` an ObjC++ file.
  for (size_t i = 0; i < sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]); ++i) {
    auto pf = kProtectedFiles[i];
    switch (pf.second) {
      case WatchItemPathType::kLiteral:
        if (path == pf.first) return true;
        break;
      case WatchItemPathType::kPrefix:
        if (path.rfind(pf.first, 0) == 0) return true;
        break;
    }
  }
  return false;
}

+ (bool)isLiteralProtectedPath:(const std::string_view)path {
  for (size_t i = 0; i < sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]); ++i) {
    auto pf = kProtectedFiles[i];
    if (pf.second == WatchItemPathType::kLiteral && path == pf.first) return true;
  }
  return false;
}

@end
