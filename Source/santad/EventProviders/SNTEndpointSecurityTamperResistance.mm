/// Copyright 2022 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santad/EventProviders/SNTEndpointSecurityTamperResistance.h"

#include <EndpointSecurity/ESTypes.h>
#include <bsm/libbsm.h>
#include <string.h>
#include <algorithm>

#import "Source/common/SNTLogging.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Metrics.h"

using santa::EndpointSecurityAPI;
using santa::EventDisposition;
using santa::Logger;
using santa::Message;
using santa::WatchItemPathType;

constexpr std::pair<std::string_view, WatchItemPathType> kProtectedFiles[] = {
  {"/private/var/db/santa/rules.db", WatchItemPathType::kLiteral},
  {"/private/var/db/santa/events.db", WatchItemPathType::kLiteral},
  {"/Applications/Santa.app", WatchItemPathType::kPrefix},
};

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
        LOGW(@"Preventing attempt to rename important Santa files!!");
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
      result = ES_AUTH_RESULT_ALLOW;
      break;
    }

    case ES_EVENT_TYPE_AUTH_SIGNAL: {
      // Only block signals sent to us and not from launchd.
      if (audit_token_to_pid(esMsg->event.signal.target->audit_token) == getpid() &&
          audit_token_to_pid(esMsg->process->audit_token) != 1) {
        LOGW(@"Preventing attempt to kill Santa daemon");
        result = ES_AUTH_RESULT_DENY;
      }
      break;
    }

    case ES_EVENT_TYPE_AUTH_EXEC: {
      // When not running a debug build, prevent attempts to kill Santa
      // by launchctl commands.
#ifndef DEBUG
      result = ValidateLaunchctlExec(esMsg);
      if (result == ES_AUTH_RESULT_DENY) LOGW(@"Preventing attempt to kill Santa daemon");
#endif
      break;
    }

    default:
      // Unexpected event type, this is a programming error
      [NSException raise:@"Invalid event type"
                  format:@"Invalid tamper resistance event type: %d", esMsg->event_type];
  }

  // Do not cache denied operations so that each tamper attempt is logged
  [self respondToMessage:esMsg withAuthResult:result cacheable:result == ES_AUTH_RESULT_ALLOW];

  // For this client, a processed event is one that was found to be violating anti-tamper policy
  recordEventMetrics(result == ES_AUTH_RESULT_DENY ? EventDisposition::kProcessed
                                                   : EventDisposition::kDropped);
}

- (void)enable {
  [super enableTargetPathWatching];

  // Get the set of protected paths
  std::vector<std::pair<std::string, WatchItemPathType>> protectedPaths =
    [SNTEndpointSecurityTamperResistance getProtectedPaths];
  protectedPaths.push_back({"/Library/SystemExtensions", WatchItemPathType::kPrefix});
  protectedPaths.push_back({"/bin/launchctl", WatchItemPathType::kLiteral});

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

es_auth_result_t ValidateLaunchctlExec(const Message &esMsg) {
  es_string_token_t exec_path = esMsg->event.exec.target->executable->path;
  if (strncmp(exec_path.data, "/bin/launchctl", exec_path.length) != 0) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Ensure there are at least 2 arguments after the command
  std::shared_ptr<EndpointSecurityAPI> esApi = esMsg.ESAPI();
  uint32_t argCount = esApi->ExecArgCount(&esMsg->event.exec);
  if (argCount < 2) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Check for some allowed subcommands
  es_string_token_t arg = esApi->ExecArg(&esMsg->event.exec, 1);
  static const std::unordered_set<std::string> safe_commands{
    "blame", "help", "hostinfo", "list", "plist", "print", "procinfo",
  };
  if (safe_commands.find(std::string(arg.data, arg.length)) != safe_commands.end()) {
    return ES_AUTH_RESULT_ALLOW;
  }

  // Check whether com.northpolesec.santa.daemon is in the argument list.
  // launchctl no longer accepts PIDs to operate on.
  for (int i = 2; i < argCount; i++) {
    es_string_token_t arg = esApi->ExecArg(&esMsg->event.exec, i);
    if (strnstr(arg.data, "com.northpolesec.santa.daemon", arg.length) != NULL) {
      return ES_AUTH_RESULT_DENY;
    }
  }

  return ES_AUTH_RESULT_ALLOW;
}

+ (std::vector<std::pair<std::string, WatchItemPathType>>)getProtectedPaths {
  std::vector<std::pair<std::string, WatchItemPathType>> protectedPathsCopy(
    sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]));

  for (size_t i = 0; i < sizeof(kProtectedFiles) / sizeof(kProtectedFiles[0]); ++i) {
    protectedPathsCopy.emplace_back(std::string(kProtectedFiles[i].first),
                                    kProtectedFiles[i].second);
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

@end
