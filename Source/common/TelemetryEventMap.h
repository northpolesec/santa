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

#ifndef SANTA__COMMON__TELEMETRYEVENTMAP_H
#define SANTA__COMMON__TELEMETRYEVENTMAP_H

#import <EndpointSecurity/ESTypes.h>
#import <Foundation/Foundation.h>

namespace santa {

// clang-format off
enum class TelemetryEvent : uint64_t {
  kNone                    = 0,
  kExecution               = 1 << 0,
  kFork                    = 1 << 1,
  kExit                    = 1 << 2,
  kClose                   = 1 << 3,
  kRename                  = 1 << 4,
  kUnlink                  = 1 << 5,
  kLink                    = 1 << 6,
  kExchangeData            = 1 << 7,
  kDisk                    = 1 << 8,
  kBundle                  = 1 << 9,
  kAllowlist               = 1 << 10,
  kFileAccess              = 1 << 11,
  kCodesigningInvalidated  = 1 << 12,
  kLoginWindowSession      = 1 << 13,
  kLoginLogout             = 1 << 14,
  kScreenSharing           = 1 << 15,
  kOpenSSH                 = 1 << 16,
  kAuthentication          = 1 << 17,
  kClone                   = 1 << 18,
  kCopyfile                = 1 << 19,
  kEverything              = ~0ULL,
};
// clang-format on

inline TelemetryEvent operator|(TelemetryEvent lhs, TelemetryEvent rhs) {
  return static_cast<TelemetryEvent>(static_cast<std::underlying_type_t<TelemetryEvent>>(lhs) |
                                     static_cast<std::underlying_type_t<TelemetryEvent>>(rhs));
}

inline TelemetryEvent &operator|=(TelemetryEvent &lhs, TelemetryEvent rhs) {
  lhs = lhs | rhs;
  return lhs;
}

inline TelemetryEvent operator&(TelemetryEvent lhs, TelemetryEvent rhs) {
  return static_cast<TelemetryEvent>(static_cast<std::underlying_type_t<TelemetryEvent>>(lhs) &
                                     static_cast<std::underlying_type_t<TelemetryEvent>>(rhs));
}

inline TelemetryEvent &operator&=(TelemetryEvent &lhs, TelemetryEvent rhs) {
  lhs = lhs & rhs;
  return lhs;
}

inline TelemetryEvent operator~(TelemetryEvent rhs) {
  return static_cast<TelemetryEvent>(~static_cast<std::underlying_type_t<TelemetryEvent>>(rhs));
}

// Create a `TelemetryEvent` bitmask based on the `Telemetry` and
// `EnableForkAndExitLogging` configuration values. The `Telemetry` event
// array takes precedence over `EnableForkAndExitLogging`.
//
// If `Telemetry` is set, the events specified will be used.
// If `Telemetry` is not set, `everything` (all events) are assumed.
// When `Telemetry` is not set, `EnableForkAndExitLogging` willbe checked. If
// `false`, the `FORK` and `EXIT` bits will be cleared from the mask.
TelemetryEvent TelemetryConfigToBitmask(NSArray<NSString *> *telemetry,
                                        BOOL enableForkAndExitLogging);

// Returns the appropriate `TelemetryEvent` enum value for a given ES event
TelemetryEvent ESEventToTelemetryEvent(es_event_type_t event);

}  // namespace santa

#endif
