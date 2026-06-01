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

#ifndef SANTA_COMMON_CODESIGNINGIDENTIFIERUTILS_H
#define SANTA_COMMON_CODESIGNINGIDENTIFIERUTILS_H

#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>

#include <cstdint>
#include <string_view>
#include <utility>

namespace santa {

// The kernel refuses to load, or kills the process on, any page whose
// content does not match its CodeDirectory slot hash when CS_VALID is
// set and CS_HARD or CS_KILL is in effect. Callers use this to decide
// whether the reported cdhash is a strong binding to executed content.
static inline bool CdhashStrictlyEnforced(uint32_t csFlags) {
  return (csFlags & CS_VALID) && (csFlags & (CS_HARD | CS_KILL));
}

extern const NSUInteger kTeamIDLength;
extern NSString* const kPlatformTeamID;
extern NSString* const kPlatformTeamIDPrefix;

// Whether the "platform" sentinel is accepted in place of a 10-char team ID.
enum class PlatformSentinel { kDisallowed, kAllowed };

// Validates that a Team ID is exactly 10 alphanumeric characters, or — when
// platform is kAllowed — the literal "platform" sentinel.
bool IsValidTeamID(std::string_view tid, PlatformSentinel platform = PlatformSentinel::kDisallowed);
bool IsValidTeamID(NSString* tid, PlatformSentinel platform = PlatformSentinel::kDisallowed);

// Validates a signing ID in the format "TeamID:SigningID" or "platform:SigningID".
bool IsValidSigningID(std::string_view sid);
bool IsValidSigningID(NSString* sid);

// Validates a CDHash is a hex string with the correct length.
bool IsValidCDHash(std::string_view cdhash);
bool IsValidCDHash(NSString* cdhash);

// Splits a signing ID into its TeamID and SigningID components.
// Returns (nil, nil) if invalid.
std::pair<NSString*, NSString*> SplitSigningID(NSString* sid);

}  // namespace santa

#endif  // SANTA_COMMON_CODESIGNINGIDENTIFIERUTILS_H
