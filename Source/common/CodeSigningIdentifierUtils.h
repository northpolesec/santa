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
#include <mach/machine.h>

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

// Returns true when the kernel will kill the process for code-signing
// invalidity even if we allow the execution to proceed. Native
// arm64 code must be signed, while unsigned x86_64 code may execute on Intel or
// under Rosetta, so CS_KILL without CS_VALID is only terminal for arm64.
//
// Note that treating CS_KILL without CS_VALID on arm64 as invalid is technically
// incorrect: to the kernel at least, such a binary is considered unsigned. This
// is a deliberate trade-off. All arm64 binaries must be signed, so the kernel
// would refuse to execute a genuinely unsigned one anyway, and creating an
// unsigned arm64 binary is difficult in the first place. The far more common
// case is a binary that is signed but damaged, so reporting invalid is the more
// useful answer.
bool KernelWillKillForCodeSigning(uint32_t csFlags, cpu_type_t imageCPUType);

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
