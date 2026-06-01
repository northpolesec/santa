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

#include "Source/common/CodeSigningIdentifierUtils.h"

#include <Kernel/kern/cs_blobs.h>

#include "Source/common/String.h"

namespace santa {

const NSUInteger kTeamIDLength = 10;
NSString* const kPlatformTeamID = @"platform";
NSString* const kPlatformTeamIDPrefix = @"platform:";

namespace {

bool IsAsciiAlnum(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

bool IsAsciiHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

}  // namespace

bool IsValidTeamID(std::string_view tid, PlatformSentinel platform) {
  if (platform == PlatformSentinel::kAllowed && tid == "platform") {
    return true;
  }
  if (tid.size() != kTeamIDLength) {
    return false;
  }
  for (char c : tid) {
    if (!IsAsciiAlnum(c)) {
      return false;
    }
  }
  return true;
}

bool IsValidTeamID(NSString* tid, PlatformSentinel platform) {
  if (!tid) {
    return false;
  }
  return IsValidTeamID(NSStringToUTF8StringView(tid), platform);
}

bool IsValidSigningID(std::string_view sid) {
  // Split on the first ':'; the team token (kAllowed accepts "platform") must be
  // valid and a non-empty signing-ID component must follow.
  size_t colon = sid.find(':');
  if (colon == std::string_view::npos) {
    return false;
  }
  return colon + 1 < sid.size() && IsValidTeamID(sid.substr(0, colon), PlatformSentinel::kAllowed);
}

bool IsValidSigningID(NSString* sid) {
  if (!sid) {
    return false;
  }
  return IsValidSigningID(NSStringToUTF8StringView(sid));
}

bool IsValidCDHash(std::string_view cdhash) {
  if (cdhash.size() != CS_CDHASH_LEN * 2) {
    return false;
  }
  for (char c : cdhash) {
    if (!IsAsciiHexDigit(c)) {
      return false;
    }
  }
  return true;
}

bool IsValidCDHash(NSString* cdhash) {
  if (!cdhash) {
    return false;
  }
  return IsValidCDHash(NSStringToUTF8StringView(cdhash));
}

std::pair<NSString*, NSString*> SplitSigningID(NSString* sid) {
  if (!IsValidSigningID(sid)) {
    return {nil, nil};
  }

  if ([sid hasPrefix:kPlatformTeamIDPrefix]) {
    return {kPlatformTeamID, [sid substringFromIndex:kPlatformTeamIDPrefix.length]};
  } else {
    return {[sid substringToIndex:kTeamIDLength], [sid substringFromIndex:kTeamIDLength + 1]};
  }
}

}  // namespace santa
