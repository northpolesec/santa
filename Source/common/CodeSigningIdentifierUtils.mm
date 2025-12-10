/// Copyright 2025 North Pole Security, Inc.
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

namespace santa {

const NSUInteger kTeamIDLength = 10;
NSString *const kPlatformTeamID = @"platform";
NSString *const kPlatformTeamIDPrefix = @"platform:";

bool IsValidTeamID(NSString *tid) {
  static NSCharacterSet *nonAlnum = [[NSCharacterSet
      characterSetWithCharactersInString:
          @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"] invertedSet];
  return tid.length == kTeamIDLength &&
         [tid rangeOfCharacterFromSet:nonAlnum].location == NSNotFound;
}

bool IsValidSigningID(NSString *sid) {
  if ([sid hasPrefix:kPlatformTeamIDPrefix] && sid.length > kPlatformTeamIDPrefix.length) {
    return true;
  } else if (sid.length > kTeamIDLength + 1 && [sid characterAtIndex:kTeamIDLength] == ':') {
    return IsValidTeamID([sid substringToIndex:kTeamIDLength]);
  } else {
    return false;
  }
}

bool IsValidCDHash(NSString *cdhash) {
  static NSCharacterSet *nonHex =
      [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdefABCDEF"] invertedSet];
  return cdhash.length == CS_CDHASH_LEN * 2 &&
         [cdhash rangeOfCharacterFromSet:nonHex].location == NSNotFound;
}

std::pair<NSString *, NSString *> SplitSigningID(NSString *sid) {
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
