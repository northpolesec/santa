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

#ifndef SANTA__COMMON__CODESIGNINGIDENTIFIERUTILS_H
#define SANTA__COMMON__CODESIGNINGIDENTIFIERUTILS_H

#import <Foundation/Foundation.h>

#include <utility>

namespace santa {

extern const NSUInteger kTeamIDLength;
extern NSString *const kPlatformTeamID;
extern NSString *const kPlatformTeamIDPrefix;

// Validates that a Team ID is exactly 10 alphanumeric characters.
bool IsValidTeamID(NSString *tid);

// Validates a signing ID in the format "TeamID:SigningID" or "platform:SigningID".
bool IsValidSigningID(NSString *sid);

// Validates a CDHash is a hex string with the correct length.
bool IsValidCDHash(NSString *cdhash);

// Splits a signing ID into its TeamID and SigningID components.
// Returns (nil, nil) if invalid.
std::pair<NSString *, NSString *> SplitSigningID(NSString *sid);

}  // namespace santa

#endif  // SANTA__COMMON__CODESIGNINGIDENTIFIERUTILS_H
