/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA__COMMON__NKEYTOKENVALIDATOR_H
#define SANTA__COMMON__NKEYTOKENVALIDATOR_H

#include <Foundation/Foundation.h>

#include <set>
#include <string>

namespace santa {

// Validates the full token chain: user JWT -> account JWT -> trusted root keys.
//
// Validation checks:
//   1. Account JWT issuer is a trusted NKey and signature is valid
//   2. User JWT issuer matches account JWT subject
//   3. User JWT signature is valid (verified against account's public key)
//   4. Neither JWT is expired
class NKeyTokenValidator {
 public:
  NKeyTokenValidator(std::set<std::string> trustedNKeys, NSString *accountJWT, NSString *userJWT);
  NKeyTokenValidator(const NKeyTokenValidator &) = delete;
  NKeyTokenValidator(NKeyTokenValidator &&) = delete;
  NKeyTokenValidator &operator=(const NKeyTokenValidator &) = delete;
  NKeyTokenValidator &operator=(NKeyTokenValidator &&) = delete;

  bool Validate();

 private:
  std::set<std::string> trustedNKeys_;
  NSString *accountJWT_;
  NSString *userJWT_;
};

}  // namespace santa

#endif  // SANTA__COMMON__NKEYTOKENVALIDATOR_H
