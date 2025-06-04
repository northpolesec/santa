/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA__COMMON__KEYCHAIN_H
#define SANTA__COMMON__KEYCHAIN_H

#import <Foundation/Foundation.h>
#import <Security/Security.h>

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace santa {
namespace keychain {

// Validation helpers with semi-arbitrary length checks.
bool IsValidServiceName(NSString *service);
bool IsValidAccountName(NSString *account);
bool IsValidDescription(NSString *description);

absl::Status SecurityOSStatusToAbslStatus(OSStatus status);

class Item;

class Manager {
 public:
  static std::unique_ptr<Manager> Create(NSString *service, SecPreferencesDomain domain);
  Manager(NSString *service, SecKeychainRef keychain_ref);
  ~Manager();

  Manager(Manager &&other);
  Manager &operator=(Manager &&other);

  // Could be safe to implement, but not currently needed
  Manager(Manager &other) = delete;
  Manager &operator=(Manager &other) = delete;

  std::unique_ptr<Item> CreateItem(NSString *account, NSString *description);

 private:
  NSString *service_;
  SecKeychainRef keychain_;
};

class Item {
 public:
  // Note: The given keychain is retained
  Item(NSString *service, NSString *account, NSString *description, SecKeychainRef keychain);
  ~Item();

  absl::Status Store(NSData *data);
  absl::Status Delete();
  absl::StatusOr<NSData *> Get();

 private:
  NSString *service_;
  NSString *account_;
  NSString *description_;
  SecKeychainRef keychain_;
};

}  // namespace keychain
}  // namespace santa

#endif  // SANTA__COMMON__KEYCHAIN_H
