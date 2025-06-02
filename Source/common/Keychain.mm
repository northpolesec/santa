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

#include "Source/common/Keychain.h"

#include <errno.h>

#import "Source/common/SNTLogging.h"

namespace santa {

namespace keychain_utils {
bool IsValidServiceName(NSString *service) {
  return service.length > 0 && service.length <= 128;
}

bool IsValidAccountName(NSString *account) {
  return account.length > 0 && account.length <= 128;
}

bool IsValidDescription(NSString *description) {
  return description.length > 0 && description.length <= 255;
}

inline absl::StatusCode OSStatusToAbslStatusCode(OSStatus status) {
  switch (status) {
    case errSecItemNotFound: return absl::StatusCode::kNotFound;
    case errSecMissingEntitlement: [[fallthrough]];
    case errSecAuthFailed: [[fallthrough]];
    case errSecWrPerm: [[fallthrough]];
    case errSecInteractionNotAllowed: return absl::StatusCode::kPermissionDenied;
    case errSecNoSuchKeychain: return absl::StatusCode::kNotFound;
    case errSecNoSuchAttr: [[fallthrough]];
    case errSecParam: return absl::StatusCode::kInvalidArgument;
    case errSecDuplicateItem: return absl::StatusCode::kAlreadyExists;

    default: return absl::StatusCode::kUnknown;  // Or kUnknown
  }
}

absl::Status SecurityOSStatusToAbslStatus(OSStatus status) {
  if (status == errSecSuccess) {
    return absl::OkStatus();
  }

  NSString *msg = CFBridgingRelease(SecCopyErrorMessageString(status, NULL));
  return absl::Status(OSStatusToAbslStatusCode(status), msg.UTF8String);
}

}  // namespace keychain_utils

std::unique_ptr<KeychainManager> KeychainManager::Create(NSString *service,
                                                         SecPreferencesDomain domain) {
  if (!keychain_utils::IsValidServiceName(service)) {
    return nullptr;
  }

  SecKeychainRef keychain = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  OSStatus status = SecKeychainCopyDomainDefault(domain, &keychain);
#pragma clang diagnostic pop
  if (status != errSecSuccess || keychain == nullptr) {
    LOGE(@"Failed to get desired keychain. Domain: %d, status: %d", domain, status);
    return nullptr;
  }

  return std::make_unique<KeychainManager>(service, keychain);
}

KeychainManager::KeychainManager(NSString *service, SecKeychainRef keychain)
    : service_(service), keychain_(keychain) {
  assert(keychain_ != nullptr);
}

KeychainManager::~KeychainManager() {
  if (keychain_ != nullptr) {
    CFRelease(keychain_);
  }
}

KeychainManager::KeychainManager(KeychainManager &&other)
    : service_(std::move(other.service_)), keychain_(other.keychain_) {
  other.service_ = nil;
  other.keychain_ = nullptr;
}

KeychainManager &KeychainManager::operator=(KeychainManager &&other) {
  if (this != &other) {
    if (keychain_ != nullptr) {
      CFRelease(keychain_);
    }

    service_ = std::move(other.service_);
    keychain_ = other.keychain_;

    other.service_ = nil;
    other.keychain_ = nullptr;
  }
  return *this;
}

std::unique_ptr<KeychainItem> KeychainManager::CreateItem(NSString *account,
                                                          NSString *description) {
  if (!keychain_utils::IsValidAccountName(account)) {
    LOGE(@"Invalid account name for keychain item: %@", account);
    return nullptr;
  }

  if (!keychain_utils::IsValidDescription(description)) {
    LOGE(@"Invalid description for keychain item: %@", description);
    return nullptr;
  }

  return std::make_unique<KeychainItem>(service_, account, description, keychain_);
}

KeychainItem::KeychainItem(NSString *service, NSString *account, NSString *description,
                           SecKeychainRef keychain)
    : service_(service), account_(account), description_(description), keychain_(keychain) {
  assert(keychain_ != nullptr);
  // Retain the keychain reference for ourselves
  CFRetain(keychain_);
}

KeychainItem::~KeychainItem() {
  if (keychain_ != nullptr) {
    CFRelease(keychain_);
  }
}

absl::Status KeychainItem::Store(NSData *data) {
  if (data.length == 0) {
    return absl::ErrnoToStatus(EINVAL, "No data to store");
  }

  if (auto status = Delete(); !status.ok()) {
    LOGE(@"Failed to remove previous value. %s", status.message().data());
    return status;
  }

  NSDictionary *attributes = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : service_,
    (__bridge id)kSecAttrAccount : account_,
    (__bridge id)kSecValueData : data,
    (__bridge id)kSecAttrSynchronizable : @(NO),
    (__bridge id)kSecAttrDescription : description_,
    (__bridge id)kSecReturnAttributes : @(NO),
    (__bridge id)kSecUseKeychain : (__bridge id)keychain_,
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    (__bridge id)kSecAttrAccessible : (__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly,
#pragma clang diagnostic pop
  };

  OSStatus status = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);
  if (status != errSecSuccess) {
    return keychain_utils::SecurityOSStatusToAbslStatus(status);
  }

  return absl::OkStatus();
}

absl::Status KeychainItem::Delete() {
  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : service_,
    (__bridge id)kSecAttrAccount : account_,
    (__bridge id)kSecReturnData : @(NO),
    (__bridge id)kSecMatchSearchList : @[ (__bridge id)keychain_ ],
  };

  OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);

  // Don't consider it an error if the item didn't exist
  if (status != errSecSuccess && status != errSecItemNotFound) {
    return keychain_utils::SecurityOSStatusToAbslStatus(status);
  }

  return absl::OkStatus();
}

absl::StatusOr<NSData *> KeychainItem::Get() {
  NSDictionary *query = @{
    (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrService : service_,
    (__bridge id)kSecAttrAccount : account_,
    (__bridge id)kSecMatchSearchList : @[ (__bridge id)keychain_ ],
    (__bridge id)kSecReturnData : @(YES),
    (__bridge id)kSecMatchLimit : (__bridge id)kSecMatchLimitOne,
  };

  CFTypeRef result = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

  if (status != errSecSuccess) {
    return keychain_utils::SecurityOSStatusToAbslStatus(status);
  }

  return CFBridgingRelease(result);
}

}  // namespace santa
