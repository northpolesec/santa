/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
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

#include "Source/common/faa/WatchItems.h"

#include <CommonCrypto/CommonDigest.h>
#include <Kernel/kern/cs_blobs.h>
#include <ctype.h>
#include <sys/syslimits.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#import "Source/common/Glob.h"
#import "Source/common/PrefixTree.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/String.h"
#import "Source/common/Unit.h"
#include "Source/common/faa/WatchItemPolicy.h"

NSString *const kWatchItemConfigKeyVersion = @"Version";
NSString *const kWatchItemConfigKeyEventDetailURL = @"EventDetailURL";
NSString *const kWatchItemConfigKeyEventDetailText = @"EventDetailText";
NSString *const kWatchItemConfigKeyWatchItems = @"WatchItems";
NSString *const kWatchItemConfigKeyPaths = @"Paths";
NSString *const kWatchItemConfigKeyPathsPath = @"Path";
NSString *const kWatchItemConfigKeyPathsIsPrefix = @"IsPrefix";
NSString *const kWatchItemConfigKeyOptions = @"Options";
NSString *const kWatchItemConfigKeyOptionsAllowReadAccess = @"AllowReadAccess";
NSString *const kWatchItemConfigKeyOptionsAuditOnly = @"AuditOnly";
NSString *const kWatchItemConfigKeyOptionsInvertProcessExceptions = @"InvertProcessExceptions";
NSString *const kWatchItemConfigKeyOptionsRuleType = @"RuleType";
NSString *const kWatchItemConfigKeyOptionsEnableSilentMode = @"EnableSilentMode";
NSString *const kWatchItemConfigKeyOptionsEnableSilentTTYMode = @"EnableSilentTTYMode";
NSString *const kWatchItemConfigKeyOptionsCustomMessage = @"BlockMessage";
NSString *const kWatchItemConfigKeyOptionsEventDetailURL = kWatchItemConfigKeyEventDetailURL;
NSString *const kWatchItemConfigKeyOptionsEventDetailText = kWatchItemConfigKeyEventDetailText;
NSString *const kWatchItemConfigKeyProcesses = @"Processes";
NSString *const kWatchItemConfigKeyProcessesBinaryPath = @"BinaryPath";
NSString *const kWatchItemConfigKeyProcessesCertificateSha256 = @"CertificateSha256";
NSString *const kWatchItemConfigKeyProcessesSigningID = @"SigningID";
NSString *const kWatchItemConfigKeyProcessesTeamID = @"TeamID";
NSString *const kWatchItemConfigKeyProcessesCDHash = @"CDHash";
NSString *const kWatchItemConfigKeyProcessesPlatformBinary = @"PlatformBinary";

// https://developer.apple.com/help/account/manage-your-team/locate-your-team-id/
static constexpr NSUInteger kMaxTeamIDLength = 10;

// Semi-arbitrary upper bound.
static constexpr NSUInteger kMaxSigningIDLength = 512;

// Semi-arbitrary minimum allowed reapplication frequency.
// Goal is to prevent a configuration setting that would cause too much
// churn rebuilding glob paths based on the state of the filesystem.
static constexpr uint64_t kMinReapplyConfigFrequencySecs = 15;

// Semi-arbitrary max custom message length. The goal is to protect against
// potential unbounded lengths, but no real reason this cannot be higher.
static constexpr NSUInteger kWatchItemConfigOptionCustomMessageMaxLength = 2048;

// Semi-arbitrary max event detail text length. The text has to fit on a button
// and shouldn't be too large.
static constexpr NSUInteger kWatchItemConfigEventDetailTextMaxLength = 48;

// Servers are recommended to support up to 8000 octets.
// https://www.rfc-editor.org/rfc/rfc9110#section-4.1-5
//
// Seems excessive but no good reason to not allow long URLs. However because
// the URL supports pseudo-format strings that can extend the length, a smaller
// max is used here.
static constexpr NSUInteger kWatchItemConfigEventDetailURLMaxLength = 6000;

namespace santa {

namespace {
// Type aliases
using ValidatorBlock = bool (^)(id, NSError **);
}  // namespace

/// Ensure the given string has the expected length and only
/// contains valid hex digits
bool ConfirmValidHexString(NSString *str, size_t expected_length) {
  if (str.length != expected_length) {
    return false;
  }

  for (int i = 0; i < str.length; i++) {
    if (!isxdigit([str characterAtIndex:i])) {
      return false;
    }
  }

  return true;
}

static inline bool GetBoolValue(NSDictionary *options, NSString *key, bool default_value) {
  return options[key] ? [options[key] boolValue] : default_value;
}

std::optional<WatchItemRuleType> GetRuleType(NSString *rule_type) {
  rule_type = [rule_type lowercaseString];
  if ([rule_type isEqualToString:@"pathswithallowedprocesses"]) {
    return WatchItemRuleType::kPathsWithAllowedProcesses;
  } else if ([rule_type isEqualToString:@"pathswithdeniedprocesses"]) {
    return WatchItemRuleType::kPathsWithDeniedProcesses;
  } else if ([rule_type isEqualToString:@"processeswithallowedpaths"]) {
    return WatchItemRuleType::kProcessesWithAllowedPaths;
  } else if ([rule_type isEqualToString:@"processeswithdeniedpaths"]) {
    return WatchItemRuleType::kProcessesWithDeniedPaths;
  } else {
    return std::nullopt;
  }
}

// The given function is expected to return std::nullopt when it
// is provided an invalid value.
template <typename T>
ValidatorBlock ValidValuesValidator(std::function<std::optional<T>(NSString *)> f) {
  return ^bool(NSString *val, NSError **err) {
    if (!f(val).has_value()) {
      [SNTError populateError:err withFormat:@"Invalid value. Got: \"%@\"", val];
      return false;
    }
    return true;
  };
}

// Given a length, returns a ValidatorBlock that confirms the
// string is a valid hex string of the given length.
ValidatorBlock HexValidator(NSUInteger expected_length) {
  return ^bool(NSString *val, NSError **err) {
    if (!ConfirmValidHexString(val, expected_length)) {
      [SNTError populateError:err withFormat:@"Expected hex string of length %lu", expected_length];
      return false;
    }

    return true;
  };
}

// Given a min and max length, returns a ValidatorBlock that confirms the
// string is within the given bounds.
ValidatorBlock LenRangeValidator(NSUInteger min_length, NSUInteger max_length) {
  return ^bool(NSString *val, NSError **err) {
    if (val.length < min_length) {
      [SNTError populateError:err
                   withFormat:@"Value too short. Got: %lu, Min: %lu", val.length, min_length];
      return false;
    } else if (val.length > max_length) {
      [SNTError populateError:err
                   withFormat:@"Value too long. Got: %lu, Max: %lu", val.length, max_length];
      return false;
    }

    return true;
  };
}

/// Ensure the key exists (if required) and the value matches the expected type
bool VerifyConfigKey(NSDictionary *dict, const NSString *key, Class expected, NSError **err,
                     bool required = false, bool (^Validator)(id, NSError **) = nil) {
  if (dict[key]) {
    if (![dict[key] isKindOfClass:expected]) {
      [SNTError
          populateError:err
             withFormat:@"Expected type '%@' for key '%@' (got: %@)", NSStringFromClass(expected),
                        key, NSStringFromClass([dict[key] class])];
      return false;
    }

    NSError *validator_err;
    if (Validator && !Validator(dict[key], &validator_err)) {
      [SNTError populateError:err
                   withFormat:@"Invalid content in key '%@': %@", key,
                              validator_err.localizedDescription];
      return false;
    }
  } else if (required) {
    [SNTError populateError:err withFormat:@"Missing required key '%@'", key];
    return false;
  }

  return true;
}

/// Ensure all values of the array key in the dictionary conform to the
/// expected type. If a Validator block is supplied, each item is also
/// subject to the custom validation method.
bool VerifyConfigKeyArray(NSDictionary *dict, NSString *key, Class expected, NSError **err,
                          bool (^Validator)(id, NSError **) = nil) {
  if (!VerifyConfigKey(dict, key, [NSArray class], err)) {
    return false;
  }

  __block bool success = true;
  __block NSError *block_err;

  [dict[key] enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
    if (![obj isKindOfClass:expected]) {
      success = false;
      [SNTError populateError:&block_err
                   withFormat:@"Expected all '%@' types in array key '%@'",
                              NSStringFromClass(expected), key];
      *stop = YES;
      return;
    }

    NSError *validator_err;
    if (Validator && !Validator(obj, &validator_err)) {
      [SNTError populateError:&block_err
                   withFormat:@"Invalid content in array key '%@': %@", key,
                              validator_err.localizedDescription];
      success = false;
      *stop = YES;
      return;
    }
  }];

  if (!success && block_err && err) {
    *err = block_err;
  }

  return success;
}

/// The `Paths` array can contain only `string` and `dict` types:
/// - For `string` types, the default path type `kDefaultPathType` is used
/// - For `dict` types, there is a required `Path` key. and an optional
///   `IsPrefix` key to set the path type to something other than the default
///
/// Example:
/// <array>
///   <string>/my/path</string>
///   <dict>
///     <key>Path</key>
///     <string>/another/partial/path</string>
///     <key>IsPrefix</key>
///     <true/>
///   </dict>
/// </array>
std::variant<Unit, SetPairPathAndType> VerifyConfigWatchItemPaths(NSArray<id> *paths,
                                                                  NSError **err) {
  SetPairPathAndType path_list;

  for (id path in paths) {
    if ([path isKindOfClass:[NSDictionary class]]) {
      NSDictionary *path_dict = (NSDictionary *)path;
      if (!VerifyConfigKey(path_dict, kWatchItemConfigKeyPathsPath, [NSString class], err, true,
                           LenRangeValidator(1, PATH_MAX))) {
        return Unit{};
      }

      NSString *path_str = path_dict[kWatchItemConfigKeyPathsPath];
      WatchItemPathType path_type = kWatchItemPolicyDefaultPathType;

      if (VerifyConfigKey(path_dict, kWatchItemConfigKeyPathsIsPrefix, [NSNumber class], err)) {
        path_type = ([(NSNumber *)path_dict[kWatchItemConfigKeyPathsIsPrefix] boolValue] == NO
                         ? WatchItemPathType::kLiteral
                         : WatchItemPathType::kPrefix);
      } else {
        return Unit{};
      }

      path_list.insert({NSStringToUTF8String(path_str), path_type});
    } else if ([path isKindOfClass:[NSString class]]) {
      if (!LenRangeValidator(1, PATH_MAX)(path, err)) {
        [SNTError populateError:err
                     withFormat:@"Invalid path length: %@",
                                (err && *err) ? (*err).localizedDescription : @"Unknown error"];
        return Unit{};
      }

      path_list.insert({NSStringToUTF8String(((NSString *)path)), kWatchItemPolicyDefaultPathType});
    } else {
      [SNTError
          populateError:err
             withFormat:@"%@ array item with invalid type. Expected 'dict' or 'string' (got: %@)",
                        kWatchItemConfigKeyPaths, NSStringFromClass([path class])];
      return Unit{};
    }
  }

  if (path_list.size() == 0) {
    [SNTError populateError:err withFormat:@"No paths specified"];
    return Unit{};
  }

  return path_list;
}

/// The `Processes` array can only contain dictionaries. Each dictionary can
/// contain the attributes that describe a single process.
///
/// <array>
///   <dict>
///     <key>BinaryPath</key>
///     <string>AAAA</string>
///     <key>TeamID</key>
///     <string>BBBB</string>
///     <key>PlatformBinary</key>
///     <true/>
///   </dict>
///   <dict>
///     <key>CertificateSha256</key>
///     <string>CCCC</string>
///     <key>CDHash</key>
///     <string>DDDD</string>
///     <key>SigningID</key>
///     <string>EEEE</string>
///   </dict>
/// </array>
std::variant<Unit, SetWatchItemProcess> VerifyConfigWatchItemProcesses(NSDictionary *watch_item,
                                                                       NSError **err) {
  __block SetWatchItemProcess proc_list;

  if (!VerifyConfigKeyArray(
          watch_item, kWatchItemConfigKeyProcesses, [NSDictionary class], err,
          ^bool(NSDictionary *process, NSError **err) {
            if (!VerifyConfigKey(process, kWatchItemConfigKeyProcessesBinaryPath, [NSString class],
                                 err, false, LenRangeValidator(1, PATH_MAX)) ||
                !VerifyConfigKey(process, kWatchItemConfigKeyProcessesSigningID, [NSString class],
                                 err, false, LenRangeValidator(1, kMaxSigningIDLength)) ||
                !VerifyConfigKey(process, kWatchItemConfigKeyProcessesTeamID, [NSString class], err,
                                 false, LenRangeValidator(kMaxTeamIDLength, kMaxTeamIDLength)) ||
                !VerifyConfigKey(process, kWatchItemConfigKeyProcessesCDHash, [NSString class], err,
                                 false, HexValidator(CS_CDHASH_LEN * 2)) ||
                !VerifyConfigKey(process, kWatchItemConfigKeyProcessesCertificateSha256,
                                 [NSString class], err, false,
                                 HexValidator(CC_SHA256_DIGEST_LENGTH * 2)) ||
                !VerifyConfigKey(process, kWatchItemConfigKeyProcessesPlatformBinary,
                                 [NSNumber class], err, false, nil)) {
              [SNTError populateError:err withFormat:@"Failed to verify key content"];
              return false;
            }

            // Ensure at least one attribute set
            if (!process[kWatchItemConfigKeyProcessesBinaryPath] &&
                !process[kWatchItemConfigKeyProcessesSigningID] &&
                !process[kWatchItemConfigKeyProcessesTeamID] &&
                !process[kWatchItemConfigKeyProcessesCDHash] &&
                !process[kWatchItemConfigKeyProcessesCertificateSha256] &&
                !process[kWatchItemConfigKeyProcessesPlatformBinary]) {
              [SNTError populateError:err
                           withFormat:@"No valid attributes set in process dictionary"];
              return false;
            }

            // Ensure that if the SigningID is a prefix, either PlatformBinary or TeamID is set
            if (process[kWatchItemConfigKeyProcessesSigningID]) {
              std::string sid([process[kWatchItemConfigKeyProcessesSigningID] UTF8String]);
              if (sid.find('*') != std::string::npos &&
                  (([process[kWatchItemConfigKeyProcessesPlatformBinary] boolValue] == false &&
                    process[kWatchItemConfigKeyProcessesTeamID] == nil))) {
                [SNTError populateError:err
                             withFormat:@"A SigningID prefix (%@) requires either the "
                                        @"PlatformBinary or TeamID keys be set",
                                        process[kWatchItemConfigKeyProcessesSigningID]];
                return false;
              }
            }

            proc_list.insert(WatchItemProcess(
                NSStringToUTF8String(process[kWatchItemConfigKeyProcessesBinaryPath] ?: @""),
                NSStringToUTF8String(process[kWatchItemConfigKeyProcessesSigningID] ?: @""),
                NSStringToUTF8String(process[kWatchItemConfigKeyProcessesTeamID] ?: @""),
                HexStringToBuf(process[kWatchItemConfigKeyProcessesCDHash]),
                NSStringToUTF8String(process[kWatchItemConfigKeyProcessesCertificateSha256] ?: @""),
                process[kWatchItemConfigKeyProcessesPlatformBinary]
                    ? std::make_optional(
                          (bool)[process[kWatchItemConfigKeyProcessesPlatformBinary] boolValue])
                    : std::nullopt));

            return true;
          })) {
    return Unit{};
  }

  return proc_list;
}

/// Ensure that a given watch item conforms to expected structure
///
/// Example:
/// <dict>
///   <key>Paths</key>
///   <array>
///   ... See VerifyConfigWatchItemPaths for more details ...
///   </array>
///   <key>Options</key>
///   <dict>
///     <key>AllowReadAccess</key>
///     <false/>
///     <key>AuditOnly</key>
///     <false/>
///     <key>InvertProcessExceptions</key> <!-- Deprecated -->
///     <false/>
///     <key>RuleType</key>
///     <string>PathsWithAllowedProcesses</string>
///     <key>EnableSilentMode</key>
///     <true/>
///     <key>EnableSilentTTYMode</key>
///     <true/>
///     <key>BlockMessage</key>
///     <string>...</string>
///     <key>EventDetailURL</key>
///     <string>...</string>
///     <key>EventDetailText</key>
///     <string>...</string>
///   </dict>
///   <key>Processes</key>
///   <array>
///   ... See VerifyConfigWatchItemProcesses for more details ...
///   </array>
/// </dict>
bool ParseConfigSingleWatchItem(NSString *name, std::string_view policy_version,
                                NSDictionary *watch_item,
                                SetSharedDataWatchItemPolicy &data_policies,
                                SetSharedProcessWatchItemPolicy &proc_policies, NSError **err) {
  if (!VerifyConfigKey(watch_item, kWatchItemConfigKeyPaths, [NSArray class], err, true)) {
    return false;
  }

  std::variant<Unit, SetPairPathAndType> path_list =
      VerifyConfigWatchItemPaths(watch_item[kWatchItemConfigKeyPaths], err);

  if (std::holds_alternative<Unit>(path_list)) {
    return false;
  }

  if (!VerifyConfigKey(watch_item, kWatchItemConfigKeyOptions, [NSDictionary class], err)) {
    return false;
  }

  NSDictionary *options = watch_item[kWatchItemConfigKeyOptions];
  if (options) {
    NSArray<NSString *> *boolOptions = @[
      kWatchItemConfigKeyOptionsAllowReadAccess,
      kWatchItemConfigKeyOptionsAuditOnly,
      kWatchItemConfigKeyOptionsInvertProcessExceptions,
      kWatchItemConfigKeyOptionsEnableSilentMode,
      kWatchItemConfigKeyOptionsEnableSilentTTYMode,
    ];

    for (NSString *key in boolOptions) {
      if (!VerifyConfigKey(options, key, [NSNumber class], err)) {
        return false;
      }
    }

    if (!VerifyConfigKey(options, kWatchItemConfigKeyOptionsRuleType, [NSString class], err, false,
                         ValidValuesValidator<WatchItemRuleType>(GetRuleType))) {
      return false;
    }

    if (!VerifyConfigKey(options, kWatchItemConfigKeyOptionsCustomMessage, [NSString class], err,
                         false,
                         LenRangeValidator(0, kWatchItemConfigOptionCustomMessageMaxLength))) {
      return false;
    }

    if (!VerifyConfigKey(options, kWatchItemConfigKeyOptionsEventDetailURL, [NSString class], err,
                         false, LenRangeValidator(0, kWatchItemConfigEventDetailURLMaxLength))) {
      return false;
    }

    if (!VerifyConfigKey(options, kWatchItemConfigKeyOptionsEventDetailText, [NSString class], err,
                         false, LenRangeValidator(0, kWatchItemConfigEventDetailTextMaxLength))) {
      return false;
    }
  }

  bool allow_read_access = GetBoolValue(options, kWatchItemConfigKeyOptionsAllowReadAccess,
                                        kWatchItemPolicyDefaultAllowReadAccess);
  bool audit_only =
      GetBoolValue(options, kWatchItemConfigKeyOptionsAuditOnly, kWatchItemPolicyDefaultAuditOnly);
  bool enable_silent_mode = GetBoolValue(options, kWatchItemConfigKeyOptionsEnableSilentMode,
                                         kWatchItemPolicyDefaultEnableSilentMode);
  bool enable_silent_tty_mode = GetBoolValue(options, kWatchItemConfigKeyOptionsEnableSilentTTYMode,
                                             kWatchItemPolicyDefaultEnableSilentTTYMode);

  std::variant<Unit, SetWatchItemProcess> proc_list =
      VerifyConfigWatchItemProcesses(watch_item, err);
  if (std::holds_alternative<Unit>(proc_list)) {
    return false;
  }

  WatchItemRuleType rule_type = kWatchItemPolicyDefaultRuleType;
  if (options[kWatchItemConfigKeyOptionsRuleType]) {
    rule_type = GetRuleType(options[kWatchItemConfigKeyOptionsRuleType])
                    .value_or(kWatchItemPolicyDefaultRuleType);
  } else if (options[kWatchItemConfigKeyOptionsInvertProcessExceptions]) {
    // Convert deprecated config option to the new WatchItemRuleType option
    if ([options[kWatchItemConfigKeyOptionsInvertProcessExceptions] boolValue]) {
      rule_type = WatchItemRuleType::kPathsWithDeniedProcesses;
    } else {
      rule_type = WatchItemRuleType::kPathsWithAllowedProcesses;
    }
  }

  switch (rule_type) {
    case WatchItemRuleType::kPathsWithAllowedProcesses: [[fallthrough]];
    case WatchItemRuleType::kPathsWithDeniedProcesses:
      for (const PairPathAndType &path_type_pair : std::get<SetPairPathAndType>(path_list)) {
        data_policies.insert(std::make_shared<DataWatchItemPolicy>(
            NSStringToUTF8StringView(name), policy_version, path_type_pair.first,
            path_type_pair.second, allow_read_access, audit_only, rule_type, enable_silent_mode,
            enable_silent_tty_mode,
            NSStringToUTF8StringView(options[kWatchItemConfigKeyOptionsCustomMessage]),
            options[kWatchItemConfigKeyOptionsEventDetailURL],
            options[kWatchItemConfigKeyOptionsEventDetailText],
            std::get<SetWatchItemProcess>(proc_list)));
      }

      break;

    case WatchItemRuleType::kProcessesWithAllowedPaths: [[fallthrough]];
    case WatchItemRuleType::kProcessesWithDeniedPaths:
      proc_policies.insert(std::make_shared<ProcessWatchItemPolicy>(
          NSStringToUTF8StringView(name), policy_version, std::get<SetPairPathAndType>(path_list),
          allow_read_access, audit_only, rule_type, enable_silent_mode, enable_silent_tty_mode,
          NSStringToUTF8StringView(options[kWatchItemConfigKeyOptionsCustomMessage]),
          options[kWatchItemConfigKeyOptionsEventDetailURL],
          options[kWatchItemConfigKeyOptionsEventDetailText],
          std::get<SetWatchItemProcess>(proc_list)));

      break;
  }

  return true;
}

bool IsWatchItemNameValid(NSString *watch_item_name, NSError **err) {
  if (!watch_item_name) {
    // This shouldn't be possible as written, but handle just in case
    [SNTError populateError:err withFormat:@"nil watch item name"];
    return false;
  }

  static dispatch_once_t once_token;
  static NSRegularExpression *regex;

  dispatch_once(&once_token, ^{
    // Should only match legal C identifiers
    regex = [NSRegularExpression regularExpressionWithPattern:@"^[A-Za-z_][A-Za-z0-9_]*$"
                                                      options:0
                                                        error:nil];
  });

  if ([regex numberOfMatchesInString:watch_item_name
                             options:0
                               range:NSMakeRange(0, watch_item_name.length)] != 1) {
    [SNTError populateError:err
                 withFormat:@"Key name must match regular expression \"%@\"", regex.pattern];
    return false;
  }

  return true;
}

bool ParseConfig(NSDictionary *config, SetSharedDataWatchItemPolicy &data_policies,
                 SetSharedProcessWatchItemPolicy &proc_policies, NSError **err) {
  if (![config[kWatchItemConfigKeyVersion] isKindOfClass:[NSString class]]) {
    [SNTError populateError:err
                 withFormat:@"Missing top level string key '%@'", kWatchItemConfigKeyVersion];
    return false;
  }

  if ([(NSString *)config[kWatchItemConfigKeyVersion] length] == 0) {
    [SNTError populateError:err
                 withFormat:@"Top level key '%@' has empty value", kWatchItemConfigKeyVersion];
    return false;
  }

  if (!VerifyConfigKey(config, kWatchItemConfigKeyEventDetailURL, [NSString class], err, false,
                       LenRangeValidator(0, kWatchItemConfigEventDetailURLMaxLength))) {
    return false;
  }

  if (!VerifyConfigKey(config, kWatchItemConfigKeyEventDetailText, [NSString class], err, false,
                       LenRangeValidator(0, kWatchItemConfigEventDetailTextMaxLength))) {
    return false;
  }

  if (config[kWatchItemConfigKeyWatchItems] &&
      ![config[kWatchItemConfigKeyWatchItems] isKindOfClass:[NSDictionary class]]) {
    [SNTError
        populateError:err
           withFormat:@"Top level key '%@' must be a dictionary", kWatchItemConfigKeyWatchItems];
    return false;
  }

  NSDictionary *watch_items = config[kWatchItemConfigKeyWatchItems];
  std::string policy_version = NSStringToUTF8String(config[kWatchItemConfigKeyVersion]);

  for (id key in watch_items) {
    if (![key isKindOfClass:[NSString class]]) {
      [SNTError populateError:err
                   withFormat:@"Invalid %@ key %@: Expected type '%@' (got: %@)",
                              kWatchItemConfigKeyWatchItems, key,
                              NSStringFromClass([NSString class]), NSStringFromClass([key class])];
      return false;
    }

    if (!IsWatchItemNameValid((NSString *)key, err)) {
      [SNTError populateError:err
                   withFormat:@"Invalid %@ key '%@': %@", kWatchItemConfigKeyWatchItems, key,
                              (err && *err) ? (*err).localizedDescription : @"Unknown failure"];
      return false;
    }

    if (![watch_items[key] isKindOfClass:[NSDictionary class]]) {
      [SNTError populateError:err
                   withFormat:@"Value type for watch item '%@' must be a dictionary (got %@)", key,
                              NSStringFromClass([watch_items[key] class])];
      return false;
    }

    if (!ParseConfigSingleWatchItem(key, policy_version, watch_items[key], data_policies,
                                    proc_policies, err)) {
      [SNTError populateError:err
                   withFormat:@"In watch item '%@': %@", key,
                              (err && *err) ? (*err).localizedDescription : @"Unknown failure"];
      return false;
    }
  }

  return true;
}

#pragma mark DataWatchItems

SetPairPathAndType DataWatchItems::operator-(const DataWatchItems &other) const {
  // NB: std::set_difference requires the container is ordered. Use a simple
  // loop here instead since our data is unordered.
  SetPairPathAndType diff;
  for (const auto &p : paths_) {
    if (other.paths_.find(p) == other.paths_.end()) {
      diff.insert(p);
    }
  }
  return diff;
}

bool DataWatchItems::Build(SetSharedDataWatchItemPolicy data_policies) {
  for (const std::shared_ptr<DataWatchItemPolicy> &item : data_policies) {
    std::vector<std::string> matches = FindMatches(@(item->path.c_str()));

    for (const auto &match : matches) {
      if (item->path_type == WatchItemPathType::kPrefix) {
        tree_->InsertPrefix(match.c_str(), item);
      } else {
        tree_->InsertLiteral(match.c_str(), item);
      }

      paths_.insert({match.c_str(), item->path_type});
    }
  }

  return true;
}

void DataWatchItems::FindPolicies(IterateTargetsBlock iterateTargetsBlock) const {
  iterateTargetsBlock(
      ^std::optional<std::shared_ptr<WatchItemPolicyBase>>(const std::string &path) {
        return tree_->LookupLongestMatchingPrefix(path);
      });
}

#pragma mark ProcessWatchItems

bool ProcessWatchItems::Build(SetSharedProcessWatchItemPolicy proc_policies) {
  policies_ = std::move(proc_policies);
  return true;
}

void ProcessWatchItems::IterateProcessPolicies(CheckPolicyBlock checkPolicyBlock) {
  for (const auto &p : policies_) {
    bool stop = checkPolicyBlock(p);
    if (stop) {
      break;
    }
  }
}

#pragma mark WatchItems

std::shared_ptr<WatchItems> WatchItems::Create(NSString *config_path,
                                               uint64_t reapply_config_frequency_secs) {
  return CreateInternal(config_path, nil, reapply_config_frequency_secs);
}

std::shared_ptr<WatchItems> WatchItems::Create(NSDictionary *config,
                                               uint64_t reapply_config_frequency_secs) {
  return CreateInternal(nil, config, reapply_config_frequency_secs);
}

std::shared_ptr<WatchItems> WatchItems::CreateInternal(NSString *config_path, NSDictionary *config,
                                                       uint64_t reapply_config_frequency_secs) {
  if (reapply_config_frequency_secs < kMinReapplyConfigFrequencySecs) {
    LOGW(@"Invalid watch item update interval provided: %llu. Min allowed: %llu",
         reapply_config_frequency_secs, kMinReapplyConfigFrequencySecs);
    return nullptr;
  }

  if (config_path && config) {
    LOGW(@"Invalid arguments creating WatchItems - both config and config_path cannot be set.");
    return nullptr;
  }

  dispatch_queue_t q = dispatch_queue_create("com.northpolesec.santa.daemon.watch_items.q",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
  dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_SEC * reapply_config_frequency_secs, 0);

  if (config_path) {
    return std::make_shared<WatchItems>(config_path, q, timer_source);
  } else {
    return std::make_shared<WatchItems>(config, q, timer_source);
  }
}

WatchItems::WatchItems(NSString *config_path, dispatch_queue_t q, dispatch_source_t timer_source,
                       void (^periodic_task_complete_f)(void))
    : config_path_(config_path),
      embedded_config_(nil),
      q_(q),
      timer_source_(timer_source),
      periodic_task_complete_f_(periodic_task_complete_f) {}

WatchItems::WatchItems(NSDictionary *config, dispatch_queue_t q, dispatch_source_t timer_source,
                       void (^periodic_task_complete_f)(void))
    : config_path_(nil),
      embedded_config_(config),
      q_(q),
      timer_source_(timer_source),
      periodic_task_complete_f_(periodic_task_complete_f) {}

WatchItems::~WatchItems() {
  if (!periodic_task_started_ && timer_source_ != NULL) {
    // The timer_source_ must be resumed to ensure it has a proper retain count before being
    // destroyed. Additionally, it should first be cancelled to ensure the timer isn't ever
    // fired (see man page for `dispatch_source_cancel(3)`).
    dispatch_source_cancel(timer_source_);
    dispatch_resume(timer_source_);
  }
}

void WatchItems::RegisterDataWatchItemsUpdatedCallback(DataWatchItemsUpdatedBlock callback) {
  absl::MutexLock lock(&lock_);
  if (!data_watch_items_updated_callback_) {
    data_watch_items_updated_callback_ = std::move(callback);
  }
}

void WatchItems::RegisterProcWatchItemsUpdatedCallback(ProcWatchItemsUpdatedBlock callback) {
  absl::MutexLock lock(&lock_);
  if (!proc_watch_items_updated_callback_) {
    proc_watch_items_updated_callback_ = std::move(callback);
  }
}

void WatchItems::UpdateCurrentState(DataWatchItems new_data_watch_items,
                                    ProcessWatchItems new_proc_watch_items,
                                    NSDictionary *new_config) {
  absl::MutexLock lock(&lock_);

  // The following conditions require updating the current config:
  // 1. The current config doesn't exist but the new one does
  // 2. The current config exists but the new one doesn't
  // 3. The set of monitored paths changed
  // 4. The configuration changed
  //
  // Note: Because there is not a dynamic component to monitored processes like there is for
  // monitored paths (due to glob expansion), it is sufficient to rely only on detecting changes to
  // the config as that is the only way the set of ProcessWatchItems could change.
  if ((current_config_ != nil && new_config == nil) ||
      (current_config_ == nil && new_config != nil) ||
      (data_watch_items_ != new_data_watch_items) ||
      (new_config && ![current_config_ isEqualToDictionary:new_config])) {
    // New paths to watch are those that are in the new set, but not current
    SetPairPathAndType paths_to_watch = new_data_watch_items - data_watch_items_;
    // Paths to stop watching are in the current set, but not new
    SetPairPathAndType paths_to_stop_watching = data_watch_items_ - new_data_watch_items;

    std::swap(data_watch_items_, new_data_watch_items);
    std::swap(proc_watch_items_, new_proc_watch_items);
    current_config_ = new_config;
    if (new_config) {
      policy_version_ = NSStringToUTF8String(new_config[kWatchItemConfigKeyVersion]);
      // Non-existent kWatchItemConfigKeyEventDetailURL key or zero length value
      // will both result in a nil global policy event detail URL.
      if (((NSString *)new_config[kWatchItemConfigKeyEventDetailURL]).length) {
        policy_event_detail_url_ = new_config[kWatchItemConfigKeyEventDetailURL];
      } else {
        policy_event_detail_url_ = nil;
      }
      policy_event_detail_text_ = new_config[kWatchItemConfigKeyEventDetailText];
    } else {
      policy_version_ = "";
      policy_event_detail_url_ = nil;
      policy_event_detail_text_ = nil;
    }

    last_update_time_ = [[NSDate date] timeIntervalSince1970];

    LOGD(@"Changes to watch items detected, notifying registered clients.");

    if (data_watch_items_updated_callback_) {
      // Note: Enable clients on an async queue in case they perform any
      // synchronous work that could trigger ES events. Otherwise they might
      // trigger AUTH ES events that would attempt to re-enter this object and
      // potentially deadlock.
      dispatch_async(q_, ^{
        data_watch_items_updated_callback_(data_watch_items_.Count(), paths_to_watch,
                                           paths_to_stop_watching);
      });
    }

    if (proc_watch_items_updated_callback_) {
      dispatch_async(q_, ^{
        proc_watch_items_updated_callback_(proc_watch_items_.Count());
      });
    }
  } else {
    LOGD(@"No changes to set of watched paths.");
  }
}

void WatchItems::ReloadConfig(NSDictionary *new_config) {
  DataWatchItems new_data_watch_items;
  ProcessWatchItems new_proc_watch_items;

  if (new_config) {
    SetSharedDataWatchItemPolicy new_data_policies;
    SetSharedProcessWatchItemPolicy new_proc_policies;
    NSError *err;
    if (!ParseConfig(new_config, new_data_policies, new_proc_policies, &err)) {
      LOGE(@"Failed to parse watch item config: %@",
           err ? err.localizedDescription : @"Unknown failure");
      return;
    }

    new_data_watch_items.Build(std::move(new_data_policies));
    new_proc_watch_items.Build(std::move(new_proc_policies));
  }

  UpdateCurrentState(std::move(new_data_watch_items), std::move(new_proc_watch_items), new_config);
}

NSDictionary *WatchItems::ReadConfig() {
  absl::ReaderMutexLock lock(&lock_);
  return ReadConfigLocked();
}

NSDictionary *WatchItems::ReadConfigLocked() {
  if (config_path_) {
    return [NSDictionary dictionaryWithContentsOfFile:config_path_];
  } else {
    return nil;
  }
}

void WatchItems::BeginPeriodicTask() {
  if (periodic_task_started_) {
    return;
  }

  std::weak_ptr<WatchItems> weak_watcher = weak_from_this();
  dispatch_source_set_event_handler(timer_source_, ^{
    std::shared_ptr<WatchItems> shared_watcher = weak_watcher.lock();
    if (!shared_watcher) {
      return;
    }

    shared_watcher->ReloadConfig(embedded_config_ ?: shared_watcher->ReadConfig());

    if (shared_watcher->periodic_task_complete_f_) {
      shared_watcher->periodic_task_complete_f_();
    }
  });

  dispatch_resume(timer_source_);
  periodic_task_started_ = true;
}

void WatchItems::FindPoliciesForTargets(IterateTargetsBlock iterateTargetsBlock) {
  absl::ReaderMutexLock lock(&lock_);
  data_watch_items_.FindPolicies(iterateTargetsBlock);
}

void WatchItems::IterateProcessPolicies(CheckPolicyBlock checkPolicyBlock) {
  absl::ReaderMutexLock lock(&lock_);
  proc_watch_items_.IterateProcessPolicies(checkPolicyBlock);
}

void WatchItems::SetConfigPath(NSString *config_path) {
  // Acquire the lock to set the config path and read the config, but drop
  // the lock before reloading the config
  NSDictionary *config;
  {
    absl::MutexLock lock(&lock_);
    config_path_ = config_path;
    embedded_config_ = nil;
    config = ReadConfigLocked();
  }
  ReloadConfig(config);
}

void WatchItems::SetConfig(NSDictionary *config) {
  {
    absl::MutexLock lock(&lock_);
    config_path_ = nil;
    embedded_config_ = config;
  }
  ReloadConfig(embedded_config_);
}

std::optional<WatchItemsState> WatchItems::State() {
  absl::ReaderMutexLock lock(&lock_);

  if (!current_config_) {
    return std::nullopt;
  }

  WatchItemsState state = {
      .rule_count = [current_config_[kWatchItemConfigKeyWatchItems] count],
      .policy_version = [NSString stringWithUTF8String:policy_version_.c_str()],
      .config_path = [config_path_ copy],
      .last_config_load_epoch = last_update_time_,
  };

  return state;
}

std::pair<NSString *, NSString *> WatchItems::EventDetailLinkInfo(
    const std::shared_ptr<WatchItemPolicyBase> &watch_item) {
  absl::ReaderMutexLock lock(&lock_);
  if (!watch_item) {
    return {policy_event_detail_url_, policy_event_detail_text_};
  }

  NSString *url = watch_item->event_detail_url.has_value() ? watch_item->event_detail_url.value()
                                                           : policy_event_detail_url_;

  NSString *text = watch_item->event_detail_text.has_value() ? watch_item->event_detail_text.value()
                                                             : policy_event_detail_text_;

  // Ensure empty strings are repplaced with nil
  if (!url.length) {
    url = nil;
  }

  if (!text.length) {
    text = nil;
  }

  return {url, text};
}

}  // namespace santa
