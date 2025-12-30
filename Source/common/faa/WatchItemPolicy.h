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

#ifndef SANTA__SANTAD__DATALAYER_WATCHITEMPOLICY_H
#define SANTA__SANTAD__DATALAYER_WATCHITEMPOLICY_H

#import <Foundation/Foundation.h>
#include <Kernel/kern/cs_blobs.h>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "Source/common/CodeSigningIdentifierUtils.h"
#import "Source/common/Glob.h"
#import "Source/common/PrefixTree.h"
#import "Source/common/SNTError.h"
#import "Source/common/String.h"
#import "Source/common/Unit.h"
#include "absl/container/flat_hash_set.h"

namespace santa {

// Forward declarations
enum class WatchItemPathType;
enum class WatchItemRuleType;
struct DataWatchItemPolicy;
struct ProcessWatchItemPolicy;
struct WatchItemProcess;

template <typename T>
struct SharedPtrValueHash;
template <typename T>
struct SharedPtrValueEqual;

// Helper type aliases
using PairPathAndType = std::pair<std::string, WatchItemPathType>;
using SetPairPathAndType = absl::flat_hash_set<PairPathAndType>;
using SetWatchItemProcess = absl::flat_hash_set<WatchItemProcess>;
using SetSharedDataWatchItemPolicy = absl::flat_hash_set<std::shared_ptr<DataWatchItemPolicy>,
                                                         SharedPtrValueHash<DataWatchItemPolicy>,
                                                         SharedPtrValueEqual<DataWatchItemPolicy>>;
using SetSharedProcessWatchItemPolicy =
    absl::flat_hash_set<std::shared_ptr<ProcessWatchItemPolicy>,
                        SharedPtrValueHash<ProcessWatchItemPolicy>,
                        SharedPtrValueEqual<ProcessWatchItemPolicy>>;

enum class WatchItemPathType {
  kPrefix,
  kLiteral,
};

enum class WatchItemRuleType {
  kPathsWithAllowedProcesses,
  kPathsWithDeniedProcesses,
  kProcessesWithAllowedPaths,
  kProcessesWithDeniedPaths,
};

static constexpr WatchItemPathType kWatchItemPolicyDefaultPathType = WatchItemPathType::kLiteral;
static constexpr bool kWatchItemPolicyDefaultAllowReadAccess = false;
static constexpr bool kWatchItemPolicyDefaultAuditOnly = true;
static constexpr WatchItemRuleType kWatchItemPolicyDefaultRuleType =
    WatchItemRuleType::kPathsWithAllowedProcesses;
static constexpr bool kWatchItemPolicyDefaultEnableSilentMode = false;
static constexpr bool kWatchItemPolicyDefaultEnableSilentTTYMode = false;

struct WatchItemProcess {
  static std::optional<WatchItemProcess> Create(NSString *bp, NSString *sid, NSString *tid,
                                                NSString *cdh, NSString *ch, bool pb,
                                                NSError **error) {
    // Ensure at least one attribute set
    if (!bp && !sid && !tid && !cdh && !ch && !pb) {
      [SNTError populateError:error withFormat:@"No valid attributes set in process dictionary"];
      return std::nullopt;
    }

    // Both PlatformBinary and TeamID cannot be set, unless the TID is "platform"
    if (pb && tid.length > 0 && ![[tid lowercaseString] isEqualToString:kPlatformTeamID]) {
      [SNTError populateError:error
                   withFormat:@"Both PlatformBinary and TeamID attributes cannot be set"];
      return std::nullopt;
    }

    // If a SigningID is supplied, and neither TeamID nor PlatformBinary
    // are specified, attempt to extract the TID from the SID value.
    if (sid.length > 0 && (!pb && tid.length == 0)) {
      // Expected format "TID:SID". Lengh of TID is 10 (or the hardcoded
      // value "platform"). We require 2 extra characters for a colon and
      // a SID of at least length 1.
      if (sid.length > (kTeamIDLength + 1) && [sid characterAtIndex:kTeamIDLength] == ':') {
        tid = [sid substringToIndex:kTeamIDLength];
        sid = [sid substringFromIndex:kTeamIDLength + 1];
      } else if (sid.length > kPlatformTeamID.length + 1 &&
                 [sid characterAtIndex:kPlatformTeamID.length] == ':' &&
                 [[sid lowercaseString] hasPrefix:kPlatformTeamID]) {
        tid = [sid substringToIndex:kPlatformTeamID.length];
        sid = [sid substringFromIndex:kPlatformTeamID.length + 1];
      } else {
        // If an SID is specified but no TID/PB is specified, it is an
        // error if the TID cannot be extracted.
        [SNTError populateError:error
                     withFormat:@"A SigningID attribute was specified, but no TeamID was provided"];
        return std::nullopt;
      }
    }

    if ([[tid lowercaseString] isEqualToString:@"platform"]) {
      tid = nil;
      pb = true;
    }

    std::string sid_str = NSStringToUTF8String(sid ?: @"");
    size_t wildcard_pos = sid_str.find('*');

    return WatchItemProcess(NSStringToUTF8String(bp ?: @""), std::move(sid_str),
                            NSStringToUTF8String(tid ?: @""), HexStringToBuf(cdh),
                            NSStringToUTF8String(ch ?: @""), pb, wildcard_pos);
  }

#ifdef DEBUG
  // This interface is intended to only be used by tests
  WatchItemProcess(std::string bp, std::string sid, std::string tid, std::vector<uint8_t> cdh,
                   std::string ch, bool pb)
      : binary_path(bp),
        signing_id(sid),
        team_id(tid),
        cdhash(std::move(cdh)),
        certificate_sha256(ch),
        platform_binary(pb) {
    signing_id_wildcard_pos = signing_id.find('*');
  }
#endif

  bool operator==(const WatchItemProcess &other) const {
    return binary_path == other.binary_path && signing_id == other.signing_id &&
           team_id == other.team_id && cdhash == other.cdhash &&
           certificate_sha256 == other.certificate_sha256 &&
           platform_binary == other.platform_binary;
  }

  bool operator!=(const WatchItemProcess &other) const { return !(*this == other); }

#ifdef DEBUG
  /// This interface should only be used for testing
  void UnsafeUpdateSigningId(std::string new_signing_id) {
    const std::string &ref_sid = signing_id;
    const_cast<std::string &>(ref_sid) = new_signing_id;
    signing_id_wildcard_pos = signing_id.find('*');
  }
#endif

  template <typename H>
  friend H AbslHashValue(H h, const WatchItemProcess &p) {
    return H::combine(std::move(h), p.binary_path, p.signing_id, p.team_id, p.cdhash,
                      p.certificate_sha256, p.platform_binary);
  }

  std::string binary_path;
  const std::string signing_id;
  std::string team_id;
  std::vector<uint8_t> cdhash;
  std::string certificate_sha256;
  bool platform_binary;
  size_t signing_id_wildcard_pos;

 private:
  // This object is intended to be created via the factory method
  WatchItemProcess(std::string bp, std::string sid, std::string tid, std::vector<uint8_t> cdh,
                   std::string ch, bool pb, size_t wc)
      : binary_path(bp),
        signing_id(sid),
        team_id(tid),
        cdhash(std::move(cdh)),
        certificate_sha256(ch),
        platform_binary(pb),
        signing_id_wildcard_pos(wc) {}
};

struct WatchItemPolicyBase {
  WatchItemPolicyBase(std::string_view n, std::string_view v,
                      bool ara = kWatchItemPolicyDefaultAllowReadAccess,
                      bool ao = kWatchItemPolicyDefaultAuditOnly,
                      WatchItemRuleType rt = kWatchItemPolicyDefaultRuleType,
                      bool esm = kWatchItemPolicyDefaultEnableSilentMode,
                      bool estm = kWatchItemPolicyDefaultEnableSilentTTYMode,
                      std::string_view cm = "", NSString *edu = nil, NSString *edt = nil,
                      SetWatchItemProcess procs = {})
      : name(n),
        version(v),
        allow_read_access(ara),
        audit_only(ao),
        rule_type(rt),
        silent(esm),
        silent_tty(estm),
        custom_message(cm.length() == 0 ? std::nullopt : std::make_optional<std::string>(cm)),
        // Note: Empty string considered valid for event_detail_url to allow rules
        // overriding global setting in order to hide the button.
        event_detail_url(edu == nil ? std::nullopt : std::make_optional<NSString *>(edu)),
        event_detail_text(edt.length == 0 ? std::nullopt : std::make_optional<NSString *>(edt)),
        processes(std::move(procs)) {}

  virtual ~WatchItemPolicyBase() = default;

  virtual bool operator==(const WatchItemPolicyBase &other) const {
    // Note: custom_message, event_detail_url, and event_detail_text are not currently considered
    // for equality purposes
    return name == other.name && version == other.version &&
           allow_read_access == other.allow_read_access && audit_only == other.audit_only &&
           rule_type == other.rule_type && silent == other.silent &&
           silent_tty == other.silent_tty && processes == other.processes;
  }

  virtual bool operator!=(const WatchItemPolicyBase &other) const { return !(*this == other); }

  template <typename H>
  friend H AbslHashValue(H h, const WatchItemPolicyBase &p) {
    return H::combine(std::move(h), p.name);
  }

  std::string name;
  std::string version;  // WIP - No current way to control via config
  bool allow_read_access;
  bool audit_only;
  WatchItemRuleType rule_type;
  bool silent;
  bool silent_tty;
  std::optional<std::string> custom_message;
  std::optional<NSString *> event_detail_url;
  std::optional<NSString *> event_detail_text;
  SetWatchItemProcess processes;
};

struct DataWatchItemPolicy : public WatchItemPolicyBase {
  DataWatchItemPolicy(std::string_view n, std::string_view v, std::string_view p,
                      WatchItemPathType pt = kWatchItemPolicyDefaultPathType,
                      bool ara = kWatchItemPolicyDefaultAllowReadAccess,
                      bool ao = kWatchItemPolicyDefaultAuditOnly,
                      WatchItemRuleType rt = kWatchItemPolicyDefaultRuleType,
                      bool esm = kWatchItemPolicyDefaultEnableSilentMode,
                      bool estm = kWatchItemPolicyDefaultEnableSilentTTYMode,
                      std::string_view cm = "", NSString *edu = nil, NSString *edt = nil,
                      SetWatchItemProcess procs = {})
      : WatchItemPolicyBase(n, v, ara, ao, rt, esm, estm, cm, edu, edt, std::move(procs)),
        path(p),
        path_type(pt) {}

  bool operator==(const WatchItemPolicyBase &other) const override {
    const DataWatchItemPolicy *otherPolicy = dynamic_cast<const DataWatchItemPolicy *>(&other);
    if (!otherPolicy) {
      return false;
    }

    // Now compare base and derived class attributes
    return WatchItemPolicyBase::operator==(*otherPolicy) && path_type == otherPolicy->path_type &&
           path == otherPolicy->path;
  }

  bool operator!=(const WatchItemPolicyBase &other) const override { return !(*this == other); }

  std::string path;
  WatchItemPathType path_type;
};

struct ProcessWatchItemPolicy : public WatchItemPolicyBase {
  ProcessWatchItemPolicy(std::string_view n, std::string_view v, SetPairPathAndType pt,
                         bool ara = kWatchItemPolicyDefaultAllowReadAccess,
                         bool ao = kWatchItemPolicyDefaultAuditOnly,
                         WatchItemRuleType rt = kWatchItemPolicyDefaultRuleType,
                         bool esm = kWatchItemPolicyDefaultEnableSilentMode,
                         bool estm = kWatchItemPolicyDefaultEnableSilentTTYMode,
                         std::string_view cm = "", NSString *edu = nil, NSString *edt = nil,
                         SetWatchItemProcess procs = {})
      : WatchItemPolicyBase(n, v, ara, ao, rt, esm, estm, cm, edu, edt, std::move(procs)),
        path_type_pairs(std::move(pt)),
        tree(std::make_unique<santa::PrefixTree<santa::Unit>>()) {
    // Build tree
    for (const auto &pt_pair : path_type_pairs) {
      std::vector<std::string> matches = FindMatches(@(pt_pair.first.c_str()));

      for (const auto &match : matches) {
        if (pt_pair.second == WatchItemPathType::kPrefix) {
          tree->InsertPrefix(match.c_str(), santa::Unit{});
        } else {
          tree->InsertLiteral(match.c_str(), santa::Unit{});
        }
      }
    }
  }

  bool operator==(const WatchItemPolicyBase &other) const override {
    const ProcessWatchItemPolicy *otherPolicy =
        dynamic_cast<const ProcessWatchItemPolicy *>(&other);
    if (!otherPolicy) {
      return false;
    }

    // Now compare base and derived class attributes
    return WatchItemPolicyBase::operator==(*otherPolicy) &&
           path_type_pairs == otherPolicy->path_type_pairs;
  }

  bool operator!=(const WatchItemPolicyBase &other) const override { return !(*this == other); }

  SetPairPathAndType path_type_pairs;
  std::unique_ptr<santa::PrefixTree<Unit>> tree;
};

// Hash and equality call operators for values of shared_ptr types
template <typename T>
struct SharedPtrValueHash {
  std::size_t operator()(const std::shared_ptr<T> &ptr) const { return absl::Hash<T>()(*ptr); }
};

template <typename T>
struct SharedPtrValueEqual {
  bool operator()(const std::shared_ptr<T> &a, const std::shared_ptr<T> &b) const {
    // Handle null pointer cases
    if (!a && !b) return true;
    if (!a || !b) return false;

    // Compare the actual Items contents
    return *a == *b;
  }
};

}  // namespace santa

#endif
