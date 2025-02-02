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

#import "Source/common/PrefixTree.h"
#import "Source/common/Unit.h"
#include "absl/container/flat_hash_set.h"

namespace santa {

// Forward declarations
enum class WatchItemPathType;
enum class WatchItemRuleType;
template <typename T>
struct SharedPtrValueHash;
template <typename T>
struct SharedPtrValueEqual;
struct DataWatchItemPolicy;
struct ProcessWatchItemPolicy;
struct WatchItemProcess;

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
  WatchItemProcess(std::string bp, std::string sid, std::string ti, std::vector<uint8_t> cdh,
                   std::string ch, std::optional<bool> pb)
      : binary_path(bp),
        signing_id(sid),
        team_id(ti),
        cdhash(std::move(cdh)),
        certificate_sha256(ch),
        platform_binary(pb) {}

  bool operator==(const WatchItemProcess &other) const {
    return binary_path == other.binary_path && signing_id == other.signing_id &&
           team_id == other.team_id && cdhash == other.cdhash &&
           certificate_sha256 == other.certificate_sha256 &&
           platform_binary.has_value() == other.platform_binary.has_value() &&
           platform_binary == other.platform_binary;
  }

  bool operator!=(const WatchItemProcess &other) const { return !(*this == other); }

  template <typename H>
  friend H AbslHashValue(H h, const WatchItemProcess &p) {
    return H::combine(std::move(h), p.binary_path, p.signing_id, p.team_id, p.cdhash,
                      p.certificate_sha256, p.platform_binary);
  }
  std::string binary_path;
  std::string signing_id;
  std::string team_id;
  std::vector<uint8_t> cdhash;
  std::string certificate_sha256;
  std::optional<bool> platform_binary;
};

struct WatchItemPolicyBase {
  WatchItemPolicyBase(std::string_view n, std::string_view v,
                      bool ara = kWatchItemPolicyDefaultAllowReadAccess,
                      bool ao = kWatchItemPolicyDefaultAuditOnly,
                      WatchItemRuleType rt = kWatchItemPolicyDefaultRuleType,
                      bool esm = kWatchItemPolicyDefaultEnableSilentMode,
                      bool estm = kWatchItemPolicyDefaultEnableSilentTTYMode,
                      std::string_view cm = "", NSString *edu = nil, NSString *edt = nil)
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
        event_detail_text(edt.length == 0 ? std::nullopt : std::make_optional<NSString *>(edt)) {}

  virtual ~WatchItemPolicyBase() = default;

  virtual bool operator==(const WatchItemPolicyBase &other) const {
    // Note: custom_message, event_detail_url, and event_detail_text are not currently considered
    // for equality purposes
    return name == other.name && version == other.version &&
           allow_read_access == other.allow_read_access && audit_only == other.audit_only &&
           rule_type == other.rule_type && silent == other.silent && silent_tty == other.silent_tty;
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
      : WatchItemPolicyBase(n, v, ara, ao, rt, esm, estm, cm, edu, edt),
        path(p),
        path_type(pt),
        processes(std::move(procs)) {}

  bool operator==(const WatchItemPolicyBase &other) const override {
    const DataWatchItemPolicy *otherPolicy = dynamic_cast<const DataWatchItemPolicy *>(&other);
    if (!otherPolicy) {
      return false;
    }

    // Now compare base and derived class attributes
    return WatchItemPolicyBase::operator==(*otherPolicy) && path_type == otherPolicy->path_type &&
           path == otherPolicy->path && processes == otherPolicy->processes;
  }

  bool operator!=(const WatchItemPolicyBase &other) const override { return !(*this == other); }

  std::string path;
  WatchItemPathType path_type;
  SetWatchItemProcess processes;
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
      : WatchItemPolicyBase(n, v, ara, ao, rt, esm, estm, cm, edu, edt),
        path_type_pairs(std::move(pt)),
        processes(std::move(procs)),
        tree(std::make_unique<santa::PrefixTree<santa::Unit>>()) {
    // Build tree
    for (const auto &pt_pair : path_type_pairs) {
      if (pt_pair.second == WatchItemPathType::kPrefix) {
        tree->InsertPrefix(pt_pair.first.c_str(), santa::Unit{});
      } else {
        tree->InsertLiteral(pt_pair.first.c_str(), santa::Unit{});
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
    return WatchItemPolicyBase::operator==(*otherPolicy) && processes == otherPolicy->processes &&
           path_type_pairs == otherPolicy->path_type_pairs;
  }

  bool operator!=(const WatchItemPolicyBase &other) const override { return !(*this == other); }

  SetPairPathAndType path_type_pairs;
  SetWatchItemProcess processes;
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
