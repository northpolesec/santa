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

#ifndef SANTA__SANTAD__DATALAYER_WATCHITEMS_H
#define SANTA__SANTAD__DATALAYER_WATCHITEMS_H

#include <CommonCrypto/CommonDigest.h>
#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <array>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "Source/common/PrefixTree.h"
#include "Source/santad/DataLayer/WatchItemPolicy.h"
#import "Source/santad/EventProviders/SNTEndpointSecurityEventHandler.h"
#include "absl/container/flat_hash_set.h"

extern NSString *const kWatchItemConfigKeyVersion;
extern NSString *const kWatchItemConfigKeyWatchItems;
extern NSString *const kWatchItemConfigKeyPaths;
extern NSString *const kWatchItemConfigKeyPathsPath;
extern NSString *const kWatchItemConfigKeyPathsIsPrefix;
extern NSString *const kWatchItemConfigKeyOptions;
extern NSString *const kWatchItemConfigKeyOptionsAllowReadAccess;
extern NSString *const kWatchItemConfigKeyOptionsAuditOnly;
extern NSString *const kWatchItemConfigKeyOptionsInvertProcessExceptions;
extern NSString *const kWatchItemConfigKeyOptionsRuleType;
extern NSString *const kWatchItemConfigKeyOptionsEnableSilentMode;
extern NSString *const kWatchItemConfigKeyOptionsEnableSilentTTYMode;
extern NSString *const kWatchItemConfigKeyOptionsCustomMessage;
extern NSString *const kWatchItemConfigKeyProcesses;
extern NSString *const kWatchItemConfigKeyProcessesBinaryPath;
extern NSString *const kWatchItemConfigKeyProcessesCertificateSha256;
extern NSString *const kWatchItemConfigKeyProcessesSigningID;
extern NSString *const kWatchItemConfigKeyProcessesTeamID;
extern NSString *const kWatchItemConfigKeyProcessesCDHash;
extern NSString *const kWatchItemConfigKeyProcessesPlatformBinary;

namespace santa {

// Forward declarations
class ProcessWatchItems;
class WatchItemsPeer;

// Type aliases
// Implementations that call IterateProcessPoliciesBlock must provide a block
// of type CheckPolicyBlock. The CheckPolicyBlock should return `true` if the
// iteration should stop, or `false` if iteration should continue to the next
// process policy.
using CheckPolicyBlock = bool (^)(std::shared_ptr<ProcessWatchItemPolicy>);
using IterateProcessPoliciesBlock = void (^)(CheckPolicyBlock);

struct WatchItemsState {
  uint64_t rule_count;
  NSString *policy_version;
  NSString *config_path;
  NSTimeInterval last_config_load_epoch;
};

class DataWatchItems {
 public:
  DataWatchItems()
      : tree_(std::make_unique<santa::PrefixTree<std::shared_ptr<DataWatchItemPolicy>>>()) {}

  DataWatchItems(DataWatchItems &&other) = default;
  DataWatchItems &operator=(DataWatchItems &&rhs) = default;

  // Copying not supported
  DataWatchItems(const DataWatchItems &other) = delete;
  DataWatchItems &operator=(const DataWatchItems &other) = delete;

  bool operator==(const DataWatchItems &other) const { return paths_ == other.paths_; }
  bool operator!=(const DataWatchItems &other) const { return !(*this == other); }
  SetPairPathAndType operator-(const DataWatchItems &other) const;

  friend void swap(DataWatchItems &first, DataWatchItems &second) {
    std::swap(first.tree_, second.tree_);
    std::swap(first.paths_, second.paths_);
  }

  bool Build(SetSharedDataWatchItemPolicy data_policies);
  size_t Count() const { return paths_.size(); }

  std::vector<std::optional<std::shared_ptr<DataWatchItemPolicy>>> FindPolcies(
      const std::vector<std::string_view> &paths) const;

 private:
  std::unique_ptr<santa::PrefixTree<std::shared_ptr<DataWatchItemPolicy>>> tree_;
  SetPairPathAndType paths_;
};

class ProcessWatchItems {
 public:
  ProcessWatchItems() = default;

  ProcessWatchItems(ProcessWatchItems &&other) = default;
  ProcessWatchItems &operator=(ProcessWatchItems &&rhs) = default;

  // Copying not supported
  ProcessWatchItems(const ProcessWatchItems &other) = delete;
  ProcessWatchItems &operator=(const ProcessWatchItems &other) = delete;

  bool operator==(const ProcessWatchItems &other) const { return policies_ == other.policies_; }
  bool operator!=(const ProcessWatchItems &other) const { return !(*this == other); }

  bool Build(SetSharedProcessWatchItemPolicy proc_policies);

  size_t Count() const { return policies_.size(); }
  void IterateProcessPolicies(CheckPolicyBlock checkPolicyBlock);

 private:
  SetSharedProcessWatchItemPolicy policies_;
};

class WatchItems : public std::enable_shared_from_this<WatchItems> {
 public:
  using VersionAndPolicies =
      std::pair<std::string, std::vector<std::optional<std::shared_ptr<DataWatchItemPolicy>>>>;

  // Factory methods
  static std::shared_ptr<WatchItems> Create(NSString *config_path,
                                            uint64_t reapply_config_frequency_secs);
  static std::shared_ptr<WatchItems> Create(NSDictionary *config,
                                            uint64_t reapply_config_frequency_secs);

  WatchItems(NSString *config_path, dispatch_queue_t q, dispatch_source_t timer_source,
             void (^periodic_task_complete_f)(void) = nullptr);
  WatchItems(NSDictionary *config, dispatch_queue_t q, dispatch_source_t timer_source,
             void (^periodic_task_complete_f)(void) = nullptr);

  ~WatchItems();

  void BeginPeriodicTask();

  void RegisterDataClient(id<SNTDataFileAccessAuthorizer> client);
  void RegisterProcessClient(id<SNTProcessFileAccessAuthorizer> client);

  void SetConfigPath(NSString *config_path);
  void SetConfig(NSDictionary *config);

  VersionAndPolicies FindPolciesForPaths(const std::vector<std::string_view> &paths);
  void IterateProcessPolicies(CheckPolicyBlock checkPolicyBlock);

  std::optional<WatchItemsState> State();

  std::pair<NSString *, NSString *> EventDetailLinkInfo(
      const std::shared_ptr<DataWatchItemPolicy> &watch_item);

  friend class santa::WatchItemsPeer;

 private:
  static std::shared_ptr<WatchItems> CreateInternal(NSString *config_path, NSDictionary *config,
                                                    uint64_t reapply_config_frequency_secs);

  NSDictionary *ReadConfig();
  NSDictionary *ReadConfigLocked() ABSL_SHARED_LOCKS_REQUIRED(lock_);
  void ReloadConfig(NSDictionary *new_config);
  void UpdateCurrentState(DataWatchItems new_data_watch_items,
                          ProcessWatchItems new_proc_watch_items, NSDictionary *new_config);

  NSString *config_path_;
  NSDictionary *embedded_config_;
  dispatch_queue_t q_;
  dispatch_source_t timer_source_;
  void (^periodic_task_complete_f_)(void);

  absl::Mutex lock_;

  DataWatchItems data_watch_items_ ABSL_GUARDED_BY(lock_);
  ProcessWatchItems proc_watch_items_ ABSL_GUARDED_BY(lock_);
  NSDictionary *current_config_ ABSL_GUARDED_BY(lock_);
  NSTimeInterval last_update_time_ ABSL_GUARDED_BY(lock_);
  std::string policy_version_ ABSL_GUARDED_BY(lock_);
  id<SNTDataFileAccessAuthorizer> registered_data_client_ ABSL_GUARDED_BY(lock_);
  id<SNTProcessFileAccessAuthorizer> registered_proc_client_ ABSL_GUARDED_BY(lock_);
  bool periodic_task_started_ = false;
  NSString *policy_event_detail_url_ ABSL_GUARDED_BY(lock_);
  NSString *policy_event_detail_text_ ABSL_GUARDED_BY(lock_);
};

}  // namespace santa

#endif
