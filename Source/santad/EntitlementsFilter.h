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

#ifndef SANTA__SANTAD__ENTITLEMENTSFILTER_H
#define SANTA__SANTAD__ENTITLEMENTSFILTER_H

#import <Foundation/Foundation.h>

#include <memory>
#include <set>
#include <string>

#include "Source/common/PrefixTree.h"
#include "Source/common/Unit.h"
#include "absl/synchronization/mutex.h"

namespace santa {

class EntitlementsFilter {
 public:
  static std::unique_ptr<EntitlementsFilter> Create(NSArray<NSString *> *teamid_filter,
                                                    NSArray<NSString *> *prefix_filter);

  EntitlementsFilter(NSArray<NSString *> *teamid_filter, NSArray<NSString *> *prefix_filter);

  ~EntitlementsFilter() = default;

  // No copies, no moves
  EntitlementsFilter(const EntitlementsFilter &other) = delete;
  EntitlementsFilter &operator=(const EntitlementsFilter &other) = delete;
  EntitlementsFilter(EntitlementsFilter &&other) = delete;
  EntitlementsFilter &operator=(EntitlementsFilter &&rhs) = delete;

  // Filter out given information based on current state of the filter configuration.
  NSDictionary *Filter(const char *teamID, NSDictionary *entitlements);

  // Update TeamID/Prefix filters based on configuration changes.
  void UpdateTeamIDFilter(NSArray<NSString *> *filter);
  void UpdatePrefixFilter(NSArray<NSString *> *filter);

 private:
  void UpdateTeamIDFilterLocked(NSArray<NSString *> *filter) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);
  void UpdatePrefixFilterLocked(NSArray<NSString *> *filter) ABSL_EXCLUSIVE_LOCKS_REQUIRED(lock_);

  std::set<std::string> teamid_filter_ ABSL_GUARDED_BY(lock_);
  santa::PrefixTree<santa::Unit> prefix_filter_ ABSL_GUARDED_BY(lock_);
  absl::Mutex lock_;
};

}  // namespace santa

#endif  // SANTA__COMMON__ENTITLEMENTSFILTER_H
