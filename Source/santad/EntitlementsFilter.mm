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

#include "Source/santad/EntitlementsFilter.h"

#include "Source/common/PrefixTree.h"
#import "Source/common/SNTDeepCopy.h"
#include "Source/common/String.h"

namespace santa {

std::unique_ptr<EntitlementsFilter> EntitlementsFilter::Create(NSArray<NSString *> *teamid_filter,
                                                               NSArray<NSString *> *prefix_filter) {
  return std::make_unique<EntitlementsFilter>(teamid_filter, prefix_filter);
}

EntitlementsFilter::EntitlementsFilter(NSArray<NSString *> *teamid_filter,
                                       NSArray<NSString *> *prefix_filter) {
  UpdateTeamIDFilterLocked(teamid_filter);
  UpdatePrefixFilterLocked(prefix_filter);
}

NSDictionary *EntitlementsFilter::Filter(const char *teamID, NSDictionary *entitlements) {
  if (!entitlements) {
    return nil;
  }

  absl::ReaderMutexLock lock(&lock_);

  if (teamID && teamid_filter_.count(std::string(teamID)) > 0) {
    // Dropping entitlement logging for configured TeamID
    return nil;
  }

  if (prefix_filter_.NodeCount() == 0) {
    // No prefix filter exists, copying full entitlements
    return [entitlements sntDeepCopy];
  } else {
    // Filtering entitlements based on prefixes
    NSMutableDictionary *filtered = [NSMutableDictionary dictionary];

    [entitlements enumerateKeysAndObjectsUsingBlock:^(NSString *key, id obj, BOOL *stop) {
      if (!prefix_filter_.HasPrefix(key.UTF8String)) {
        if ([obj isKindOfClass:[NSArray class]] || [obj isKindOfClass:[NSDictionary class]]) {
          [filtered setObject:[obj sntDeepCopy] forKey:key];
        } else {
          [filtered setObject:[obj copy] forKey:key];
        }
      }
    }];

    return filtered.count > 0 ? filtered : nil;
  }
}

void EntitlementsFilter::UpdateTeamIDFilter(NSArray<NSString *> *filter) {
  absl::MutexLock lock(&lock_);
  UpdateTeamIDFilterLocked(filter);
}

void EntitlementsFilter::UpdateTeamIDFilterLocked(NSArray<NSString *> *filter) {
  teamid_filter_.clear();

  for (NSString *prefix in filter) {
    teamid_filter_.insert(NSStringToUTF8String(prefix));
  }
}

void EntitlementsFilter::UpdatePrefixFilter(NSArray<NSString *> *filter) {
  absl::MutexLock lock(&lock_);
  UpdatePrefixFilterLocked(filter);
}

void EntitlementsFilter::UpdatePrefixFilterLocked(NSArray<NSString *> *filter) {
  prefix_filter_.Reset();

  for (NSString *item in filter) {
    prefix_filter_.InsertPrefix(item.UTF8String, Unit{});
  }
}

}  // namespace santa
