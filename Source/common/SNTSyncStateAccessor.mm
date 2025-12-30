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

#import "Source/common/SNTSyncStateAccessor.h"

@interface SNTSyncStateAccessor ()
@property(atomic) NSDictionary *syncState;
@property(atomic) NSDictionary *overrides;
@end

@implementation SNTSyncStateAccessor

- (instancetype)initWithSyncState:(NSDictionary *)syncState
                        overrides:(NSDictionary *)overrides {
  self = [super init];
  if (self) {
    _syncState = syncState ?: @{};
    _overrides = overrides ?: @{};
  }
  return self;
}

- (id)objectForKeyedSubscript:(NSString *)key {
  return [self objectForKey:key];
}

- (id)objectForKey:(NSString *)key {
  // Check overrides first
  id value = self.overrides[key];
  if (value) {
    return value;
  }

  // Fall back to sync state
  return self.syncState[key];
}

- (NSUInteger)count {
  NSMutableSet *allKeys = [NSMutableSet setWithArray:self.syncState.allKeys];
  [allKeys addObjectsFromArray:self.overrides.allKeys];
  return allKeys.count;
}

- (NSArray *)allKeys {
  NSMutableSet *allKeys = [NSMutableSet setWithArray:self.syncState.allKeys];
  [allKeys addObjectsFromArray:self.overrides.allKeys];
  return allKeys.allObjects;
}

- (NSDictionary *)underlyingSyncState {
  return self.syncState;
}

- (NSDictionary *)underlyingOverrides {
  return self.overrides;
}

- (void)updateSyncStateValue:(id)value forKey:(NSString *)key {
  NSMutableDictionary *newSyncState = self.syncState.mutableCopy;
  if (value) {
    newSyncState[key] = value;
  } else {
    [newSyncState removeObjectForKey:key];
  }
  self.syncState = newSyncState;
}

- (void)replaceAllOverrides:(NSDictionary *)newOverrides {
  self.overrides = newOverrides ?: @{};
}

@end
