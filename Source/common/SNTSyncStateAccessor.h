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

#import <Foundation/Foundation.h>

///
///  Wrapper class for sync state that transparently handles override precedence.
///
///  This class provides dictionary-like access to sync state values while automatically
///  checking for DEBUG-only overrides first. When accessing a value via subscript syntax,
///  the accessor checks the overrides dictionary first, then falls back to the sync state.
///
///  This allows sync state overrides to maintain precedence over sync server values without
///  requiring modifications to existing code that accesses sync state.
///
///  Example:
///    SNTSyncStateAccessor *accessor = [[SNTSyncStateAccessor alloc]
///        initWithSyncState:@{@"EnableBundles": @YES}
///                overrides:@{@"ClientMode": @1}];
///
///    NSNumber *mode = accessor[@"ClientMode"];  // Returns @1 from overrides
///    NSNumber *bundles = accessor[@"EnableBundles"];  // Returns @YES from sync state
///
@interface SNTSyncStateAccessor : NSObject

///
///  Designated initializer.
///
///  @param syncState The sync state dictionary from the sync server
///  @param overrides The override dictionary from sync-state-overrides.plist (DEBUG only)
///
- (instancetype)initWithSyncState:(NSDictionary *)syncState
                        overrides:(NSDictionary *)overrides;

///
///  Dictionary-like access via subscript syntax. Enables `accessor[key]` usage.
///
///  @param key The sync state key to look up
///  @return The value from overrides if present, otherwise from sync state, or nil
///
- (id)objectForKeyedSubscript:(NSString *)key;

///
///  Dictionary-like access via traditional method. Equivalent to objectForKeyedSubscript:.
///
///  @param key The sync state key to look up
///  @return The value from overrides if present, otherwise from sync state, or nil
///
- (id)objectForKey:(NSString *)key;

///
///  Returns the count of unique keys across both dictionaries.
///
- (NSUInteger)count;

///
///  Returns all keys from both sync state and overrides (deduplicated).
///
- (NSArray *)allKeys;

///
///  Returns the underlying sync state dictionary (does not include overrides).
///  Used for persisting sync state to disk.
///
@property(readonly, nonatomic) NSDictionary *underlyingSyncState;

///
///  Returns the underlying overrides dictionary (DEBUG only).
///  Used for debugging and file watching.
///
@property(readonly, nonatomic) NSDictionary *underlyingOverrides;

///
///  Updates a value in the sync state dictionary (not overrides).
///  This is called when the sync server updates a value.
///
///  @param value The new value to set
///  @param key The sync state key to update
///
- (void)updateSyncStateValue:(id)value forKey:(NSString *)key;

///
///  Replaces all overrides with a new dictionary.
///  This is called when the sync-state-overrides.plist file changes.
///
///  @param newOverrides The new overrides dictionary
///
- (void)replaceAllOverrides:(NSDictionary *)newOverrides;

@end
