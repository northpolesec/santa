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

#ifndef SANTA__COMMON__CONSTRAINEDELEMENTCACHE_H
#define SANTA__COMMON__CONSTRAINEDELEMENTCACHE_H

#include <dispatch/dispatch.h>

#include <memory>

#include "Source/common/SantaCache.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/hash/hash.h"
#include "absl/synchronization/mutex.h"

namespace santa {

/// This is a bespoke cache for mapping some key to a set of values. Both
/// the size of the outer map and inner set size are constrianed by given
/// parameters at time of construction.
template <typename KeyT, typename ValueT, class Hasher = absl::Hash<KeyT>>
class SantaSetCache {
 public:
  using ValueSet = absl::flat_hash_set<ValueT>;
  using SharedValueSet = std::shared_ptr<ValueSet>;
  using SharedConstValueSet = std::shared_ptr<const ValueSet>;

  static std::unique_ptr<SantaSetCache> Create(size_t capacity, size_t per_entry_capacity) {
    return std::make_unique<SantaSetCache>(capacity, per_entry_capacity);
  }

  SantaSetCache(size_t capacity, size_t per_entry_capacity)
      : cache_(capacity), per_entry_capacity_(per_entry_capacity) {}

  // Not copyable
  SantaSetCache(const SantaSetCache &other) = delete;
  SantaSetCache &operator=(const SantaSetCache &other) = delete;

  // Moves could be safe to implement, but not currently needed.
  SantaSetCache(SantaSetCache &&other) = delete;
  SantaSetCache &operator=(SantaSetCache &&rhs) = delete;

  /// Check if the set at the given key contained the given value.
  bool Contains(const KeyT &key, const ValueT &val) {
    return cache_.contains(key, ^bool(const SharedValueSet &set) {
      return set && set->count(val) > 0;
    });
  }

  /// Adds the value to the set contained at given key. The
  /// set is created if one didn't previously exist. If adding
  /// the key causes the cache capacity to overflow, the cache
  /// is cleared. If adding the value to the set causes it to
  /// overflow, it is first cleared.
  /// Return true if the set at the given key contained the
  /// given value. Otherwise false.
  bool Set(const KeyT &key, ValueT val) {
    __block bool did_set = false;
    __block ValueT tmp_val = std::move(val);

    cache_.update(key, ^(SharedValueSet &set) {
      ValueT moved_val = std::move(tmp_val);
      if (!set) {
        set = std::make_shared<ValueSet>();
      }

      // Check if the entry already exists
      if (set->count(moved_val) > 0) {
        did_set = false;
        return;
      }

      // Check if we'll exceed capacity with the new entry
      if (set->size() >= per_entry_capacity_) {
        set->clear();
      }

      set->insert(std::move(moved_val));

      // Value was set, return info to caller
      did_set = true;
    });

    return did_set;
  }

  /// Remove the outer cache entry.
  void Remove(const KeyT &key) { cache_.remove(key); }

  /// Clear the whole cache.
  void Clear() { cache_.clear(); }

  /// Return a shared_ptr of the const set contained at the given key
  /// IMPORTANT: This method should never be called from multithreaded
  /// environments. The returned value can be mutated by other threads.
  SharedConstValueSet UnsafeGet(const KeyT &key) { return cache_.get(key); }

  /// Size of the cache
  size_t Size() { return cache_.count(); }

  /// Size of the underlying set in the cache at the given key
  size_t Size(const KeyT &key) {
    SharedValueSet set = cache_.get(key);
    if (set) {
      return set->size();
    } else {
      return 0;
    }
  }

 private:
  SantaCache<KeyT, SharedValueSet, Hasher> cache_;

  size_t per_entry_capacity_;
};

}  // namespace santa

#endif  // SANTA__COMMON__CONSTRAINEDELEMENTCACHE_H
