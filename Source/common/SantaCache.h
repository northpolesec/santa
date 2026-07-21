/// Copyright 2016-2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA_COMMON_SANTACACHE_H
#define SANTA_COMMON_SANTACACHE_H

#include <os/lock.h>
#include <os/log.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <type_traits>

#include "Source/common/BranchPrediction.h"
#include "absl/hash/hash.h"

/**
  A somewhat simple, concurrent linked-list hash table.

  The type used for keys must overload the == operator and a specialization of
  SantaCacheHasher must exist for it.

  Enforces a maximum size by clearing all entries if a new value
  is added that would go over the maximum size declared at creation.

  The number of buckets is calculated as `maximum_size` / `per_bucket`
  rounded up to the next power of 2. Locking is done per-bucket using
  os_unfair_lock for priority inheritance support.
*/
template <typename KeyT, typename ValueT, class Hasher = absl::Hash<KeyT>>
class SantaCache {
 public:
  /**
    Initialize a newly created cache.

    @param maximum_size The maximum number of entries in this cache. Once this
        number is reached all the entries will be purged.
    @param per_bucket The target number of entries in each bucket when cache is
    full. A higher number will result in better performance but higher memory
    usage. Cannot be higher than 64 to try and ensure buckets don't overflow.
  */
  SantaCache(uint64_t maximum_size = 10000, uint8_t per_bucket = 5) {
    if (unlikely(per_bucket > maximum_size)) per_bucket = (uint8_t)maximum_size;
    if (unlikely(per_bucket < 1)) per_bucket = 1;
    if (unlikely(per_bucket > 64)) per_bucket = 64;
    max_size_ = maximum_size;
    bucket_count_ =
        (1 << (32 -
               __builtin_clz((((uint32_t)max_size_ / per_bucket) - 1) ?: 1)));
    // hash() relies on bucket_count_ being a power of two.
    assert(bucket_count_ > 0 && (bucket_count_ & (bucket_count_ - 1)) == 0);
    buckets_ = (struct bucket*)calloc(bucket_count_, sizeof(struct bucket));
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      buckets_[i].lock = OS_UNFAIR_LOCK_INIT;
    }
  }

  /**
    Clear and free memory
  */
  ~SantaCache() {
    clear();
    free(buckets_);
  }

  /**
    Get an element from the cache. Returns zero_ if item doesn't exist.
  */
  ValueT get(const KeyT& key) const {
    struct bucket* bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry* entry = bucket->head;
    while (entry != nullptr) {
      if (entry->key == key) {
        ValueT val = entry->value;
        unlock(bucket);
        return val;
      }
      entry = entry->next;
    }
    unlock(bucket);
    return zero_;
  }

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
        empty the cache before inserting the new value.

    @param key The key.
    @param value The value with parameterized type.

    @return true if the value was set.
  */
  bool set(const KeyT& key, const ValueT& value) {
    return set(key, value, NoOpUpdate{}, false, {}, false);
  }

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
        empty the cache before inserting the new value.

    @param key The key.
    @param value The value with parameterized type.
    @param previous_value the new value will only be set if this
        parameter is equal to the existing value in the cache.
        This allows set to become a CAS operation.

    @return true if the value was set
  */
  bool set(const KeyT& key, const ValueT& value, const ValueT& previous_value) {
    return set(key, value, NoOpUpdate{}, false, previous_value, true);
  }

  /**
    Update an element in the cache under lock. If the element
        doesn't yet exist, it will be first created and value
        initialized before the update_block is called.

    @note If the cache is full when this is called, this will
        empty the cache before inserting the new value.

    @param key The key.
    @param update_block The block that will be called to give
        the caller the opportunity to update the value.
  */
  template <typename UpdateBlockT>
  bool update(const KeyT& key, UpdateBlockT update_block) {
    static_assert(std::is_invocable_r_v<void, UpdateBlockT, ValueT&>,
                  "update_block must be callable as void(ValueT&)");
    return set(key, zero_, update_block, true, {}, false);
  }

  /**
    Iterate all key and value pairs in the cache.

    @param foreach_block Called for all key and value pairs.
  */
  template <typename ForeachBlockT>
  void foreach(ForeachBlockT foreach_block) {
    static_assert(std::is_invocable_r_v<void, ForeachBlockT, KeyT&, ValueT&>,
                  "foreach_block must be callable as void(KeyT&, ValueT&)");
    // Lock all buckets
    // NB: The clear_bucket_ lock isn't necessary since both foreach and
    // clear methods lock all buckets sequentially from index 0.
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      lock(&buckets_[i]);
    }

    // Operate on all k/v pairs
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct entry* entry = buckets_[i].head;
      while (entry != nullptr) {
        foreach_block(entry->key, entry->value);
        entry = entry->next;
      }
    }

    // Unlock all buckets
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      unlock(&buckets_[i]);
    }
  }

  /**
    An alias for `set(key, zero_)`
  */
  inline void remove(const KeyT& key) { set(key, zero_); }

  /**
    Check if a given key exists in the cache. If a contains_block
        is provided, it allows the caller to further filter for
        specific values while under lock.

    @param key The key.
    @param contains_block Block to be called with the value at the
        given key while under lock.

    @return If the key exists, the result of the call to the
        contains_block, otherwise false.
  */
  template <typename ContainsBlockT>
  bool contains(const KeyT& key, ContainsBlockT contains_block) const {
    static_assert(std::is_invocable_r_v<bool, ContainsBlockT, const ValueT&>,
                  "contains_block must be callable as bool(const ValueT&)");
    struct bucket* bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry* entry = bucket->head;
    while (entry != nullptr) {
      if (entry->key == key) {
        bool result = contains_block(entry->value);
        unlock(bucket);
        return result;
      }
      entry = entry->next;
    }
    unlock(bucket);
    return false;
  }

  /**
    Check if a given key exists in the cache.
  */
  bool contains(const KeyT& key) const {
    return contains(key, [](const ValueT&) { return true; });
  }

  /**
    Remove entries matching a predicate. The predicate receives each key
    and a mutable reference to the value. Return true to remove the entry.

    Buckets are locked one at a time (unlike foreach which locks all),
    so the predicate may safely call methods on other SantaCache instances.

    @warning The predicate MUST NOT call methods on this same SantaCache
        instance. The bucket lock is held during the predicate call, and
        re-entering the same cache would attempt to re-lock the same
        os_unfair_lock, which is undefined behavior.

    @param predicate Called for each entry under its bucket lock.
        Return true to remove the entry.

    @return The number of entries removed.
  */
  template <typename PredicateT>
  uint64_t remove_if(PredicateT predicate) {
    static_assert(std::is_invocable_r_v<bool, PredicateT, const KeyT&, ValueT&>,
                  "predicate must be callable as bool(const KeyT&, ValueT&)");
    uint64_t removed = 0;

    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct bucket* bucket = &buckets_[i];
      lock(bucket);

      struct entry* entry = bucket->head;
      struct entry* prev = nullptr;
      while (entry != nullptr) {
        struct entry* next = entry->next;
        if (predicate(entry->key, entry->value)) {
          if (prev) {
            prev->next = next;
          } else {
            bucket->head = next;
          }
          delete entry;
          count_.fetch_sub(1, std::memory_order_relaxed);
          ++removed;
        } else {
          prev = entry;
        }
        entry = next;
      }

      unlock(bucket);
    }

    return removed;
  }

  /**
    Remove all entries and free bucket memory.

    @param clear_block If not NULL, will be called for all key
        and value pairs just prior to deletion.
  */
  template <typename ClearBlockT>
  void clear(ClearBlockT clear_block) {
    static_assert(std::is_invocable_r_v<void, ClearBlockT, KeyT&, ValueT&>,
                  "clear_block must be callable as void(KeyT&, ValueT&)");
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct bucket* bucket = &buckets_[i];
      // We grab the lock so nothing can use this bucket while we're erasing it.
      lock(bucket);

      // Free the bucket's entries, if there are any.
      struct entry* entry = bucket->head;
      while (entry != nullptr) {
        clear_block(entry->key, entry->value);
        struct entry* next_entry = entry->next;
        delete entry;
        entry = next_entry;
      }
      bucket->head = nullptr;
    }

    // Reset cache count. All bucket locks are held so no concurrent set()
    // can observe a stale count and trigger a redundant clear.
    count_.store(0, std::memory_order_relaxed);

    // Release all bucket locks.
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      unlock(&buckets_[i]);
    }
  }

  /**
    Remove all entries.
  */
  void clear() {
    clear([](KeyT&, ValueT&) {});
  }

  /**
    Return number of entries currently in cache.
  */
  inline uint64_t count() const {
    return count_.load(std::memory_order_relaxed);
  }

  /**
    Fill in the per_bucket_counts array with the number of entries in each
    bucket.

    The per_buckets_count array will contain the per-bucket counts, up to the
    number in array_size. The start_bucket parameter will determine which bucket
    to start off with and upon return will contain either 0 if no buckets are
    remaining or the next bucket to begin with when called again.
  */
  void bucket_counts(uint16_t* per_bucket_counts, uint16_t* array_size,
                     uint64_t* start_bucket) {
    if (per_bucket_counts == nullptr || array_size == nullptr ||
        start_bucket == nullptr)
      return;

    uint64_t start = *start_bucket;
    if (start >= bucket_count_) {
      *start_bucket = 0;
      return;
    }

    uint16_t size = *array_size;
    if (start + size > bucket_count_) size = (uint16_t)(bucket_count_ - start);

    for (uint16_t i = 0; i < size; ++i) {
      uint16_t count = 0;
      struct bucket* bucket = &buckets_[start++];
      lock(bucket);
      struct entry* entry = bucket->head;
      while (entry != nullptr) {
        if (entry->value != zero_) ++count;
        entry = entry->next;
      }
      unlock(bucket);
      per_bucket_counts[i] = count;
    }

    *array_size = size;
    *start_bucket = (start >= bucket_count_) ? 0 : start;
  }

 private:
  struct entry {
    entry(KeyT k) : key(std::move(k)) {}

    KeyT key;
    ValueT value = {};
    struct entry* next = nullptr;
  };

  struct bucket {
    struct entry* head = nullptr;
    os_unfair_lock lock = OS_UNFAIR_LOCK_INIT;
  };

  /**
    Callable placeholder for set() paths that assign a value rather than
    update in place.
  */
  struct NoOpUpdate {
    void operator()(ValueT&) const {}
  };

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
    empty the cache before inserting the new value.

    @param key The key
    @param value The value with parameterized type
    @param update_block The block that will be called to give
        the caller the opportunity to update the value.
    @param update_only Pass true if update_block should be used to mutate
        the value in place instead of assigning value.
    @param previous_value If has_prev_value is true, the new value will only
        be set if this parameter is equal to the existing value in the cache.
        This allows set to become a CAS operation.
    @param has_prev_value Pass true if previous_value should be used.

    @return true if the entry was set, false if it was not
  */
  template <typename UpdateBlockT>
  bool set(const KeyT& key, const ValueT& value, UpdateBlockT update_block,
           bool update_only, const ValueT& previous_value,
           bool has_prev_value) {
    struct bucket* bucket = &buckets_[hash(key)];

    while (true) {
      lock(bucket);
      struct entry* entry = bucket->head;
      struct entry* previous_entry = nullptr;
      while (entry != nullptr) {
        if (entry->key == key) {
          if (update_only) {
            update_block(entry->value);
          } else {
            ValueT existing_value = entry->value;

            if (has_prev_value && previous_value != existing_value) {
              unlock(bucket);
              return false;
            }

            entry->value = value;
          }

          if (!update_only && value == zero_) {
            if (previous_entry != nullptr) {
              previous_entry->next = entry->next;
            } else {
              bucket->head = entry->next;
            }
            delete entry;
            count_.fetch_sub(1, std::memory_order_relaxed);
          }

          unlock(bucket);
          return true;
        }
        previous_entry = entry;
        entry = entry->next;
      }

      // If value is zero_, we're clearing but there's nothing to clear
      // so we don't need to do anything else. Alternatively, if has_prev_value
      // is true and is not zero_ we don't want to set a value.
      if (!update_only &&
          (value == zero_ || (has_prev_value && previous_value != zero_))) {
        unlock(bucket);
        return false;
      }

      // Check that adding this new item won't take the cache
      // over its maximum size.
      if (count_.load(std::memory_order_relaxed) + 1 > max_size_) {
        unlock(bucket);
        lock(&clear_bucket_);
        // Check again in case clear has already run while waiting for lock
        if (count_.load(std::memory_order_relaxed) + 1 > max_size_) {
          clear();
        }
        unlock(&clear_bucket_);
        // Bucket was unlocked during the clear path. Another thread may have
        // inserted the same key, so retry the lookup from scratch.
        continue;
      }

      // Key not found and cache has capacity. Insert at head.
      struct entry* new_entry = new struct entry(key);
      if (update_only) {
        update_block(new_entry->value);
      } else {
        new_entry->value = value;
      }
      new_entry->next = bucket->head;
      bucket->head = new_entry;
      count_.fetch_add(1, std::memory_order_relaxed);

      unlock(bucket);
      return true;
    }
  }

  /**
    Lock a bucket using os_unfair_lock for kernel-mediated priority inheritance.
  */
  inline void lock(struct bucket* bucket) const {
    os_unfair_lock_lock(&bucket->lock);
  }

  /**
    Unlock a bucket.
  */
  inline void unlock(struct bucket* bucket) const {
    os_unfair_lock_unlock(&bucket->lock);
  }

  std::atomic<uint64_t> count_ = 0;

  // count_ is written on every insert/remove while the members below are
  // read on every cache operation. The padding keeps them on separate cache
  // lines to avoid false sharing between mutators and readers. Explicit
  // padding (rather than alignas) is used because instances embedded as
  // Objective-C ivars don't get over-aligned storage; a 128-byte gap works
  // at any object alignment (the coherence granule is 128 bytes on Apple
  // Silicon, 64-byte lines fetched in adjacent pairs on x86_64).
  char count_padding_[128];

  uint64_t max_size_;
  uint32_t bucket_count_;

  struct bucket* buckets_;

  /**
    Holder for a 'zero' entry for the current type
  */
  const ValueT zero_ = {};

  /**
    Special bucket used when automatically clearing due to size
    to prevent two threads trying to clear at the same time and
    getting stuck.
  */
  struct bucket clear_bucket_ = {};

  /**
    Hash a key to determine which bucket it belongs in.
  */
  inline uint64_t hash(const KeyT& input) const {
    // bucket_count_ is a power of two, so masking is equivalent to modulo
    // but avoids an integer division.
    return Hasher{}(input) & (bucket_count_ - 1);
  }
};

#endif  // SANTA_COMMON_SANTACACHE_H
