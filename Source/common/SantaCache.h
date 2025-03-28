/// Copyright 2016-2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA__SANTA_DRIVER__SANTACACHE_H
#define SANTA__SANTA_DRIVER__SANTACACHE_H

#include <libkern/OSAtomic.h>
#include <libkern/OSTypes.h>
#include <os/log.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "Source/common/BranchPrediction.h"
#include "absl/hash/hash.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

/**
  A somewhat simple, concurrent linked-list hash table intended for use in IOKit
  kernel extensions.

  The type used for keys must overload the == operator and a specialization of
  SantaCacheHasher must exist for it.

  Enforces a maximum size by clearing all entries if a new value
  is added that would go over the maximum size declared at creation.

  The number of buckets is calculated as `maximum_size` / `per_bucket`
  rounded up to the next power of 2. Locking is done per-bucket.
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
    if (unlikely(bucket_count_ > UINT32_MAX)) bucket_count_ = UINT32_MAX;
    buckets_ = (struct bucket *)malloc(bucket_count_ * sizeof(struct bucket));
    bzero(buckets_, bucket_count_ * sizeof(struct bucket));
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
  ValueT get(KeyT key) const {
    struct bucket *bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
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
  bool set(const KeyT &key, const ValueT &value) {
    return set(key, value, nullptr, {}, false);
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
  bool set(const KeyT &key, const ValueT &value, const ValueT &previous_value) {
    return set(key, value, nullptr, previous_value, true);
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
  bool update(const KeyT &key, std::function<void(ValueT &)> update_block) {
    return set(key, zero_, update_block, {}, false);
  }

  /**
    Iterate all key and value pairs in the cache.

    @param foreach_block Called for all key and value pairs.
  */
  void foreach(std::function<void(KeyT &, ValueT &)> foreach_block) {
    assert(foreach_block != nullptr);

    // Lock all buckets
    // NB: The clear_bucket_ lock isn't necessary since both foreach and
    // clear methods lock all buckets sequentially from index 0.
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      lock(&buckets_[i]);
    }

    // Operate on all k/v pairs
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct entry *entry = (struct entry *)((uintptr_t)buckets_[i].head - 1);
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
  inline void remove(const KeyT &key) { set(key, zero_); }

  /**
    Check if a given key exists in the cache. If a contains_block
        is provided, it allows the caller to further filter for
        specific values while under lock.

    @param key The key.
    @param contains_block Block to be called with the value at the
        given key while under lock.

    @return If the key exists, return true if the contains_block
        is NOT provided, otherwise return the result of the call to
        the contains_block.
  */
  bool contains(const KeyT &key,
                std::function<bool(const ValueT &)> contains_block) const {
    struct bucket *bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
    while (entry != nullptr) {
      if (entry->key == key) {
        bool result = contains_block ? contains_block(entry->value) : true;
        unlock(bucket);
        return result;
      }
      entry = entry->next;
    }
    unlock(bucket);
    return false;
  }

  /**
    An alias for `contains(key, nullptr)`
  */
  bool contains(const KeyT &key) const { return contains(key, nullptr); }

  /**
    Remove all entries and free bucket memory.

    @param clear_block If not NULL, will be called for all key
        and value pairs just prior to deletion.
  */
  void clear(std::function<void(KeyT &, ValueT &)> clear_block) {
    for (uint32_t i = 0; i < bucket_count_; ++i) {
      struct bucket *bucket = &buckets_[i];
      // We grab the lock so nothing can use this bucket while we're erasing it
      // and never release it. It'll be 'released' when the bzero call happens
      // at the end of this function.
      lock(bucket);

      // Free the bucket's entries, if there are any.
      struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
      while (entry != nullptr) {
        if (clear_block) {
          clear_block(entry->key, entry->value);
        }
        struct entry *next_entry = entry->next;
        delete entry;
        entry = next_entry;
      }
    }

    // Reset cache count, no atomicity needed as we hold all the bucket locks.
    count_ = 0;

    // This resets all of the bucket counts and locks. Releasing the locks for
    // each bucket isn't really atomic here but each bucket will be zero'd
    // before the lock is released as the lock is the last thing in a bucket.
    bzero(buckets_, bucket_count_ * sizeof(struct bucket));
  }

  /**
    An alias for `clear(nullptr)`
  */
  void clear() { clear(nullptr); }

  /**
    Return number of entries currently in cache.
  */
  inline uint64_t count() const { return count_; }

  /**
    Fill in the per_bucket_counts array with the number of entries in each
    bucket.

    The per_buckets_count array will contain the per-bucket counts, up to the
    number in array_size. The start_bucket parameter will determine which bucket
    to start off with and upon return will contain either 0 if no buckets are
    remaining or the next bucket to begin with when called again.
  */
  void bucket_counts(uint16_t *per_bucket_counts, uint16_t *array_size,
                     uint64_t *start_bucket) {
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
      struct bucket *bucket = &buckets_[start++];
      lock(bucket);
      struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
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
    struct entry *next = nullptr;
  };

  struct bucket {
    // The least significant bit of this pointer is always 0 (due to alignment),
    // so we utilize that bit as the lock for the bucket.
    struct entry *head;
  };

  /**
    Set an element in the cache.

    @note If the cache is full when this is called, this will
    empty the cache before inserting the new value.

    @param key The key
    @param value The value with parameterized type
    @param update_block The block that will be called to give
        the caller the opportunity to update the value.
    @param previous_value If has_prev_value is true, the new value will only
        be set if this parameter is equal to the existing value in the cache.
        This allows set to become a CAS operation.
    @param has_prev_value Pass true if previous_value should be used.

    @return true if the entry was set, false if it was not
  */
  bool set(const KeyT &key, const ValueT &value,
           std::function<void(ValueT &)> update_block,
           const ValueT &previous_value, bool has_prev_value) {
    // Only either value or update block can be set
    assert(!(value != zero_ && update_block != nullptr));
    bool update_only = (update_block != nullptr);

    struct bucket *bucket = &buckets_[hash(key)];
    lock(bucket);
    struct entry *entry = (struct entry *)((uintptr_t)bucket->head - 1);
    struct entry *previous_entry = nullptr;
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
            bucket->head = (struct entry *)((uintptr_t)entry->next + 1);
          }
          delete entry;
          OSAtomicDecrement64((volatile int64_t *)&count_);
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
    if (count_ + 1 > max_size_) {
      unlock(bucket);
      lock(&clear_bucket_);
      // Check again in case clear has already run while waiting for lock
      if (count_ + 1 > max_size_) {
        clear();
      }
      lock(bucket);
      unlock(&clear_bucket_);
    }

    // Allocate a new entry, set the key and value, then put this new entry at
    // the head of this bucket's linked list.
    struct entry *new_entry = new struct entry(std::move(key));
    if (update_block) {
      update_block(new_entry->value);
    } else {
      new_entry->value = value;
    }
    new_entry->next = (struct entry *)((uintptr_t)bucket->head - 1);
    bucket->head = (struct entry *)((uintptr_t)new_entry + 1);
    OSAtomicIncrement64((volatile int64_t *)&count_);

    unlock(bucket);
    return true;
  }

  /**
    Lock a bucket. Spins until the lock is acquired.
  */
  inline void lock(struct bucket *bucket) const {
    while (OSAtomicTestAndSet(7, (volatile uint8_t *)&bucket->head)) {
    }
  }

  /**
    Unlock a bucket. Panics if the lock wasn't locked.
  */
  inline void unlock(struct bucket *bucket) const {
    if (unlikely(OSAtomicTestAndClear(7, (volatile uint8_t *)&bucket->head) ==
                 0)) {
      os_log_error(OS_LOG_DEFAULT,
                   "SantaCache::unlock(): Tried to unlock an unlocked lock");
      abort();
    }
  }

  uint64_t count_ = 0;

  uint64_t max_size_;
  uint32_t bucket_count_;

  struct bucket *buckets_;

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
  inline uint64_t hash(KeyT input) const {
    return Hasher{}(input) % bucket_count_;
  }
};

#pragma clang diagnostic pop

#endif  // SANTA__SANTA_DRIVER__SANTACACHE_H
