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

#ifndef SANTA__COMMON__RINGBUFFER_H
#define SANTA__COMMON__RINGBUFFER_H

#import <Foundation/Foundation.h>

#include <cstdlib>
#include <deque>
#include <optional>

#include "Source/common/SNTLogging.h"

namespace santa {

template <typename T>
class RingBuffer {
 public:
  RingBuffer(size_t capacity) : capacity_(capacity) {
    if (capacity == 0) {
      LOGE(@"RingBuffer capacity must be greater than 0");
      std::abort();
    }
  }

  RingBuffer(RingBuffer &&other) = default;
  RingBuffer &operator=(RingBuffer &&rhs) = default;

  // Could be safe to implement these, but not currently needed
  RingBuffer(const RingBuffer &other) = delete;
  RingBuffer &operator=(const RingBuffer &other) = delete;

  inline size_t Capacity() const { return capacity_; }
  inline bool Empty() const { return buffer_.size() == 0; };
  inline bool Full() const { return buffer_.size() == capacity_; };

  std::optional<T> Enqueue(const T &val) {
    std::optional<T> removed_value;
    if (Full()) {
      removed_value = std::move(buffer_.front());
      buffer_.pop_front();
    }
    buffer_.push_back(val);
    return removed_value;
  }

  std::optional<T> Enqueue(T &&val) {
    std::optional<T> removed_value;
    if (Full()) {
      removed_value = std::move(buffer_.front());
      buffer_.pop_front();
    }
    buffer_.push_back(std::move(val));
    return removed_value;
  }

  std::optional<T> Dequeue() {
    if (Empty()) {
      return std::nullopt;
    } else {
      T value = std::move(buffer_.front());
      buffer_.pop_front();
      return std::make_optional<T>(value);
    }
  }

  using iterator = typename std::deque<T>::iterator;
  using const_iterator = typename std::deque<T>::const_iterator;

  // Erase methods similar to std::vector
  iterator Erase(const_iterator pos) {
    // Validate iterator
    if (pos < buffer_.cbegin() || pos >= buffer_.cend()) {
      LOGE(@"RingBuffer iterator out of range");
      std::abort();
    }
    return buffer_.erase(pos);
  }

  iterator Erase(const_iterator first, const_iterator last) {
    // Validate iterators
    if (first < buffer_.cbegin() || last > buffer_.cend() || first > last) {
      LOGE(@"RingBuffer iterator out of range");
      std::abort();
    }
    return buffer_.erase(first, last);
  }

  // Iterator support
  iterator begin() { return buffer_.begin(); }
  iterator end() { return buffer_.end(); }
  const_iterator begin() const { return buffer_.begin(); }
  const_iterator end() const { return buffer_.end(); }
  const_iterator cbegin() const { return buffer_.cbegin(); }
  const_iterator cend() const { return buffer_.cend(); }

 private:
  size_t capacity_;
  std::deque<T> buffer_;
};

}  // namespace santa

#endif
