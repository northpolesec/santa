/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA_COMMON_VERIFYINGHASHER_UNINITBUFFER_H
#define SANTA_COMMON_VERIFYINGHASHER_UNINITBUFFER_H

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

namespace santa {

// Owning byte buffer with no value-init on allocation. Avoids the
// std::vector<uint8_t>::resize() zero-fill on buffers that get fully
// overwritten by pread/memcpy before being read. Used by VerifyingHasherCore
// for chunk_buf_ and cs_blob_buf_.
//
// Move-only (std::unique_ptr<uint8_t[]>). Allocate() is "once per buffer"
// — calling it on a populated buffer is a usage bug and the assert traps
// it in dev builds. If a callsite legitimately needs to resize, it should
// either default-construct a fresh UninitBuffer or call a future Reset().
class UninitBuffer {
 public:
  UninitBuffer() = default;

  // Allocate `n` bytes, leaving them uninitialized. Must only be called on
  // an empty buffer. Strong exception guarantee: if make_unique_for_overwrite
  // throws bad_alloc, the buffer is left in its prior (empty) state.
  void Allocate(size_t n) {
    assert(size_ == 0 && "UninitBuffer::Allocate called on a non-empty buffer");
    data_ = std::make_unique_for_overwrite<uint8_t[]>(n);
    size_ = n;
  }
  uint8_t* data() { return data_.get(); }
  const uint8_t* data() const { return data_.get(); }
  size_t size() const { return size_; }
  bool empty() const { return size_ == 0; }
  std::span<const uint8_t> view() const { return {data_.get(), size_}; }

 private:
  std::unique_ptr<uint8_t[]> data_;
  size_t size_ = 0;
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_UNINITBUFFER_H
