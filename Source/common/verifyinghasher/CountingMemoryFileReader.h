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

#ifndef SANTA_COMMON_VERIFYINGHASHER_COUNTINGMEMORYFILEREADER_H
#define SANTA_COMMON_VERIFYINGHASHER_COUNTINGMEMORYFILEREADER_H

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <vector>

#include "Source/common/verifyinghasher/FileReader.h"

namespace santa {

// In-memory FileReader that tracks per-byte read counts. Used to
// validate the single-observation invariant: every byte is read at
// most once per VerifyingHasherCore::Run(). After Run() returns,
// MaxReadsAnyByte() returns the maximum read count across all bytes.
// Callers (unit tests + the end-to-end fuzzer) assert/abort on > 1.
class CountingMemoryFileReader : public FileReader {
 public:
  explicit CountingMemoryFileReader(std::vector<uint8_t> data)
      : data_(std::move(data)), reads_(data_.size(), 0) {}
  ssize_t Pread(void* buf, size_t len, off_t off) override {
    if (off < 0) {
      errno = EINVAL;
      return -1;
    }
    if (static_cast<size_t>(off) >= data_.size()) return 0;
    size_t n = std::min(len, data_.size() - static_cast<size_t>(off));
    std::memcpy(buf, data_.data() + off, n);
    for (size_t i = 0; i < n; ++i) ++reads_[off + i];
    return static_cast<ssize_t>(n);
  }
  off_t Size() const override { return static_cast<off_t>(data_.size()); }
  uint32_t MaxReadsAnyByte() const {
    uint32_t m = 0;
    for (auto c : reads_) {
      if (c > m) {
        m = c;
      }
    }
    return m;
  }

 private:
  std::vector<uint8_t> data_;
  std::vector<uint32_t> reads_;
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_COUNTINGMEMORYFILEREADER_H
