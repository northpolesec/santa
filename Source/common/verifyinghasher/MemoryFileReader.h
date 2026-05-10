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

#ifndef SANTA_COMMON_VERIFYINGHASHER_MEMORYFILEREADER_H
#define SANTA_COMMON_VERIFYINGHASHER_MEMORYFILEREADER_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "Source/common/verifyinghasher/FileReader.h"

namespace santa {

// In-memory FileReader implementation. Used by tests and fuzz targets;
// production callers use the FdFileReader impl in FileReader.{h,mm}.
class MemoryFileReader : public FileReader {
 public:
  explicit MemoryFileReader(std::vector<uint8_t> data)
      : data_(std::move(data)) {}
  ssize_t Pread(void* buf, size_t len, off_t off) override {
    if (fail_next_) {
      fail_next_ = false;
      return -1;
    }
    if (off < 0) return -1;
    if (static_cast<size_t>(off) >= data_.size()) return 0;
    size_t available = data_.size() - static_cast<size_t>(off);
    size_t n = std::min(len, available);
    std::memcpy(buf, data_.data() + off, n);
    return static_cast<ssize_t>(n);
  }
  off_t Size() const override { return static_cast<off_t>(data_.size()); }

  // Forces the next Pread call to return -1 without touching `data_`;
  // used by tests to exercise error-handling branches.
  void ScheduleErrorOnNextPread() { fail_next_ = true; }

 private:
  std::vector<uint8_t> data_;
  bool fail_next_ = false;
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_MEMORYFILEREADER_H
