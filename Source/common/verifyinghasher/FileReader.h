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

#ifndef SANTA_COMMON_VERIFYINGHASHER_FILEREADER_H
#define SANTA_COMMON_VERIFYINGHASHER_FILEREADER_H

#include <sys/types.h>

#include <cstddef>

namespace santa {

// Non-owning, position-stable file reader. All reads must use pread()
// semantics (positional, never mutates an internal offset). This is the
// only I/O surface the verifier sees, so callers (notably SNTFileInfo)
// can share an fd without us trampling its read cursor.
//
// Readahead policy is the caller's responsibility — VerifyingHasherCore issues
// roughly sequential preads but does not configure the fd. Production
// callers (Santa) should set fcntl(F_RDAHEAD, 1) on their fd before
// constructing FdFileReader for warm sequential reads.
class FileReader {
 public:
  virtual ~FileReader() = default;
  // Returns bytes read (≤ len); 0 = EOF; -1 = error (errno set).
  virtual ssize_t Pread(void* buf, size_t len, off_t off) = 0;
  // Total file size in bytes. Constant for the lifetime of the reader.
  virtual off_t Size() const = 0;
};

// Production reader: wraps a borrowed file descriptor. Does NOT take
// ownership; caller is responsible for fd lifetime.
class FdFileReader : public FileReader {
 public:
  explicit FdFileReader(int fd, off_t size);
  ssize_t Pread(void* buf, size_t len, off_t off) override;
  off_t Size() const override { return size_; }

 private:
  int fd_;
  off_t size_;
};

}  // namespace santa

#endif  // SANTA_COMMON_VERIFYINGHASHER_FILEREADER_H
