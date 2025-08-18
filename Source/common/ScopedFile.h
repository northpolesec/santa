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

#ifndef SANTA__COMMON__SCOPEDFILE_H
#define SANTA__COMMON__SCOPEDFILE_H

#import <Foundation/Foundation.h>
#include <unistd.h>

#include <cstring>
#include <memory>

#import "Source/common/SNTLogging.h"
#include "absl/status/statusor.h"

// Forward declarations
namespace santa {
class ScopedFilePeer;
}  // namespace santa

namespace santa {

class ScopedFile {
 public:
  static absl::StatusOr<ScopedFile> CreateTemporary(
      NSString *path_prefix = nil, NSString *filename_template = @"santa_test_XXXXXX") {
    if (filename_template.length == 0) {
      return absl::FailedPreconditionError("No temp file template provided");
    }

    NSString *path = NSTemporaryDirectory();
    if (path_prefix) {
      path = [path stringByAppendingFormat:@"/%@", path_prefix];
      NSError *err;
      if (![[NSFileManager defaultManager] createDirectoryAtPath:path
                                     withIntermediateDirectories:YES
                                                      attributes:nil
                                                           error:&err]) {
        return absl::FailedPreconditionError("Failed to create intermediate dir");
      }
    }

    path = [path stringByAppendingFormat:@"/%@", filename_template];

    char *mutable_path = strdup(path.UTF8String);
    if (!mutable_path) {
      return absl::InternalError("Failed to allocate memory for temp file path");
    }

    int fd = mkstemp(mutable_path);
    if (fd < 0) {
      free(mutable_path);
      return absl::ErrnoToStatus(errno, "Failed to create temp file");
    }

    path = [NSString stringWithCString:mutable_path encoding:NSUTF8StringEncoding];
    free(mutable_path);

    if (unlink(path.UTF8String) != 0) {
      // Log warning, but otherwise continue.
      LOGW(@"Unable to unlink backing temp file: %@. Error: %d: %s", path, errno, strerror(errno));
    }

    return ScopedFile(fd);
  }

  ScopedFile(int fd) : fd_(fd) {}

  ~ScopedFile() {
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  ScopedFile(const ScopedFile &) = delete;
  ScopedFile &operator=(const ScopedFile &) = delete;

  ScopedFile(ScopedFile &&other) {
    fd_ = other.fd_;
    other.fd_ = -1;
  }

  ScopedFile &operator=(ScopedFile &&rhs) {
    if (this != &rhs) {
      fd_ = rhs.fd_;
      rhs.fd_ = -1;
    }
    return *this;
  }

  NSFileHandle *Reader() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

  NSFileHandle *Writer() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

  friend class ScopedFilePeer;

 private:
  int fd_ = -1;
};

}  // namespace santa

#endif  // SANTA__COMMON__SCOPEDFILE_H
