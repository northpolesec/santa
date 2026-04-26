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

#ifndef SANTA_COMMON_SCOPEDFILE_H
#define SANTA_COMMON_SCOPEDFILE_H

#import <Foundation/Foundation.h>
#include <unistd.h>

#include <cstring>
#include <memory>

#import "Source/common/SNTLogging.h"
#include "absl/status/statusor.h"

namespace santa {

class ScopedFile {
 public:
  static absl::StatusOr<ScopedFile> CreateTemporary(
      NSString* path_prefix = nil, size_t size = 0,
      NSString* filename_template = @"santa_test_XXXXXX", bool keep_path = false) {
    if (filename_template.length == 0) {
      return absl::FailedPreconditionError("No temp file template provided");
    }

    NSString* path = NSTemporaryDirectory();
    if (path_prefix) {
      path = [path stringByAppendingFormat:@"/%@", path_prefix];
      NSError* err;
      if (![[NSFileManager defaultManager] createDirectoryAtPath:path
                                     withIntermediateDirectories:YES
                                                      attributes:nil
                                                           error:&err]) {
        return absl::FailedPreconditionError("Failed to create intermediate dir");
      }
    }

    path = [path stringByAppendingFormat:@"/%@", filename_template];

    char* mutable_path = strdup(path.UTF8String);
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

    if (!keep_path) {
      if (unlink(path.UTF8String) != 0) {
        // Log warning, but otherwise continue.
        LOGW(@"Unable to unlink backing temp file: %@. Error: %d: %s", path, errno,
             strerror(errno));
      }
      path = nil;
    }

    if (size > 0 && ftruncate(fd, static_cast<off_t>(size)) != 0) {
      int saved_errno = errno;
      if (path) unlink(path.UTF8String);
      close(fd);
      return absl::ErrnoToStatus(saved_errno, "Failed to size temp file");
    }

    return ScopedFile(fd, path);
  }

  explicit ScopedFile(int fd, NSString* path = nil) : fd_(fd), path_(path) {}

  ~ScopedFile() {
    if (path_) unlink(path_.UTF8String);
    if (fd_ >= 0) {
      close(fd_);
    }
  }

  ScopedFile(const ScopedFile&) = delete;
  ScopedFile& operator=(const ScopedFile&) = delete;

  ScopedFile(ScopedFile&& other) : fd_(other.fd_), path_(other.path_) {
    other.fd_ = -1;
    other.path_ = nil;
  }

  ScopedFile& operator=(ScopedFile&& rhs) {
    if (this != &rhs) {
      if (path_) unlink(path_.UTF8String);
      if (fd_ >= 0) close(fd_);
      fd_ = rhs.fd_;
      path_ = rhs.path_;
      rhs.fd_ = -1;
      rhs.path_ = nil;
    }
    return *this;
  }

  NSFileHandle* Reader() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

  NSFileHandle* Writer() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

  // Some consumers need access to the raw file descriptor. But usage must be
  // carefully evaluated to ensure usage of the returned file descriptor
  // doesn't outlast the lifetime of this object.
  int UnsafeFD() const { return fd_; }

  // The on-disk path, or nil if the file was unlinked at creation time
  // (the default `keep_path = false` behavior).
  NSString* Path() const { return path_; }

 private:
  int fd_ = -1;
  NSString* path_ = nil;
};

}  // namespace santa

#endif  // SANTA_COMMON_SCOPEDFILE_H
