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

namespace santa {

class ScopedFile {
 public:
  static std::unique_ptr<ScopedFile> CreateTemporary(
      NSString *path_prefix = nil, NSString *filename_template = @"santa_test_XXXXXX") {
    if (filename_template.length == 0) {
      return nullptr;
    }

    NSString *path = NSTemporaryDirectory();
    if (path_prefix) {
      path = [path stringByAppendingFormat:@"/%@", path_prefix];
      NSError *err;
      if (![[NSFileManager defaultManager] createDirectoryAtPath:path
                                     withIntermediateDirectories:YES
                                                      attributes:nil
                                                           error:&err]) {
        LOGE(@"Failed to create intermediate dir");
        return nullptr;
      }
    }

    path = [path stringByAppendingFormat:@"/%@", filename_template];

    char *mutable_path = strdup(path.UTF8String);
    if (!mutable_path) {
      LOGE(@"Failed to allocate memory for temp file path");
      return nullptr;
    }

    NSLog(@"About to create temporary: %s", mutable_path);
    int fd = mkstemp(mutable_path);
    if (fd < 0) {
      LOGE(@"Failed to create temp file: %d: %s", errno, strerror(errno));
      free(mutable_path);
      return nullptr;
    }

    path = [NSString stringWithCString:mutable_path encoding:NSUTF8StringEncoding];
    free(mutable_path);

    if (unlink(path.UTF8String) != 0) {
      // Log warning, but otherwise continue.
      LOGW(@"Unable to unlink backing temp file: %@. Error: %d: %s", path, errno, strerror(errno));
    }

    return std::make_unique<ScopedFile>(fd);
  }

  ScopedFile(int fd) : fd_(fd) {}

  ~ScopedFile() { close(fd_); }

  ScopedFile(const ScopedFile &) = delete;
  ScopedFile &operator=(const ScopedFile &) = delete;

  NSFileHandle *Reader() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

  NSFileHandle *Writer() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

 private:
  int fd_ = -1;
};

}  // namespace santa

#endif  // SANTA__COMMON__SCOPEDFILE_H
