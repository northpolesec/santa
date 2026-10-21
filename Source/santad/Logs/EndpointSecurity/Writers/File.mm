/// Copyright 2022 Google Inc. All rights reserved.
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

#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>

#include "Source/common/BranchPrediction.h"
#include "Source/common/SNTLogging.h"

namespace santa {

std::shared_ptr<File> File::Create(NSString* path, uint64_t flush_timeout_ms,
                                   size_t batch_size_bytes, size_t max_expected_write_size_bytes,
                                   mode_t file_mode, gid_t file_gid) {
  dispatch_queue_t q = dispatch_queue_create("com.northpolesec.santa.daemon.file_event_log",
                                             DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
  dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);

  dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                            NSEC_PER_MSEC * flush_timeout_ms, 0);

  auto ret_writer = std::make_shared<File>(path, batch_size_bytes, max_expected_write_size_bytes, q,
                                           timer_source, file_mode, file_gid);
  ret_writer->WatchLogFile();

  std::weak_ptr<File> weak_writer(ret_writer);
  dispatch_source_set_event_handler(ret_writer->timer_source_, ^{
    std::shared_ptr<File> shared_writer = weak_writer.lock();
    if (!shared_writer) {
      return;
    }
    shared_writer->FlushSerialized();
  });

  dispatch_resume(ret_writer->timer_source_);

  return ret_writer;
}

File::File(NSString* path, size_t batch_size_bytes, size_t max_expected_write_size_bytes,
           dispatch_queue_t q, dispatch_source_t timer_source, mode_t file_mode, gid_t file_gid)
    : buffer_(batch_size_bytes + max_expected_write_size_bytes),
      batch_size_bytes_(batch_size_bytes),
      q_(q),
      timer_source_(timer_source),
      watch_source_(nullptr) {
  path_ = path;
  file_mode_ = file_mode;
  file_gid_ = file_gid;
  OpenFileHandleSerialized();
}

void File::WatchLogFile() {
  if (watch_source_) {
    dispatch_source_cancel(watch_source_);
  }

  watch_source_ = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, file_handle_.fileDescriptor,
                                         DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME, q_);

  auto shared_this = shared_from_this();
  dispatch_source_set_event_handler(watch_source_, ^{
    [shared_this->file_handle_ closeFile];
    shared_this->OpenFileHandleSerialized();
    shared_this->WatchLogFile();
  });

  dispatch_resume(watch_source_);
}

File::~File() {
  if (timer_source_) {
    dispatch_source_cancel(timer_source_);
  }
}

// IMPORTANT: Not thread safe.
void File::OpenFileHandleSerialized() {
  NSFileManager* fm = [NSFileManager defaultManager];
  if (![fm fileExistsAtPath:path_]) {
    // When a group is configured the log is created owner-only and widened below, once the group
    // is settled. Otherwise a group-readable log would exist, however briefly, while it still
    // belonged to the group of the directory above it.
    NSNumber* createMode = file_gid_ != (gid_t)-1 ? @(0600) : (file_mode_ ? @(file_mode_) : nil);
    [fm createFileAtPath:path_
                contents:nil
              attributes:createMode ? @{NSFilePosixPermissions : createMode} : nil];
  }
  file_handle_ = [NSFileHandle fileHandleForWritingAtPath:path_];
  [file_handle_ seekToEndOfFile];

  // Apply the mode on every open rather than only on creation. `WatchLogFile` calls back in here
  // each time the log is rotated out from under us, and the replacement file was created by
  // newsyslog using the mode from its own config - not ours.
  //
  // Only ever to a regular file. An EventLogPath in a directory others can write could be a
  // symlink by the time it is opened, and `fileHandleForWritingAtPath:` follows it - so without
  // this check the mode would land on whatever the link names, applied as root.
  if ((file_mode_ || file_gid_ != (gid_t)-1) && file_handle_) {
    // Confirm the descriptor refers to the regular file that this path names, and not to whatever
    // a symlink pointed at. `fileHandleForWritingAtPath:` follows a symlink, and an lstat alone
    // would leave a window between the open and the change. Comparing the lstat of the path with
    // the fstat of the open descriptor closes it: if the path is a symlink, or was swapped after
    // the open, the two do not describe the same file and nothing is changed.
    struct stat path_sb;
    struct stat fd_sb;
    if (lstat(path_.UTF8String, &path_sb) != 0 || fstat(file_handle_.fileDescriptor, &fd_sb) != 0 ||
        !S_ISREG(path_sb.st_mode) || path_sb.st_dev != fd_sb.st_dev ||
        path_sb.st_ino != fd_sb.st_ino) {
      LOGW(@"Not setting mode or group on %@: not the regular file it names", path_);
    } else {
      // Group first, for two reasons. chown(2) can clear the set-id bits, so the chmod after it
      // is the one that decides the final mode. And a mode that grants group access is only safe
      // once the file belongs to the configured group: if the chown fails, widening the mode
      // would grant that access to whichever group owns the log now, so the mode is left alone.
      bool groupOK = true;
      if (file_gid_ != (gid_t)-1 &&
          fchown(file_handle_.fileDescriptor, (uid_t)-1, file_gid_) != 0) {
        groupOK = false;
        LOGW(@"Unable to set group %u on %@: %d: %s", file_gid_, path_, errno, strerror(errno));
      }
      if (!groupOK) {
        LOGW(@"Not setting mode 0%o on %@: its group could not be set", file_mode_, path_);
      } else if (file_mode_ && fchmod(file_handle_.fileDescriptor, file_mode_) != 0) {
        LOGW(@"Unable to set mode 0%o on %@: %d: %s", file_mode_, path_, errno, strerror(errno));
      }
    }
  }
}

void File::Write(std::vector<uint8_t>&& bytes) {
  auto shared_this = shared_from_this();

  // Workaround to move `bytes` into the block without a copy
  __block std::vector<uint8_t> temp_bytes = std::move(bytes);

  dispatch_async(q_, ^{
    std::vector<uint8_t> moved_bytes = std::move(temp_bytes);

    shared_this->CopyDataSerialized(moved_bytes);

    if (shared_this->ShouldFlush()) {
      shared_this->FlushSerialized();
    }
  });
}

bool File::ShouldFlush() {
  return buffer_offset_ >= batch_size_bytes_;
}

void File::Flush() {
  dispatch_sync(q_, ^{
    FlushSerialized();
  });
}

// IMPORTANT: Not thread safe.
void File::EnsureCapacitySerialized(size_t additional_bytes) {
  if ((buffer_offset_ + additional_bytes) > buffer_.capacity()) {
    buffer_.resize(std::max(buffer_.capacity() * 2, buffer_offset_ + additional_bytes));
  }
}

// IMPORTANT: Not thread safe.
void File::CopyDataSerialized(const std::vector<uint8_t>& bytes) {
  EnsureCapacitySerialized(bytes.size());
  std::copy(bytes.begin(), bytes.end(), buffer_.begin() + buffer_offset_);
  buffer_offset_ += bytes.size();
}

// IMPORTANT: Not thread safe.
void File::FlushSerialized() {
  if (likely(buffer_offset_ > 0)) {
    write(file_handle_.fileDescriptor, buffer_.data(), buffer_offset_);

    // After flushing, reset the offset back to 0
    buffer_offset_ = 0;
  }
}

}  // namespace santa
