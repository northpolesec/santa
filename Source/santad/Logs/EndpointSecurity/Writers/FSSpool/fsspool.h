/// Copyright 2022 Google LLC
/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H_
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H_

// Namespace ::fsspool::fsspool implements a filesystem-backed message spool, to
// use as a lock-free IPC mechanism.

#include <sys/stat.h>

#include <string>

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/AnyBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_platform_specific.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"

// Forward declarations
namespace fsspool {
class FsSpoolWriterPeer;
}

namespace fsspool {

template <typename T>
concept BatcherInterface =
    requires(T batcher, int fd, std::vector<uint8_t> bytes) {
      T{};
      { batcher.InitializeBatch(fd) } -> std::same_as<void>;
      { batcher.Write(bytes) } -> std::same_as<absl::Status>;
      { batcher.CompleteBatch(fd) } -> std::same_as<absl::StatusOr<size_t>>;
    };

// Enqueues messages into the spool. Multiple concurrent writers can
// write to the same directory. (Note that this class is only thread-compatible
// and not thread-safe though!)
template <BatcherInterface T>
class FsSpoolWriter {
 public:
  // The base, spool, and temporary directory will be created as needed on the
  // first call to Write() - however the base directory can be created into an
  // existing path (i.e. this class will not do an `mkdir -p`).
  FsSpoolWriter(absl::string_view base_dir, size_t max_spool_size)
      : base_dir_(base_dir),
        spool_dir_(SpoolNewDirectory(base_dir)),
        tmp_dir_(SpoolTempDirectory(base_dir)),
        space_check_failure_since_last_flush_(false),
        max_spool_size_(max_spool_size),
        id_(absl::StrFormat(
            "%016x",
            absl::Uniform<uint64_t>(absl::BitGen(), 0,
                                    std::numeric_limits<uint64_t>::max()))),
        // Guess that the spool is full during construction, so we will
        // recompute the actual spool size on the first write.
        spool_size_estimate_(max_spool_size + 1) {}

  absl::Status SpaceAvailable() {
    if (spool_size_estimate_ > max_spool_size_) {
      absl::StatusOr<size_t> estimate = EstimateSpoolDirSize();
      if (!estimate.ok()) {
        return estimate.status();  // failed to recompute spool size
      }

      spool_size_estimate_ = *estimate;
      if (spool_size_estimate_ > max_spool_size_) {
        // Still over the limit: avoid writing.
        return absl::ResourceExhaustedError(
            "Spool size estimate greater than max allowed");
      } else {
        return absl::OkStatus();
      }
    } else {
      return absl::OkStatus();
    }
  }

  absl::Status InitializeCurrentSpoolStateIfNeeded() {
    if (current_spool_state_.IsOpen()) {
      return absl::OkStatus();
    }

    absl::Status status = BuildDirectoryStructureIfNeeded();
    if (!status.ok()) {
      return status;
    }

    if (status = SpaceAvailable(); !status.ok()) {
      return status;
    }

    std::string fname = UniqueFilename();
    current_spool_state_.tmp_file =
        absl::StrCat(tmp_dir_, PathSeparator(), fname);
    current_spool_state_.spool_file =
        absl::StrCat(spool_dir_, PathSeparator(), fname);

    current_spool_state_.tmp_fd =
        ::fsspool::Open(current_spool_state_.tmp_file.c_str(),
                        O_WRONLY | O_CREAT | O_TRUNC, 0400);
    if (current_spool_state_.tmp_fd < 0) {
      return absl::ErrnoToStatus(errno, "open() failed");
    }

    batcher_.InitializeBatch(current_spool_state_.tmp_fd);

    return absl::OkStatus();
  }

  absl::Status CompleteCurrentSpoolState() {
    if (!current_spool_state_.IsOpen()) {
      return absl::OkStatus();
    }

    absl::StatusOr<size_t> size_estimate =
        batcher_.CompleteBatch(current_spool_state_.tmp_fd);
    ::fsspool::Close(current_spool_state_.tmp_fd);
    current_spool_state_.tmp_fd = -1;

    if (!size_estimate.ok()) {
      // TODO: delete tmp file
      return size_estimate.status();
    }

    spool_size_estimate_ += *size_estimate;

    if (absl::Status status = RenameFile(current_spool_state_.tmp_file,
                                         current_spool_state_.spool_file);
        !status.ok()) {
      // TODO: delete tmp file
      return status;
    }

    return absl::OkStatus();
  }

  // Returns ResourceExhaustedError the first time no space is available since
  // last flush Returns DataLossError if writes weren't attempted due to a
  // previous space check failure Otherwise returns OK or an appropriate failure
  // status
  absl::Status Write(std::vector<uint8_t> bytes) {
    // The StreamBatcher must be initialized before the first Write
    if constexpr (std::is_same_v<T, ::fsspool::StreamBatcher>) {
      // Don't attempt initialization if a previous initialization check
      // indicated the spool was out of space.
      if (!space_check_failure_since_last_flush_) {
        if (absl::Status status = InitializeCurrentSpoolStateIfNeeded();
            !status.ok()) {
          if (absl::IsResourceExhausted(status)) {
            space_check_failure_since_last_flush_ = true;
          }
          return status;
        }
      } else {
        return absl::DataLossError("No space exists");
      }
    }

    return batcher_.Write(std::move(bytes));
  }

  absl::Status Flush() {
    // The AnyBatcher must be initialized upon Flush
    if constexpr (std::is_same_v<T, ::fsspool::AnyBatcher>) {
      if (absl::Status status = InitializeCurrentSpoolStateIfNeeded();
          !status.ok()) {
        return status;
      }
    }

    absl::Status status = CompleteCurrentSpoolState();
    space_check_failure_since_last_flush_ = false;
    return status;
  }

  // Pushes the given byte array to the spool. The given maximum
  // spool size will be enforced. Returns an error code. If the spool gets full,
  // returns the UNAVAILABLE canonical code (which is retryable).
  absl::Status WriteMessage(absl::string_view msg);

  friend class fsspool::FsSpoolWriterPeer;

 private:
  // Makes sure that all the required
  // directories needed for correct operation of this Writer are present in the
  // filesystem.
  absl::Status BuildDirectoryStructureIfNeeded() {
    if (!IsDirectory(spool_dir_)) {
      if (!IsDirectory(base_dir_)) {
        if (absl::Status status = MkDir(base_dir_); !status.ok()) {
          return status;  // failed to create base directory
        }
      }

      if (absl::Status status = MkDir(spool_dir_); !status.ok()) {
        return status;  // failed to create spool directory;
      }
    }
    if (!IsDirectory(tmp_dir_)) {
      // No need to check the base directory too, since spool_dir_ exists.
      if (absl::Status status = MkDir(tmp_dir_); !status.ok()) {
        return status;  // failed to create tmp directory
      }
    }
    return absl::OkStatus();
  }

  // Generates a unique filename by combining the random ID of
  // this writer with a sequence number.
  std::string UniqueFilename() {
    std::string result = absl::StrFormat("%s_%020d", id_, sequence_number_);
    sequence_number_++;
    return result;
  }

  // Estimate the size of the spool directory. However, only recompute a new
  // estimate if the spool directory has has a change to its modification time.
  absl::StatusOr<size_t> EstimateSpoolDirSize() {
    struct stat stats;
    if (stat(spool_dir_.c_str(), &stats) < 0) {
      return absl::ErrnoToStatus(errno, "failed to stat spool directory");
    }

    if (stats.st_mtimespec.tv_sec == spool_dir_last_mtime_.tv_sec &&
        stats.st_mtimespec.tv_nsec == spool_dir_last_mtime_.tv_nsec) {
      // If the spool's last modification time hasn't changed then
      // re-use the current estimate.
      return spool_size_estimate_;
    } else {
      // Store the updated mtime
      spool_dir_last_mtime_ = stats.st_mtimespec;

      // Recompute the current estimated size
      return EstimateDirSize(spool_dir_);
    }
  }

  struct CurrentSpoolState {
    CurrentSpoolState() : tmp_fd(-1) {}

    bool IsOpen() { return tmp_fd >= 0; }

    std::string spool_file;
    std::string tmp_file;
    int tmp_fd;
  };

  const std::string base_dir_;
  const std::string spool_dir_;
  const std::string tmp_dir_;
  T batcher_;
  struct timespec spool_dir_last_mtime_;
  CurrentSpoolState current_spool_state_;

  // This acts as an optimization when initializing a CurrentSpoolState to help
  // reduce the number of times costly free space checks happen. If the spool
  // fills up, another attempt to initialize a CurrentSpoolState will not occur
  // until after the next flush attempt (SpoolDirectoryEventMaxFlushTimeSec).
  // This is only checked when the StreamBatcher is in use as writes using the
  // AnyBatcher are buffered in memory.
  bool space_check_failure_since_last_flush_;

  // Approximate maximum size of the spooling area, in bytes. If a message is
  // being written to a spooling area which already contains more than
  // maxSpoolSize bytes, the write will not be executed. This is an approximate
  // estimate: no care is taken to make an exact estimate (for example, if a
  // file gets deleted from the spool while the estimate is being computed, the
  // final estimate is likely to still include the size of that file).
  const size_t max_spool_size_;

  // 64bit hex ID for this writer. Used in combination with the sequence
  // number to generate unique names for files. This is generated through
  // util::random::NewGlobalID(), hence has only 52 bits of randomness.
  const std::string id_;

  // Sequence number of the next message to be written. This
  // counter will be incremented at every Write call, so that the produced
  // spooled files have different names.
  uint64_t sequence_number_ = 0;

  // Last estimate for the spool size. The estimate will grow every time we
  // write messages (basically, we compute it as if there was no reader
  // consuming messages). It will get updated with the actual value whenever we
  // think we've passed the size limit. The new estimate will be the sum of the
  // approximate disk space occupied by each message written (in multiples of
  // 4KiB, i.e. a typical disk cluster size).
  size_t spool_size_estimate_;
};

// This class is thread-unsafe.
class FsSpoolReader {
 public:
  explicit FsSpoolReader(absl::string_view base_directory)
      : base_dir_(base_directory),
        spool_dir_(SpoolNewDirectory(base_directory)) {}
  absl::Status AckMessage(const std::string& message_path, bool delete_file) {
    if (delete_file) {
      int remove_status = remove(message_path.c_str());
      if ((remove_status != 0) && (errno != ENOENT)) {
        return absl::ErrnoToStatus(
            errno,
            absl::Substitute("Failed to remove $0: $1", message_path, errno));
      }
    }
    unacked_messages_.erase(message_path);
    return absl::OkStatus();
  }

  // Returns absl::NotFoundError in case the FsSpool is empty.
  absl::StatusOr<std::string> NextMessagePath() {
    absl::StatusOr<std::string> file_path = OldestSpooledFile();
    if (!file_path.ok()) {
      return file_path;
    }
    unacked_messages_.insert(*file_path);
    return file_path;
  }

  absl::StatusOr<absl::flat_hash_set<std::string>> BatchMessagePaths(
      size_t count) {
    absl::flat_hash_set<std::string> batch;
    if (count == 0) {
      return batch;
    }
    absl::Status status = IterateDirectory(
        spool_dir_,
        [this, count, &batch](const std::string& file_name, bool* stop) {
          if (file_name == "." || file_name == "..") {
            return;
          }

          std::string file_path =
              absl::StrCat(spool_dir_, PathSeparator(), file_name);

          if (unacked_messages_.contains(file_path)) {
            return;
          }

          batch.insert(file_path);
          unacked_messages_.insert(file_path);

          if (batch.size() >= count) {
            *stop = true;
          }
        });
    return batch;
  }

  size_t NumberOfUnackedMessages() const { return unacked_messages_.size(); }

 private:
  const std::string base_dir_;
  const std::string spool_dir_;
  absl::flat_hash_set<std::string> unacked_messages_;

  absl::StatusOr<std::string> OldestSpooledFile() {
    if (!IsDirectory(spool_dir_)) {
      return absl::NotFoundError(
          "Spool directory is not a directory or it doesn't exist.");
    }
    absl::Time oldest_file_mtime;
    std::string oldest_file_path;
    absl::Status status = IterateDirectory(
        spool_dir_, [this, &oldest_file_path, &oldest_file_mtime](
                        const std::string& file_name, bool* stop) {
          std::string file_path =
              absl::StrCat(spool_dir_, PathSeparator(), file_name);
          struct stat stats;
          if (stat(file_path.c_str(), &stats) < 0) {
            return;
          }
          if (!StatIsReg(stats.st_mode)) {
            return;
          }
          if (unacked_messages_.contains(file_path)) {
            return;
          }
          absl::Time file_mtime = absl::FromTimeT(stats.st_mtime);
          if (!oldest_file_path.empty() && oldest_file_mtime < file_mtime) {
            return;
          }
          oldest_file_path = file_path;
          oldest_file_mtime = file_mtime;
        });
    if (!status.ok()) {
      return status;
    }

    if (oldest_file_path.empty()) {
      return absl::NotFoundError("Empty FsSpool directory.");
    }
    return oldest_file_path;
  }
};

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H_
