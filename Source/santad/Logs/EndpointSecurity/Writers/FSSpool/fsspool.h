/// Copyright 2022 Google LLC
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

#ifndef SANTA_SANTAD_LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H
#define SANTA_SANTAD_LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H

// Namespace ::fsspool::fsspool implements a filesystem-backed message spool, to
// use as a lock-free IPC mechanism.

#include <fcntl.h>
#include <sys/stat.h>

#include <algorithm>
#include <functional>
#include <optional>
#include <string>
#include <vector>

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
template <typename T>
class FsSpoolWriterPeer;
}

namespace fsspool {

template <typename T>
concept BatcherInterface =
    (std::default_initializable<T> || requires {
      T{std::declval<std::function<void()>>()};
    }) && requires(T batcher, int fd, std::vector<uint8_t> bytes) {
      { batcher.ShouldInitializeBeforeWrite() } -> std::same_as<bool>;
      { batcher.InitializeBatch(fd) } -> std::same_as<absl::Status>;
      { batcher.NeedToOpenFile() } -> std::same_as<bool>;
      { batcher.Write(bytes) } -> std::same_as<absl::Status>;
      { batcher.CompleteBatch(fd) } -> std::same_as<absl::StatusOr<size_t>>;
    };

// Default modes used when no mode is configured. Preserves the behavior Santa
// shipped before the mode became configurable.
inline constexpr mode_t kDefaultSpoolFileMode = 0400;
inline constexpr mode_t kDefaultSpoolDirMode = 0700;

// Derives a directory mode from a file mode by granting execute (i.e. traverse)
// permission to each class that was granted read, so that a group-readable
// spool file is actually reachable through the directories above it. Each
// class's execute bit sits two positions below its read bit, so the read bits
// shifted down are exactly the execute bits to add.
inline constexpr mode_t DirectoryModeForFileMode(mode_t file_mode) {
  return file_mode | ((file_mode & 0444) >> 2);
}

// Enqueues messages into the spool. Multiple concurrent writers can
// write to the same directory. (Note that this class is only thread-compatible
// and not thread-safe though!)
template <BatcherInterface T>
class FsSpoolWriter {
 public:
  // The base, spool, and temporary directory will be created as needed on the
  // first call to Write() - however the base directory can be created into an
  // existing path (i.e. this class will not do an `mkdir -p`).
  // `eviction_callback`, when set, is invoked with the number of spool files
  // erased whenever the spool exceeds its size limit and the oldest files are
  // evicted to make room. Used to surface an eviction metric without coupling
  // this generic spool library to a particular metrics implementation.
  // `file_mode`, when non-zero, is the permission mode applied to each spool
  // file; the spool directories get the corresponding directory mode. Zero
  // means use the defaults above.
  FsSpoolWriter(T batcher, absl::string_view base_dir, size_t max_spool_size,
                std::function<void(size_t)> eviction_callback = nullptr,
                mode_t file_mode = 0)
      : batcher_(std::move(batcher)),
        base_dir_(base_dir),
        spool_dir_(SpoolNewDirectory(base_dir)),
        tmp_dir_(SpoolTempDirectory(base_dir)),
        space_check_failure_since_last_flush_(false),
        max_spool_size_(max_spool_size),
        eviction_callback_(std::move(eviction_callback)),
        mode_configured_(file_mode != 0),
        file_mode_(file_mode ? file_mode : kDefaultSpoolFileMode),
        dir_mode_(file_mode ? DirectoryModeForFileMode(file_mode)
                            : kDefaultSpoolDirMode),
        id_(absl::StrFormat(
            "%016x",
            absl::Uniform<uint64_t>(absl::BitGen(), 0,
                                    std::numeric_limits<uint64_t>::max()))),
        // Guess that the spool is full during construction, so we will
        // recompute the actual spool size on the first write.
        spool_size_estimate_(max_spool_size + 1) {
    (void)IterateDirectory(
        tmp_dir_, [this](const std::string& file_name, bool* stop) {
          if (file_name == std::string(".") || file_name == std::string("..")) {
            return;
          }
          std::string full_path =
              absl::StrCat(tmp_dir_, PathSeparator(), file_name);
          struct stat sb;
          if (lstat(full_path.c_str(), &sb) == 0 &&
              (S_ISLNK(sb.st_mode) || S_ISREG(sb.st_mode))) {
            (void)Unlink(full_path.c_str());
          }
        });

    // Spool files already on disk were written with whatever mode was
    // configured at the time, so after a mode change the files waiting to be
    // exported would stay unreadable to the very group the new mode grants.
    // Re-apply it once here rather than on every flush: the mode is read at
    // santad startup, which is also when this runs, so there is nothing later
    // to catch up with.
    //
    // Only root can create entries in the spool directory (the configured mode
    // is never group- or world-writable), so nothing untrusted can plant a
    // symlink between the lstat and the chmod. LChmod rather than Chmod
    // regardless, so a link that somehow is there - e.g. a SpoolDirectory
    // pointed at a location others can write - is never followed.
    if (mode_configured_) {
      (void)IterateDirectory(
          spool_dir_, [this](const std::string& file_name, bool* stop) {
            std::string full_path =
                absl::StrCat(spool_dir_, PathSeparator(), file_name);
            struct stat sb;
            if (lstat(full_path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode)) {
              (void)::fsspool::LChmod(full_path.c_str(), file_mode_);
            }
          });
    }
  }

  ~FsSpoolWriter() { (void)Flush(); };

  absl::Status SpaceAvailable() {
    if (spool_size_estimate_ <= max_spool_size_) {
      return absl::OkStatus();
    }

    // Recompute the spool size with a single directory walk, also collecting
    // per-file metadata so eviction (below) can reuse it instead of walking and
    // stat()ing every file a second time.
    std::vector<DirEntryInfo> files;
    absl::StatusOr<size_t> estimate = EstimateSpoolDirSize(&files);
    if (!estimate.ok()) {
      return estimate.status();  // failed to recompute spool size
    }
    spool_size_estimate_ = *estimate;

    if (spool_size_estimate_ > max_spool_size_) {
      // Over the limit: rather than dropping all new telemetry, erase the
      // oldest spool files to make room. This keeps the freshest data flowing
      // (and lets signal processing continue) at the cost of the oldest,
      // not-yet-exported files. Updates spool_size_estimate_ to the
      // post-eviction total.
      EvictOldestSpoolFiles(files, *estimate);

      // If eviction couldn't free enough space (e.g. unlinks failing on a
      // read-only remount or immutable files), keep the spool bounded by
      // refusing the write rather than letting it grow without limit.
      if (spool_size_estimate_ > max_spool_size_) {
        return absl::ResourceExhaustedError("No space left in spool directory");
      }
    }

    return absl::OkStatus();
  }

  absl::Status InitializeCurrentSpoolStateIfNeeded() {
    if (current_spool_state_.IsOpen()) {
      return absl::OkStatus();
    }

    if (!batcher_.NeedToOpenFile()) {
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
                        O_WRONLY | O_CREAT | O_TRUNC, file_mode_);
    if (current_spool_state_.tmp_fd < 0) {
      return absl::ErrnoToStatus(errno, "open() failed");
    }

    // open(2) applies the process umask to `file_mode_`, which would silently
    // withhold the access the mode was configured to grant. Set it exactly,
    // while the file is still in tmp/. Only when a mode was explicitly
    // configured: without one, open(2)'s umask-adjusted result is the behavior
    // Santa has always had. Best effort, as for the directories below - umask
    // can only narrow what open(2) applied, never widen it, so a failure here
    // can't leave the file more permissive than configured.
    if (mode_configured_) {
      (void)::fsspool::FChmod(current_spool_state_.tmp_fd, file_mode_);
    }

    return batcher_.InitializeBatch(current_spool_state_.tmp_fd);
  }

  // Completes the in-progress spool file (if any), renaming it from the tmp
  // directory into the spool directory. Returns the path of the just-completed
  // spool file, or std::nullopt when no file was open.
  absl::StatusOr<std::optional<std::string>> CompleteCurrentSpoolState() {
    if (!current_spool_state_.IsOpen()) {
      return std::optional<std::string>(std::nullopt);
    }

    absl::StatusOr<size_t> size_estimate =
        batcher_.CompleteBatch(current_spool_state_.tmp_fd);
    ::fsspool::Close(current_spool_state_.tmp_fd);
    current_spool_state_.tmp_fd = -1;

    if (!size_estimate.ok()) {
      (void)Unlink(current_spool_state_.tmp_file.c_str());
      return size_estimate.status();
    }

    spool_size_estimate_ += *size_estimate;

    if (absl::Status status = RenameFile(current_spool_state_.tmp_file,
                                         current_spool_state_.spool_file);
        !status.ok()) {
      (void)Unlink(current_spool_state_.tmp_file.c_str());
      return status;
    }

    return std::optional<std::string>(current_spool_state_.spool_file);
  }

  // Returns ResourceExhaustedError the first time no space is available
  // since last flush
  // Returns DataLossError if writes weren't attempted due to a previous
  // space check failure
  // Otherwise returns OK or an appropriate failure status
  absl::Status Write(std::vector<uint8_t> bytes) {
    // Initializer the batcher before write if required
    if (batcher_.ShouldInitializeBeforeWrite()) {
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

  // Flushes the in-progress spool file. Returns the path of the just-completed
  // spool file, or std::nullopt when no file was open.
  absl::StatusOr<std::optional<std::string>> Flush() {
    // If the batcher wasn't initialized before Write, it must be initialized
    // now
    if (!batcher_.ShouldInitializeBeforeWrite()) {
      if (absl::Status status = InitializeCurrentSpoolStateIfNeeded();
          !status.ok()) {
        return status;
      }
    }

    absl::StatusOr<std::optional<std::string>> result =
        CompleteCurrentSpoolState();
    space_check_failure_since_last_flush_ = false;
    return result;
  }

  friend class fsspool::FsSpoolWriterPeer<T>;

 private:
  // Makes sure that all the required
  // directories needed for correct operation of this Writer are present in the
  // filesystem.
  absl::Status BuildDirectoryStructureIfNeeded() {
    if (!IsDirectory(spool_dir_)) {
      if (!IsDirectory(base_dir_)) {
        if (absl::Status status = MkDir(base_dir_, dir_mode_); !status.ok()) {
          return status;  // failed to create base directory
        }
      }

      if (absl::Status status = MkDir(spool_dir_, dir_mode_); !status.ok()) {
        return status;  // failed to create spool directory;
      }
    }
    if (!IsDirectory(tmp_dir_)) {
      // No need to check the base directory too, since spool_dir_ exists.
      if (absl::Status status = MkDir(tmp_dir_, dir_mode_); !status.ok()) {
        return status;  // failed to create tmp directory
      }
    }

    // MkDir is a no-op on a directory that already exists, so a spool laid down
    // by an earlier Santa (or before the mode was configured) would keep its
    // old mode and hide the files inside it. Re-assert the mode on each
    // directory. Only done when a mode was explicitly configured, so an
    // unconfigured Santa leaves whatever mode the directories already carry
    // alone. Best effort: a chmod that fails shouldn't stop telemetry being
    // written.
    //
    // Through an fd opened O_NOFOLLOW rather than by pathname, so a symlink
    // standing in for a spool directory is never chmod'd through: in a
    // SpoolDirectory others can write, that would hand a non-root account a
    // root-owned chmod of any path it cares to name. O_DIRECTORY makes the fd
    // a directory by construction.
    if (mode_configured_) {
      for (const std::string& dir : {base_dir_, spool_dir_, tmp_dir_}) {
        int fd = ::fsspool::Open(dir.c_str(),
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW, 0);
        if (fd < 0) {
          continue;
        }
        (void)::fsspool::FChmod(fd, dir_mode_);
        (void)::fsspool::Close(fd);
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

  // Returns the on-disk size of the spool directory via a single bulk scan
  // (no stat() per file). When `files` is non-null it is also populated with
  // the per-file metadata gathered during that scan, so callers needing to
  // evict can avoid a second scan of the directory.
  absl::StatusOr<size_t> EstimateSpoolDirSize(
      std::vector<DirEntryInfo>* files = nullptr) {
    return BulkStatRegularFiles(spool_dir_, files);
  }

  // Deletes the oldest spool files until the estimated on-disk size of the
  // spool directory drops below the low-water mark (90% of max_spool_size_).
  // Evicting to a low-water mark rather than to exactly the limit frees ~10%
  // of headroom so eviction doesn't immediately recur on the next few writes.
  // `files`/`total` come from the caller's directory walk, so no second walk is
  // needed. Updates spool_size_estimate_ to the post-eviction total.
  // Best-effort: a file that fails to unlink is left in place and skipped.
  void EvictOldestSpoolFiles(std::vector<DirEntryInfo>& files, size_t total) {
    const size_t low_water_mark = max_spool_size_ - max_spool_size_ / 10;

    // Oldest first.
    std::sort(files.begin(), files.end(),
              [](const DirEntryInfo& a, const DirEntryInfo& b) {
                return a.mtime < b.mtime;
              });

    size_t evicted = 0;
    for (const DirEntryInfo& file : files) {
      if (total <= low_water_mark) {
        break;
      }
      if (Unlink(file.path.c_str()) == 0) {
        total -= file.occupancy;
        evicted++;
      }
    }

    spool_size_estimate_ = total;

    if (evicted > 0 && eviction_callback_) {
      eviction_callback_(evicted);
    }
  }

  struct CurrentSpoolState {
    CurrentSpoolState() : tmp_fd(-1) {}

    bool IsOpen() { return tmp_fd >= 0; }

    std::string spool_file;
    std::string tmp_file;
    int tmp_fd;
  };

  T batcher_;
  const std::string base_dir_;
  const std::string spool_dir_;
  const std::string tmp_dir_;
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

  // Invoked (when set) with the number of spool files erased during an
  // eviction.
  std::function<void(size_t)> eviction_callback_;

  // Whether a mode was explicitly configured, as opposed to the modes below
  // having been filled in with the built-in defaults.
  const bool mode_configured_;

  // Permission modes applied to spool files and to the directories holding
  // them. Always resolved to a concrete mode by the constructor.
  const mode_t file_mode_;
  const mode_t dir_mode_;

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

#endif  // SANTA_SANTAD_LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOL_H
