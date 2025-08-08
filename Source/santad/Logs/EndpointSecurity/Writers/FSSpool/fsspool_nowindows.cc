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

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <functional>
#include <string>

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool_platform_specific.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"

namespace fsspool {

constexpr absl::string_view kSpoolDirName = "new";
constexpr absl::string_view kTmpDirName = "tmp";

absl::string_view PathSeparator() { return "/"; }

std::string SpoolNewDirectory(absl::string_view base_dir) {
  return absl::StrCat(base_dir, PathSeparator(), kSpoolDirName);
}

std::string SpoolTempDirectory(absl::string_view base_dir) {
  return absl::StrCat(base_dir, PathSeparator(), kTmpDirName);
}

bool IsDirectory(const std::string& d) {
  struct stat stats;
  if (stat(d.c_str(), &stats) < 0) {
    return false;
  }
  return StatIsDir(stats.st_mode);
}

bool IsAbsolutePath(absl::string_view path) {
  return absl::StartsWith(path, "/");
}

int Write(int fd, absl::string_view buf) {
  return ::write(fd, buf.data(), buf.size());
}

absl::Status WriteBuffer(int fd, absl::string_view msg) {
  while (!msg.empty()) {
    const int n_written = Write(fd, msg);
    if (n_written < 0) {
      return absl::ErrnoToStatus(errno, "write() failed");
    }
    msg.remove_prefix(n_written);
  }
  return absl::OkStatus();
}

int Unlink(const char* pathname) { return unlink(pathname); }

int MkDir(const char* path, mode_t mode) { return mkdir(path, mode); }

absl::Status MkDir(const std::string& path) {
  if (!IsAbsolutePath(path)) {
    return absl::InvalidArgumentError(
        absl::StrCat(path, " is not an absolute path."));
  }
  if (fsspool::MkDir(path.c_str(), 0700) < 0) {
    if (errno == EEXIST && IsDirectory(path)) {
      return absl::OkStatus();
    }
    return absl::ErrnoToStatus(errno, absl::StrCat("failed to create ", path));
  }
  return absl::OkStatus();
}

bool StatIsDir(mode_t mode) { return S_ISDIR(mode); }

bool StatIsReg(mode_t mode) { return S_ISREG(mode); }

int Open(const char* filename, int flags, mode_t mode) {
  return open(filename, flags, mode);
}

int Close(int fd) { return close(fd); }

absl::Status RenameFile(const std::string& src, const std::string& dst) {
  if (rename(src.c_str(), dst.c_str()) < 0) {
    return absl::ErrnoToStatus(
        errno, absl::StrCat("failed to rename ", src, " to ", dst));
  }
  return absl::OkStatus();
}

absl::Status IterateDirectory(
    const std::string& dir,
    std::function<void(const std::string&, bool*)> callback) {
  if (!IsDirectory(dir)) {
    return absl::InvalidArgumentError(
        absl::StrFormat("%s is not a directory", dir));
  }
  DIR* dp = opendir(dir.c_str());
  if (dp == nullptr) {
    return absl::ErrnoToStatus(errno, absl::StrCat("failed to open ", dir));
  }
  struct dirent* ep;
  bool stop = false;
  while (!stop && ((ep = readdir(dp)) != nullptr)) {
    callback(ep->d_name, &stop);
  }
  closedir(dp);
  return absl::OkStatus();
}

size_t EstimateDiskOccupation(size_t fileSize) {
  // kDiskClusterSize defines the typical size of a disk cluster (4KiB).
  static constexpr size_t kDiskClusterSize = 4096;
  size_t n_clusters = (fileSize + kDiskClusterSize - 1) / kDiskClusterSize;
  // Empty files still occupy some space.
  if (n_clusters == 0) {
    n_clusters = 1;
  }
  return n_clusters * kDiskClusterSize;
}

absl::StatusOr<size_t> EstimateDirSize(const std::string& dir) {
  size_t estimate = 0;
  absl::Status status = IterateDirectory(
      dir, [&dir, &estimate](const std::string& file_name, bool* stop) {
        /// NOMUTANTS--We could skip this condition altogether, as S_ISREG on
        /// the directory would be false anyway.
        if (file_name == std::string(".") || file_name == std::string("..")) {
          return;
        }
        std::string file_path = absl::StrCat(dir, PathSeparator(), file_name);
        struct stat stats;
        if (stat(file_path.c_str(), &stats) < 0) {
          return;
        }
        if (!StatIsReg(stats.st_mode)) {
          return;
        }
        // Use st_size, as st_blocks is not available on Windows.
        estimate += EstimateDiskOccupation(stats.st_size);
      });
  if (status.ok()) {
    return estimate;
  }
  return status;
}

}  // namespace fsspool
