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

#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <unistd.h>

#include <functional>
#include <memory>
#include <string>
#include <vector>

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

absl::StatusOr<size_t> BulkStatRegularFiles(
    const std::string& dir, std::vector<DirEntryInfo>* entries) {
  int fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    return absl::ErrnoToStatus(errno, absl::StrCat("failed to open ", dir));
  }

  struct attrlist attr_list;
  memset(&attr_list, 0, sizeof(attr_list));
  attr_list.bitmapcount = ATTR_BIT_MAP_COUNT;
  attr_list.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME |
                         ATTR_CMN_OBJTYPE | ATTR_CMN_MODTIME;
  attr_list.fileattr = ATTR_FILE_ALLOCSIZE;

  size_t total = 0;
  // 64KiB holds ~580 entries/call, so even a 15k-file spool is a couple dozen
  // syscalls rather than one stat() per file. Heap-allocated (uninitialized) to
  // keep it off the stack.
  constexpr size_t kBufSize = 64 * 1024;
  auto buf = std::make_unique_for_overwrite<char[]>(kBufSize);
  for (;;) {
    int count = getattrlistbulk(fd, &attr_list, buf.get(), kBufSize, 0);
    if (count < 0) {
      absl::Status status = absl::ErrnoToStatus(
          errno, absl::StrCat("getattrlistbulk failed on ", dir));
      close(fd);
      return status;
    }
    if (count == 0) {
      break;  // end of directory
    }

    char* entry = buf.get();
    for (int i = 0; i < count; i++) {
      // Fields are packed in attrlist order; copy them out to dodge alignment
      // issues. ATTR_CMN_RETURNED_ATTRS tells us which ones are actually
      // present.
      char* field = entry;
      uint32_t length;
      memcpy(&length, field, sizeof(length));
      field += sizeof(uint32_t);

      attribute_set_t returned;
      memcpy(&returned, field, sizeof(returned));
      field += sizeof(attribute_set_t);

      const char* name = nullptr;
      if (returned.commonattr & ATTR_CMN_NAME) {
        attrreference_t name_ref;
        memcpy(&name_ref, field, sizeof(name_ref));
        name = field + name_ref.attr_dataoffset;
        field += sizeof(attrreference_t);
      }

      fsobj_type_t obj_type = VNON;
      if (returned.commonattr & ATTR_CMN_OBJTYPE) {
        memcpy(&obj_type, field, sizeof(obj_type));
        field += sizeof(fsobj_type_t);
      }

      time_t mtime = 0;
      if (returned.commonattr & ATTR_CMN_MODTIME) {
        struct timespec mod_time;
        memcpy(&mod_time, field, sizeof(mod_time));
        field += sizeof(struct timespec);
        mtime = mod_time.tv_sec;
      }

      off_t alloc_size = 0;
      if (returned.fileattr & ATTR_FILE_ALLOCSIZE) {
        memcpy(&alloc_size, field, sizeof(alloc_size));
        field += sizeof(off_t);
      }

      if (obj_type == VREG) {
        total += static_cast<size_t>(alloc_size);
        if (entries != nullptr && name != nullptr) {
          entries->push_back({absl::StrCat(dir, PathSeparator(), name), mtime,
                              static_cast<size_t>(alloc_size)});
        }
      }

      entry += length;
    }
  }
  close(fd);
  return total;
}

absl::StatusOr<size_t> EstimateDirSize(const std::string& dir) {
  return BulkStatRegularFiles(dir, nullptr);
}

}  // namespace fsspool
