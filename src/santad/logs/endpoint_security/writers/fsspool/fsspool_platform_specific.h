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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLPLATFORMSPECIFIC_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLPLATFORMSPECIFIC_H

#include <functional>
#include <string>
#include <string_view>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace fsspool {

absl::string_view PathSeparator();
std::string SpoolNewDirectory(absl::string_view base_dir);
std::string SpoolTempDirectory(absl::string_view base_dir);
bool IsAbsolutePath(absl::string_view path);
bool IsDirectory(const std::string& d);
int Close(int fd);
int Open(const char* filename, int flags, mode_t mode);
absl::Status RenameFile(const std::string& src, const std::string& dst);
// Creates a directory if it doesn't exist.
// It only accepts absolute paths.
absl::Status MkDir(const std::string& path);
int MkDir(const char* path, mode_t mode);
bool StatIsDir(mode_t mode);
bool StatIsReg(mode_t mode);
int Unlink(const char* pathname);
int Write(int fd, absl::string_view buf);
// Writes a buffer to the given file descriptor.
// Calls to write can result in a partially written file. Very rare cases in
// which this could happen (since we're writing to a regular file) include
// if we receive a signal during write or if the disk is full.
// Retry writing until we've flushed everything, return an error if any write
// fails.
absl::Status WriteBuffer(int fd, absl::string_view msg);

absl::Status IterateDirectory(
    const std::string& dir,
    std::function<void(const std::string&, bool*)> callback);

absl::StatusOr<size_t> EstimateDirSize(const std::string& dir);

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLPLATFORMSPECIFIC_H
