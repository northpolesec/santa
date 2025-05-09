/// Copyright 2022 Google Inc. All rights reserved.
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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_WRITER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_WRITER_H

#include <optional>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

namespace santa {

class Writer {
 public:
  virtual ~Writer() = default;

  virtual void Write(std::vector<uint8_t> &&bytes) = 0;
  virtual void Flush() = 0;

  virtual std::optional<absl::flat_hash_set<std::string>> GetFilesToExport(
      size_t max_count) {
    return std::nullopt;
  }

  virtual std::optional<std::string> NextFileToExport() { return std::nullopt; }

  virtual void FilesExported(
      absl::flat_hash_map<std::string, bool> files_exported) {
    // no-op
  }
};

}  // namespace santa

#endif
