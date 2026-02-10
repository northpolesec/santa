/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA__SANTAD__SLEIGHLAUNCHER_H
#define SANTA__SANTAD__SLEIGHLAUNCHER_H

#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace santa {

class SleighLauncher {
 public:
  static constexpr std::string_view kDefaultSleighPath =
      "/Applications/Santa.app/Contents/MacOS/sleigh";

  static std::unique_ptr<SleighLauncher> Create(std::string sleigh_path);
  SleighLauncher(std::string sleigh_path);

  virtual ~SleighLauncher() = default;

  SleighLauncher(SleighLauncher &) = delete;
  SleighLauncher &operator=(SleighLauncher &rhs) = delete;

  virtual absl::Status Launch(const std::vector<std::string> &input_files,
                              uint32_t timeout_seconds);

 private:
  std::string sleigh_path_;

  absl::StatusOr<std::string> SerializeConfig(
      const std::vector<int> &input_fds);
};

}  // namespace santa

#endif
