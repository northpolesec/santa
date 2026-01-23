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

#import <Foundation/Foundation.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"

namespace santa {

struct SleighResult {
  bool success;
  int exit_code;
  std::string error_message;
};

class SleighLauncher {
 public:
  static constexpr const char *kDefaultSleighPath = "/Applications/Santa.app/Contents/MacOS/sleigh";

  static std::unique_ptr<SleighLauncher> Create(NSString *sleigh_path, uint32_t timeout_seconds);

  SleighLauncher(NSString *sleigh_path, uint32_t timeout_seconds);

  virtual ~SleighLauncher() = default;

  SleighLauncher(SleighLauncher &&) = default;
  SleighLauncher &operator=(SleighLauncher &&rhs) = default;
  SleighLauncher(SleighLauncher &) = delete;
  SleighLauncher &operator=(SleighLauncher &rhs) = delete;

  virtual SleighResult Launch(const std::vector<std::string> &input_files);

  void SetTimeoutSeconds(uint32_t timeout_seconds);

 private:
  NSString *sleigh_path_;
  std::unique_ptr<std::atomic_uint32_t> timeout_seconds_;

  absl::StatusOr<std::string> SerializeConfig(const std::vector<std::string> &input_files);
};

}  // namespace santa

#endif
