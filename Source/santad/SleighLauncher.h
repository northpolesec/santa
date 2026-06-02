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

#ifndef SANTA_SANTAD_SLEIGHLAUNCHER_H
#define SANTA_SANTAD_SLEIGHLAUNCHER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "commands/v1.pb.h"
#include "telemetry/sleighconfig.pb.h"

namespace santa {

class SleighLauncher {
 public:
  static constexpr std::string_view kDefaultSleighPath =
      "/Applications/Santa.app/Contents/MacOS/sleigh";

  static std::unique_ptr<SleighLauncher> Create(std::string sleigh_path);
  SleighLauncher(std::string sleigh_path);

  virtual ~SleighLauncher() = default;

  SleighLauncher(SleighLauncher&) = delete;
  SleighLauncher& operator=(SleighLauncher& rhs) = delete;

  // Telemetry export: open input_files (as root), hand the fds to a sleigh child,
  // and wait. sleigh's stdout is not captured. Behavior is unchanged from before
  // the RunSleigh refactor.
  virtual absl::Status Launch(const std::vector<std::string>& input_files,
                              uint32_t timeout_seconds);

  // Binary upload: hand an already-open fd to a sleigh child along with the signed
  // POST, the santa-computed metadata, and the CEL filter expressions, then capture
  // sleigh's stdout and parse it as a BinaryUploadResponse.
  //
  // The caller owns input_fd; this method closes it (in the parent) after fork.
  // A non-zero exit, or empty/unparseable stdout, is returned as an error — callers
  // map that to INTERNAL_ERROR and must NOT trust a default-valued parse (M5).
  virtual absl::StatusOr<::santa::commands::v1::BinaryUploadResponse> LaunchBinaryUpload(
      int input_fd, const std::string& signed_post_url,
      const std::map<std::string, std::string>& form_values, const std::string& expected_sha256,
      const ::santa::telemetry::v1::BinaryMetadata& metadata,
      const std::vector<std::string>& filter_expressions, uint32_t timeout_seconds);

 protected:
  // Verifies the sleigh binary's code signature before exec. Returns Ok when the
  // signature is acceptable (and, in DEBUG builds, always — sleigh is unsigned during
  // local development). Virtual so tests can override it; production enforces it.
  virtual absl::Status VerifySleighCodeSignature();

 private:
  std::string sleigh_path_;

  // Sets host_id/host_name on a SleighConfig.
  void PopulateHostInfo(::santa::telemetry::v1::SleighConfig* config);

  absl::StatusOr<std::string> SerializeConfig(const std::vector<int>& input_fds);

  absl::StatusOr<std::string> SerializeBinaryUploadConfig(
      int input_fd, const std::string& signed_post_url,
      const std::map<std::string, std::string>& form_values, const std::string& expected_sha256,
      const ::santa::telemetry::v1::BinaryMetadata& metadata,
      const std::vector<std::string>& filter_expressions);

  // Forks sleigh, writes the serialized config to its stdin, optionally captures
  // its stdout, and waits up to timeout_secs (SIGKILL on timeout). Closes every fd
  // in input_fds in the parent (the child inherited its own copies across fork).
  // Returns the captured stdout (empty when capture_stdout is false).
  absl::StatusOr<std::string> RunSleigh(const std::string& serialized,
                                        const std::vector<int>& input_fds, uint32_t timeout_secs,
                                        bool capture_stdout);
};

}  // namespace santa

#endif  // SANTA_SANTAD_SLEIGHLAUNCHER_H
