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

  // Telemetry export: open input_files (as root), hand the FDs to a Sleigh
  // child, and wait. Sleigh's stdout is not captured. Behavior is unchanged
  // from before the RunSleigh refactor.
  virtual absl::Status LaunchTelemetryExport(
      const std::vector<std::string>& input_files, uint32_t timeout_seconds);

  // Binary upload: hand an already-open FD to a Sleigh child along with the
  // signed POST, the Santa-computed metadata, and the CEL filter expressions,
  // then capture Sleigh's stdout and parse it as a BinaryUploadResponse.
  //
  // The caller owns input_fd; this method closes it (in the parent) after fork.
  // A non-zero exit, or empty/unparseable stdout, is returned as an error —
  // callers map that to INTERNAL_ERROR and must NOT trust a default-valued
  // parse.
  virtual absl::StatusOr<::santa::commands::v1::BinaryUploadResponse>
  LaunchBinaryUpload(int input_fd, const std::string& signed_post_url,
                     const std::map<std::string, std::string>& form_values,
                     const std::string& expected_sha256,
                     const ::santa::telemetry::v1::BinaryMetadata& metadata,
                     const std::vector<std::string>& filter_expressions,
                     uint32_t timeout_seconds);

  // Signal scan: open input_file (as root), hand the FD to a Sleigh child along
  // with the detection signals to evaluate (each a serialized
  // santa.common.v1.Signal), capture Sleigh's stdout, and parse it as a
  // SleighResponse. Sleigh uploads nothing; it only reports which signals
  // matched. An empty/unparseable stdout, or a non-zero exit, is returned as an
  // error. The caller passes signals in (from the synced signal_rules config);
  // this method does not read configuration.
  //
  // input_fd must be a readable fd positioned at offset 0. The caller retains
  // ownership of input_fd (this method scans a dup of it); holding that fd open
  // keeps the spool file's data readable even after the telemetry exporter
  // unlinks the path, so the scan and export need no coordination.
  virtual absl::StatusOr<::santa::telemetry::v1::SleighSignalScanResponse>
  LaunchSignalScan(int input_fd,
                   const std::vector<std::string>& serialized_signals,
                   uint32_t timeout_seconds);

 protected:
  // Verifies the Sleigh binary's code signature before exec. Returns Ok when
  // the signature is acceptable (and, in DEBUG builds, always — Sleigh is
  // unsigned during local development). Virtual so tests can override it;
  // production enforces it.
  virtual absl::Status VerifySleighCodeSignature();

 private:
  std::string sleigh_path_;

  // Sets host_id/host_name on a SleighConfig.
  void PopulateHostInfo(::santa::telemetry::v1::SleighConfig* config);

  absl::StatusOr<std::string> SerializeTelemetryUploadConfig(
      const std::vector<int>& input_fds);

  absl::StatusOr<std::string> SerializeBinaryUploadConfig(
      int input_fd, const std::string& signed_post_url,
      const std::map<std::string, std::string>& form_values,
      const std::string& expected_sha256,
      const ::santa::telemetry::v1::BinaryMetadata& metadata,
      const std::vector<std::string>& filter_expressions);

  absl::StatusOr<std::string> SerializeSignalScanConfig(
      int input_fd, const std::vector<std::string>& serialized_signals);

  // Forks Sleigh, writes the serialized config to its stdin, optionally
  // captures its stdout, and waits up to timeout_secs (SIGKILL on timeout).
  // Closes every fd in input_fds in the parent (the child inherited its own
  // copies across fork). Returns the captured stdout (empty when capture_stdout
  // is false).
  absl::StatusOr<std::string> RunSleigh(const std::string& serialized,
                                        const std::vector<int>& input_fds,
                                        uint32_t timeout_secs,
                                        bool capture_stdout);
};

}  // namespace santa

#endif  // SANTA_SANTAD_SLEIGHLAUNCHER_H
