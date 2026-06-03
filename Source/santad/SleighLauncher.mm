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

#include "Source/santad/SleighLauncher.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>
#include <string>

#include "absl/cleanup/cleanup.h"

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/String.h"
#include "commands/v1.pb.h"
#include "telemetry/sleighconfig.pb.h"

namespace santa {

std::unique_ptr<SleighLauncher> SleighLauncher::Create(std::string sleigh_path) {
  if (sleigh_path.empty()) {
    sleigh_path = kDefaultSleighPath;
  }
  return std::make_unique<SleighLauncher>(sleigh_path);
}

SleighLauncher::SleighLauncher(std::string sleigh_path) : sleigh_path_(std::move(sleigh_path)) {}

absl::Status SleighLauncher::LaunchTelemetryExport(const std::vector<std::string>& input_files,
                                                   uint32_t timeout_secs) {
  // Open all input files (as root) and collect FD numbers.
  std::vector<int> input_fds;
  absl::Cleanup close_fds = [&input_fds]() {
    for (int fd : input_fds) {
      close(fd);
    }
  };

  for (const auto& file : input_files) {
    int fd = open(file.c_str(), O_RDONLY);
    if (fd < 0) {
      LOGD(@"SleighLauncher::LaunchTelemetryExport(): Failed to open input file: %s", file.c_str());
      return absl::InternalError("Failed to open input file: " + file);
    }
    input_fds.push_back(fd);
  }

  absl::StatusOr<std::string> serialized = SerializeConfig(input_fds);
  if (!serialized.ok()) {
    LOGD(@"SleighLauncher::LaunchTelemetryExport(): Failed to serialize SleighConfig");
    return serialized.status();
  }

  // Hand fd ownership to RunSleigh, which closes them in the parent after fork.
  std::move(close_fds).Cancel();
  return RunSleigh(*serialized, input_fds, timeout_secs, /*capture_stdout=*/false).status();
}

absl::StatusOr<::santa::commands::v1::BinaryUploadResponse> SleighLauncher::LaunchBinaryUpload(
    int input_fd, const std::string& signed_post_url,
    const std::map<std::string, std::string>& form_values, const std::string& expected_sha256,
    const ::santa::telemetry::v1::BinaryMetadata& metadata,
    const std::vector<std::string>& filter_expressions, uint32_t timeout_seconds) {
  absl::StatusOr<std::string> serialized = SerializeBinaryUploadConfig(
      input_fd, signed_post_url, form_values, expected_sha256, metadata, filter_expressions);
  if (!serialized.ok()) {
    // RunSleigh closes input_fd on all later paths; on this pre-RunSleigh early
    // return we still own it, so close it here to avoid leaking the descriptor.
    close(input_fd);
    return serialized.status();
  }

  absl::StatusOr<std::string> output =
      RunSleigh(*serialized, {input_fd}, timeout_seconds, /*capture_stdout=*/true);
  if (!output.ok()) {
    return output.status();
  }

  // Do not trust a default-valued parse — an empty or unparseable stdout is an
  // error, not a COMPLETED-with-zero-bytes response.
  ::santa::commands::v1::BinaryUploadResponse response;
  if (output->empty() || !response.ParseFromString(*output)) {
    return absl::InternalError("Sleigh produced no parseable BinaryUploadResponse");
  }
  return response;
}

absl::StatusOr<std::string> SleighLauncher::RunSleigh(const std::string& serialized,
                                                      const std::vector<int>& input_fds,
                                                      uint32_t timeout_secs, bool capture_stdout) {
  // Close our copies of the inherited fds on every return path (the child keeps its
  // own copies across fork).
  absl::Cleanup close_fds = [&input_fds]() {
    for (int fd : input_fds) {
      close(fd);
    }
  };

  if (access(sleigh_path_.c_str(), X_OK) != 0) {
    return absl::NotFoundError("Sleigh binary not executable: " + sleigh_path_);
  }

  // Code signature check (ObjC, must happen before fork). Done before the pipes
  // exist so a rejected signature needs no pipe cleanup.
  if (absl::Status sig = VerifySleighCodeSignature(); !sig.ok()) {
    return sig;
  }

  // stdin pipe (config in).
  int stdin_pipe[2];
  if (pipe(stdin_pipe) != 0) {
    return absl::InternalError("Failed to create stdin pipe");
  }

  // stdout pipe (response out), only when capturing.
  int stdout_pipe[2] = {-1, -1};
  if (capture_stdout) {
    if (pipe(stdout_pipe) != 0) {
      close(stdin_pipe[0]);
      close(stdin_pipe[1]);
      return absl::InternalError("Failed to create stdout pipe");
    }
  }

  // Prepare argv (before fork, no ObjC in child).
  const char* sleigh_path_cstr = sleigh_path_.c_str();
  const char* argv[] = {sleigh_path_cstr, nullptr};

  pid_t pid = fork();
  if (pid < 0) {
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);
    if (capture_stdout) {
      close(stdout_pipe[0]);
      close(stdout_pipe[1]);
    }
    LOGD(@"SleighLauncher::RunSleigh(): fork() failed");
    return absl::InternalError("fork() failed");
  }

  if (pid == 0) {
    // Child process - only async-signal-safe functions from here.
    dup2(stdin_pipe[0], STDIN_FILENO);
    if (capture_stdout) {
      dup2(stdout_pipe[1], STDOUT_FILENO);
    }
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);
    if (capture_stdout) {
      close(stdout_pipe[0]);
      close(stdout_pipe[1]);
    }

    if (!DropRootPrivileges()) {
      _exit(126);
    }

    execv(sleigh_path_cstr, const_cast<char* const*>(argv));
    _exit(127);
  }

  // Parent process.
  close(stdin_pipe[0]);                     // Close read end of stdin pipe.
  fcntl(stdin_pipe[1], F_SETNOSIGPIPE, 1);  // Prevent SIGPIPE if child exits early.

  int stdout_read_fd = -1;
  if (capture_stdout) {
    close(stdout_pipe[1]);  // Parent only reads.
    stdout_read_fd = stdout_pipe[0];
  }
  absl::Cleanup close_stdout_read = [&stdout_read_fd]() {
    if (stdout_read_fd >= 0) {
      close(stdout_read_fd);
    }
  };

  // Write serialized config to stdin pipe.
  const char* data = serialized.data();
  size_t remaining = serialized.size();
  bool write_failed = false;
  while (remaining > 0) {
    ssize_t written = write(stdin_pipe[1], data, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        continue;
      }
      write_failed = true;
      break;
    }
    data += written;
    remaining -= written;
  }
  close(stdin_pipe[1]);

  if (write_failed) {
    kill(pid, SIGKILL);
    waitpid(pid, nullptr, 0);
    LOGD(@"SleighLauncher::RunSleigh(): Failed to write config to Sleigh stdin");
    return absl::InternalError("Failed to write config to Sleigh stdin");
  }

  // Read stdout to EOF (when capturing) and reap the child on a background queue,
  // bounded by a timeout on the main thread. Reading before waitpid collects the
  // full response; on timeout we SIGKILL, which closes the child's stdout and
  // unblocks the read.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block int child_status = 0;
  __block std::string captured;
  __block bool read_failed = false;

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    if (capture_stdout) {
      char buf[8192];
      ssize_t n;
      while ((n = read(stdout_read_fd, buf, sizeof(buf))) > 0) {
        captured.append(buf, static_cast<size_t>(n));
      }
      if (n < 0) {
        read_failed = true;
      }
    }
    waitpid(pid, &child_status, 0);
    dispatch_semaphore_signal(sema);
  });

  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, timeout_secs * NSEC_PER_SEC))) {
    // Timeout - kill the process and wait for the async read/waitpid to complete.
    kill(pid, SIGKILL);
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return absl::DeadlineExceededError("Sleigh timed out after " + std::to_string(timeout_secs) +
                                       " seconds");
  }

  if (read_failed) {
    return absl::InternalError("Failed to read Sleigh stdout");
  }

  if (WIFEXITED(child_status)) {
    int exit_code = WEXITSTATUS(child_status);
    if (exit_code != 0) {
      return absl::UnknownError("Sleigh exited with code " + std::to_string(exit_code));
    }
  } else {
    return absl::UnknownError("Sleigh terminated abnormally");
  }

  return captured;
}

absl::Status SleighLauncher::VerifySleighCodeSignature() {
  NSString* sleighNSPath = StringToNSString(sleigh_path_);
  MOLCodesignChecker* csc = [[MOLCodesignChecker alloc] initWithBinaryPath:sleighNSPath];
  if (!csc || ![csc.teamID isEqualToString:@"ZMCG7MLDV9"] ||
      csc.signatureFlags & kSecCodeSignatureAdhoc) {
    LOGD(@"SleighLauncher::VerifySleighCodeSignature(): Sleigh code signature is invalid");
#ifndef DEBUG
    return absl::FailedPreconditionError("Sleigh code signature is invalid");
#endif
  }
  return absl::OkStatus();
}

void SleighLauncher::PopulateHostInfo(::santa::telemetry::v1::SleighConfig* config) {
  NSString* machineID = [[SNTConfigurator configurator] machineID];
  config->set_host_id(machineID ? [machineID UTF8String] : "");
  NSString* hostName = [SNTSystemInfo longHostname];
  config->set_host_name(hostName ? [hostName UTF8String] : "");
}

absl::StatusOr<std::string> SleighLauncher::SerializeConfig(const std::vector<int>& input_fds) {
  ::santa::telemetry::v1::SleighConfig config;
  PopulateHostInfo(&config);

  auto* export_telemetry = config.mutable_export_telemetry();

  for (int fd : input_fds) {
    export_telemetry->add_input_fds(fd);
  }

  NSArray<NSString*>* filterExpressions =
      [[SNTConfigurator configurator] telemetryFilterExpressions];
  for (NSString* expr in filterExpressions) {
    export_telemetry->add_filter_expressions([expr UTF8String]);
  }

  // Convert export config to parameters for sleigh.
  SNTExportConfiguration* exportConfig = [[SNTConfigurator configurator] exportConfig];
  if (!exportConfig) {
    return absl::InvalidArgumentError("Export configuration is nil");
  }

  auto* signed_post = export_telemetry->mutable_signed_post();
  signed_post->set_url([[exportConfig.url absoluteString] UTF8String]);
  [exportConfig.formValues
      enumerateKeysAndObjectsUsingBlock:^(NSString* key, id value, BOOL* stop) {
        if (![value isKindOfClass:[NSString class]]) return;
        (*signed_post->mutable_form_values())[[key UTF8String]] = [value UTF8String];
      }];

  std::string serialized;
  if (!config.SerializeToString(&serialized)) {
    return absl::UnknownError("Failed to serialize SleighConfig proto");
  }
  return serialized;
}

absl::StatusOr<std::string> SleighLauncher::SerializeBinaryUploadConfig(
    int input_fd, const std::string& signed_post_url,
    const std::map<std::string, std::string>& form_values, const std::string& expected_sha256,
    const ::santa::telemetry::v1::BinaryMetadata& metadata,
    const std::vector<std::string>& filter_expressions) {
  ::santa::telemetry::v1::SleighConfig config;
  PopulateHostInfo(&config);

  auto* binary_upload = config.mutable_binary_upload();
  binary_upload->set_input_fd(input_fd);
  binary_upload->set_expected_sha256(expected_sha256);
  *binary_upload->mutable_metadata() = metadata;
  for (const auto& expr : filter_expressions) {
    binary_upload->add_filter_expressions(expr);
  }

  auto* signed_post = binary_upload->mutable_signed_post();
  signed_post->set_url(signed_post_url);
  for (const auto& [key, value] : form_values) {
    (*signed_post->mutable_form_values())[key] = value;
  }

  std::string serialized;
  if (!config.SerializeToString(&serialized)) {
    return absl::UnknownError("Failed to serialize SleighConfig proto");
  }
  return serialized;
}

}  // namespace santa
