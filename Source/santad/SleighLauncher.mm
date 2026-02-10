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

#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <memory>

#include "absl/cleanup/cleanup.h"

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDropRootPrivs.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "Source/common/String.h"
#include "telemetry/sleighconfig.pb.h"

namespace santa {

std::unique_ptr<SleighLauncher> SleighLauncher::Create(std::string sleigh_path) {
  if (sleigh_path.empty()) {
    sleigh_path = kDefaultSleighPath;
  }
  return std::make_unique<SleighLauncher>(sleigh_path);
}

SleighLauncher::SleighLauncher(std::string sleigh_path) : sleigh_path_(std::move(sleigh_path)) {}

absl::Status SleighLauncher::Launch(const std::vector<std::string> &input_files,
                                    uint32_t timeout_secs) {
  // Phase 1: Open all input files (as root) and collect FD numbers
  std::vector<int> input_fds;
  absl::Cleanup close_fds = [&input_fds]() {
    for (int fd : input_fds) {
      close(fd);
    }
  };

  for (const auto &file : input_files) {
    int fd = open(file.c_str(), O_RDONLY);
    if (fd < 0) {
      LOGD(@"SleighLauncher::Launch(): Failed to open input file: %s", file.c_str());
      return absl::InternalError("Failed to open input file: " + file);
    }
    input_fds.push_back(fd);
  }

  // Phase 2: Serialize config with FD numbers
  absl::StatusOr<std::string> serialized = SerializeConfig(input_fds);
  if (!serialized.ok()) {
    LOGD(@"SleighLauncher::Launch(): Failed to serialize SleighConfig");
    return absl::InternalError("Failed to serialize SleighConfig protobuf");
  }

  // Phase 3: Create stdin pipe
  int stdin_pipe[2];
  if (pipe(stdin_pipe) != 0) {
    LOGD(@"SleighLauncher::Launch(): Failed to create stdin pipe");
    return absl::InternalError("Failed to create stdin pipe");
  }

  // Phase 4: Code signature check (ObjC, must happen before fork)
  NSString *sleighNSPath = StringToNSString(sleigh_path_);
  MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:sleighNSPath];
  if (!csc || ![csc.teamID isEqualToString:@"ZMCG7MLDV9"] ||
      csc.signatureFlags & kSecCodeSignatureAdhoc) {
    LOGD(@"SleighLauncher::Launch(): Sleigh code signature is invalid");
#ifndef DEBUG
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);
    return absl::FailedPreconditionError("Sleigh code signature is invalid");
#endif
  }

  // Phase 5: Prepare argv (before fork, no ObjC in child)
  const char *sleigh_path_cstr = sleigh_path_.c_str();
  const char *argv[] = {sleigh_path_cstr, nullptr};

  // Phase 6: fork
  pid_t pid = fork();
  if (pid < 0) {
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);
    LOGD(@"SleighLauncher::Launch(): fork() failed");
    return absl::InternalError("fork() failed");
  }

  if (pid == 0) {
    // Child process - only async-signal-safe functions from here

    // Redirect stdin to read end of pipe
    dup2(stdin_pipe[0], STDIN_FILENO);
    close(stdin_pipe[0]);
    close(stdin_pipe[1]);

    // Drop root privileges
    if (!DropRootPrivileges()) {
      _exit(126);
    }

    // exec sleigh
    execv(sleigh_path_cstr, const_cast<char *const *>(argv));
    _exit(127);
  }

  // Parent process
  close(stdin_pipe[0]);                     // Close read end
  fcntl(stdin_pipe[1], F_SETNOSIGPIPE, 1);  // Prevent SIGPIPE if child exits
  std::move(close_fds).Invoke();            // Close input FDs (child inherited copies)

  // Write serialized config to stdin pipe
  const char *data = serialized->data();
  size_t remaining = serialized->size();
  bool write_failed = false;
  while (remaining > 0) {
    ssize_t written = write(stdin_pipe[1], data, remaining);
    if (written < 0) {
      if (errno == EINTR) {
        // Retry
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
    LOGD(@"SleighLauncher::Launch(): Failed to write config to Sleigh stdin");
    return absl::InternalError("Failed to write config to Sleigh stdin");
  }

  // Async waitpid with timeout using dispatch semaphore
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block int child_status = 0;

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    waitpid(pid, &child_status, 0);
    dispatch_semaphore_signal(sema);
  });

  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, timeout_secs * NSEC_PER_SEC))) {
    // Timeout - kill the process and wait for async waitpid to complete
    kill(pid, SIGKILL);
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return absl::DeadlineExceededError("Sleigh timed out after " + std::to_string(timeout_secs) +
                                       " seconds");
  }

  // Check exit code
  if (WIFEXITED(child_status)) {
    int exit_code = WEXITSTATUS(child_status);
    if (exit_code != 0) {
      return absl::UnknownError("Sleigh exited with code " + std::to_string(exit_code));
    }
  } else {
    return absl::UnknownError("Sleigh terminated abnormally");
  }

  return absl::OkStatus();
}

absl::StatusOr<std::string> SleighLauncher::SerializeConfig(const std::vector<int> &input_fds) {
  // Build the SleighConfig protobuf
  ::santa::telemetry::v1::SleighConfig config;
  NSString *machineID = [[SNTConfigurator configurator] machineID];
  config.set_host_id(machineID ? [machineID UTF8String] : "");
  std::string host_name = [[SNTSystemInfo longHostname] UTF8String];
  config.set_host_name(host_name);

  for (int fd : input_fds) {
    config.add_input_fds(fd);
  }

  // filter_expressions left empty (reserved for future use)

  // Convert export config to parameters for sleigh
  SNTExportConfiguration *exportConfig = [[SNTConfigurator configurator] exportConfig];
  if (!exportConfig) {
    return absl::InvalidArgumentError("Export configuration is nil");
  }

  auto *export_config = config.mutable_export_config();
  auto *signed_post = export_config->mutable_signed_post();
  signed_post->set_url([[exportConfig.url absoluteString] UTF8String]);
  [exportConfig.formValues
      enumerateKeysAndObjectsUsingBlock:^(NSString *key, id value, BOOL *stop) {
        if (![value isKindOfClass:[NSString class]]) return;
        (*signed_post->mutable_form_values())[[key UTF8String]] = [value UTF8String];
      }];

  // Serialize the protobuf
  std::string serialized;
  if (!config.SerializeToString(&serialized)) {
    return absl::UnknownError("Failed to serialize SleighConfig proto");
  }
  return serialized;
}

}  // namespace santa
