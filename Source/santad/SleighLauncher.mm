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

#include <atomic>
#include <memory>

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTExportConfiguration.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSystemInfo.h"
#include "telemetry/sleighconfig.pb.h"

namespace santa {

std::unique_ptr<SleighLauncher> SleighLauncher::Create(NSString *sleigh_path,
                                                       uint32_t timeout_seconds) {
  if (!sleigh_path) {
    sleigh_path = @(kDefaultSleighPath);
  }

  return std::make_unique<SleighLauncher>(sleigh_path, timeout_seconds);
}

SleighLauncher::SleighLauncher(NSString *sleigh_path, uint32_t timeout_seconds)
    : sleigh_path_(sleigh_path),
      timeout_seconds_(std::make_unique<std::atomic_uint32_t>(timeout_seconds)) {}

void SleighLauncher::SetTimeoutSeconds(uint32_t timeout_seconds) {
  timeout_seconds_->store(timeout_seconds, std::memory_order_relaxed);
}

SleighResult SleighLauncher::Launch(const std::vector<std::string> &input_files) {
  // Check Sleigh binary exists and is correctly signed.
  MOLCodesignChecker *csc = [[MOLCodesignChecker alloc] initWithBinaryPath:sleigh_path_];
  if (!csc || ![csc.teamID isEqualToString:@"ZMCG7MLDV9"] ||
      csc.signatureFlags & kSecCodeSignatureAdhoc) {
    LOGD(@"SleighLauncher::Launch(): Sleigh code signature is invalid");
#ifndef DEBUG
    return SleighResult{
        .success = false,
        .exit_code = -1,
        .error_message = "Sleigh code signature is invalid",
    };
#endif
  }

  absl::StatusOr<std::string> serialized = SerializeConfig(input_files);
  if (!serialized.ok()) {
    LOGD(@"SleighLauncher::Launch(): Failed to serialize SleighConfig");
    return SleighResult{
        .success = false,
        .exit_code = -1,
        .error_message = "Failed to serialize SleighConfig protobuf",
    };
  }
  NSData *configData = [NSData dataWithBytes:serialized->data() length:serialized->size()];

  // Set up NSTask
  NSTask *task = [[NSTask alloc] init];
  task.executableURL = [NSURL fileURLWithPath:sleigh_path_];

  // Set up stdin pipe
  NSPipe *stdinPipe = [NSPipe pipe];
  task.standardInput = stdinPipe;

  // Start the process
  NSError *error;
  if (![task launchAndReturnError:&error]) {
    LOGD(@"SleighLauncher::Launch(): Failed to launch sleigh: %@", error);
    return SleighResult{
        .success = false,
        .exit_code = -1,
        .error_message =
            "Failed to launch sleigh: " + std::string([error.localizedDescription UTF8String]),
    };
  }
  // Write config to stdin and close
  NSFileHandle *stdinHandle = stdinPipe.fileHandleForWriting;
  @try {
    [stdinHandle writeData:configData];
    [stdinHandle closeFile];
  } @catch (NSException *e) {
    LOGD(@"SleighLauncher::Launch(): Failed to write config to Sleigh stdin: %@", e);
    [task terminate];
    return SleighResult{
        .success = false,
        .exit_code = -1,
        .error_message =
            "Failed to write config to sleigh stdin: " + std::string([e.reason UTF8String]),
    };
  }

  // Wait for completion with timeout
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);

  task.terminationHandler = ^(__unused NSTask *t) {
    dispatch_semaphore_signal(sema);
  };

  uint32_t timeout_secs = timeout_seconds_->load(std::memory_order_relaxed);
  if (dispatch_semaphore_wait(sema,
                              dispatch_time(DISPATCH_TIME_NOW, timeout_secs * NSEC_PER_SEC))) {
    // Timeout - kill the process
    [task terminate];
    return SleighResult{
        .success = false,
        .exit_code = -1,
        .error_message =
            "Sleigh process timed out after " + std::to_string(timeout_secs) + " seconds",
    };
  }

  // Check exit code
  int exitCode = task.terminationStatus;
  if (exitCode != 0) {
    std::string errorMsg = "Sleigh exited with code " + std::to_string(exitCode);

    return SleighResult{
        .success = false,
        .exit_code = exitCode,
        .error_message = errorMsg,
    };
  }

  return SleighResult{
      .success = true,
      .exit_code = 0,
      .error_message = "",
  };
}

absl::StatusOr<std::string> SleighLauncher::SerializeConfig(
    const std::vector<std::string> &input_files) {
  // Build the SleighConfig protobuf
  ::santa::telemetry::v1::SleighConfig config;
  NSString *machineID = [[SNTConfigurator configurator] machineID];
  config.set_host_id(machineID ? [machineID UTF8String] : "");
  std::string host_name = [[SNTSystemInfo longHostname] UTF8String];
  config.set_host_name(host_name);

  for (const auto &file : input_files) {
    config.add_input_files(file);
  }

  // filter_expressions left empty (reserved for future use)

  // Convert export config to parameters for sleigh
  SNTExportConfiguration *exportConfig = [[SNTConfigurator configurator] exportConfig];
  std::map<std::string, std::string> form_values;

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
