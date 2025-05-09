/// Copyright 2022 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
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

#include "Source/santad/Logs/EndpointSecurity/Logger.h"

#include <Foundation/Foundation.h>
#include <sys/stat.h>

#include <utility>

#import "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTLogging.h"
#include "Source/common/SNTStoredEvent.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Null.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#include "Source/santad/SNTDecisionCache.h"
#import "Source/santad/SNTSyncdQueue.h"
#include "absl/container/flat_hash_map.h"

namespace santa {

// Flush the write buffer every 5 seconds
static constexpr uint64_t kFlushBufferTimeoutMS = 10000;
// Batch writes up to 128kb
static constexpr size_t kBufferBatchSizeBytes = (1024 * 128);
// Reserve an extra 4kb of buffer space to account for event overflow
static constexpr size_t kMaxExpectedWriteSizeBytes = 4096;
// Minimum allowable telemetry export frequency.
// Semi-arbitrary. Goal is to protect against too much strain on the export path.
static constexpr uint32_t kMinTelemetryExportIntervalSecs = 60;
// Max time to wait for the sync service to export a file.
// Should be slightly smaller than kMinTelemetryExportIntervalSecs to
// prevent overlapping runs.
static constexpr uint32_t kMinTelemetryExportTimeoutSecs = kMinTelemetryExportIntervalSecs - 2;

// Translate configured log type to appropriate Serializer/Writer pairs
std::unique_ptr<Logger> Logger::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                       SNTSyncdQueue *syncd_queue, TelemetryEvent telemetry_mask,
                                       SNTEventLogType log_type, SNTDecisionCache *decision_cache,
                                       NSString *event_log_path, NSString *spool_log_path,
                                       size_t spool_dir_size_threshold,
                                       size_t spool_file_size_threshold,
                                       uint64_t spool_flush_timeout_ms,
                                       uint32_t telemetry_export_seconds) {
  std::unique_ptr<Logger> logger;

  switch (log_type) {
    case SNTEventLogTypeFilelog:
      logger = std::make_unique<Logger>(
          syncd_queue, telemetry_mask, BasicString::Create(esapi, std::move(decision_cache)),
          File::Create(event_log_path, kFlushBufferTimeoutMS, kBufferBatchSizeBytes,
                       kMaxExpectedWriteSizeBytes));
      break;
    case SNTEventLogTypeSyslog:
      logger = std::make_unique<Logger>(
          syncd_queue, telemetry_mask, BasicString::Create(esapi, std::move(decision_cache), false),
          Syslog::Create());
      break;
    case SNTEventLogTypeNull:
      logger =
          std::make_unique<Logger>(syncd_queue, telemetry_mask, Empty::Create(), Null::Create());
      break;
    case SNTEventLogTypeProtobuf:
      logger = std::make_unique<Logger>(
          syncd_queue, telemetry_mask, Protobuf::Create(esapi, std::move(decision_cache)),
          Spool::Create([spool_log_path UTF8String], spool_dir_size_threshold,
                        spool_file_size_threshold, spool_flush_timeout_ms));
      break;
    case SNTEventLogTypeJSON:
      logger = std::make_unique<Logger>(
          syncd_queue, telemetry_mask, Protobuf::Create(esapi, std::move(decision_cache), true),
          File::Create(event_log_path, kFlushBufferTimeoutMS, kBufferBatchSizeBytes,
                       kMaxExpectedWriteSizeBytes));
      break;
    default: LOGE(@"Invalid log type: %ld", log_type); return nullptr;
  }

  logger->SetTimerInterval(telemetry_export_seconds);

  return logger;
}

Logger::Logger(SNTSyncdQueue *syncd_queue, TelemetryEvent telemetry_mask,
               std::shared_ptr<santa::Serializer> serializer, std::shared_ptr<santa::Writer> writer)
    : Timer<Logger>(kMinTelemetryExportIntervalSecs),
      syncd_queue_(syncd_queue),
      telemetry_mask_(telemetry_mask),
      serializer_(std::move(serializer)),
      writer_(std::move(writer)) {
  export_queue_ = dispatch_queue_create("com.northpolesec.santa.daemon.export",
                                        DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
}

void Logger::SetTelemetryMask(TelemetryEvent mask) {
  telemetry_mask_ = mask;
}

void Logger::OnTimer() {
  ExportTelemetry();
}

void Logger::ExportTelemetry() {
  dispatch_sync(export_queue_, ^{
    ExportTelemetrySerialized();
  });
}

void Logger::ExportTelemetrySerialized() {
  dispatch_group_t group = dispatch_group_create();

  // Track which files have been provided by the writer for exporting as well
  // as their export status so the writer can know which ones to clean up.
  __block absl::flat_hash_map<std::string, bool> files_exported;

  while (std::optional<std::string> file_to_export = writer_->NextFileToExport()) {
    NSString *path = @((*file_to_export).c_str());

    NSFileHandle *handle = [NSFileHandle fileHandleForReadingAtPath:path];
    if (!handle) {
      LOGW(@"Failed to get a file handle for telemetry file to export: %@", path);
      files_exported.insert_or_assign(*file_to_export, true);
      continue;
    }

    struct stat sb;
    if (fstat(handle.fileDescriptor, &sb) != 0) {
      LOGW(@"Failed to stat telemetry file to export: %@", path);
      files_exported.insert_or_assign(*file_to_export, true);
      continue;
    }

    if (!S_ISREG(sb.st_mode)) {
      LOGW(@"Telemetry file to export is not a regular file: %@", path);
      files_exported.insert_or_assign(*file_to_export, true);
      continue;
    }

    // Track all files as initially unsuccessfully processed
    // in case the export times out.
    files_exported.insert_or_assign(*file_to_export, false);

    dispatch_group_enter(group);
    [syncd_queue_ exportTelemetryFile:handle
                    completionHandler:^(BOOL success) {
                      [handle closeFile];
                      files_exported.insert_or_assign(*file_to_export, success);
                      dispatch_group_leave(group);
                    }];
  }

  if (dispatch_group_wait(
          group, dispatch_time(DISPATCH_TIME_NOW, kMinTelemetryExportTimeoutSecs * NSEC_PER_SEC))) {
    LOGW(@"Timed out waiting for telemetry to export.");
  }

  writer_->FilesExported(files_exported);
}

void Logger::Log(std::unique_ptr<EnrichedMessage> msg) {
  if (ShouldLog(msg->GetTelemetryEvent())) {
    writer_->Write(serializer_->SerializeMessage(std::move(msg)));
  }
}

void Logger::LogAllowlist(const Message &msg, const std::string_view hash) {
  if (ShouldLog(TelemetryEvent::kAllowlist)) {
    writer_->Write(serializer_->SerializeAllowlist(msg, hash));
  }
}

void Logger::LogBundleHashingEvents(NSArray<SNTStoredEvent *> *events) {
  if (ShouldLog(TelemetryEvent::kBundle)) {
    for (SNTStoredEvent *se in events) {
      writer_->Write(serializer_->SerializeBundleHashingEvent(se));
    }
  }
}

void Logger::LogDiskAppeared(NSDictionary *props) {
  if (ShouldLog(TelemetryEvent::kDisk)) {
    writer_->Write(serializer_->SerializeDiskAppeared(props));
  }
}

void Logger::LogDiskDisappeared(NSDictionary *props) {
  if (ShouldLog(TelemetryEvent::kDisk)) {
    writer_->Write(serializer_->SerializeDiskDisappeared(props));
  }
}

void Logger::LogFileAccess(const std::string &policy_version, const std::string &policy_name,
                           const santa::Message &msg,
                           const santa::EnrichedProcess &enriched_process,
                           const std::string &target, FileAccessPolicyDecision decision) {
  if (ShouldLog(TelemetryEvent::kFileAccess)) {
    writer_->Write(serializer_->SerializeFileAccess(policy_version, policy_name, msg,
                                                    enriched_process, target, decision));
  }
}

void Logger::Flush() {
  writer_->Flush();
}

void Logger::UpdateMachineIDLogging() const {
  serializer_->UpdateMachineID();
}

}  // namespace santa
