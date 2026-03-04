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

#include <algorithm>
#include <atomic>
#include <memory>
#include <utility>

#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTExportConfiguration.h"
#include "Source/common/SNTLogging.h"
#include "Source/common/SNTStoredExecutionEvent.h"
#include "Source/common/SNTSystemInfo.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/BasicString.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Empty.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/AnyBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/ZstdOutputStream.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/File.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Null.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Spool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Syslog.h"
#include "Source/santad/SNTDecisionCache.h"
#include "Source/santad/SleighLauncher.h"
#include "absl/container/flat_hash_map.h"

namespace santa {

// Flush the write buffer every 5 seconds
static constexpr uint64_t kFlushBufferTimeoutMS = 10000;
// Batch writes up to 128kb
static constexpr size_t kBufferBatchSizeBytes = (1024 * 128);
// Reserve an extra 4kb of buffer space to account for event overflow
static constexpr size_t kMaxExpectedWriteSizeBytes = 4096;
// Minimum/maximum allowable telemetry export frequency.
// Semi-arbitrary. Goal is to protect against too much strain on the export path.
static constexpr uint32_t kMinTelemetryExportIntervalSecs = 60;
static constexpr uint32_t kMaxTelemetryExportIntervalSecs = 3600;

// Translate configured log type to appropriate Serializer/Writer pairs
std::unique_ptr<Logger> Logger::Create(
    std::shared_ptr<EndpointSecurityAPI> esapi,
    std::unique_ptr<santa::SleighLauncher> sleigh_launcher,
    GetExportConfigBlock getExportConfigBlock, TelemetryEvent telemetry_mask,
    SNTEventLogType log_type, SNTDecisionCache *decision_cache, NSString *event_log_path,
    NSString *spool_log_path, size_t spool_dir_size_threshold, size_t spool_file_size_threshold,
    uint64_t spool_flush_timeout_ms, uint32_t telemetry_export_seconds,
    uint32_t telemetry_export_timeout_seconds, uint32_t telemetry_export_batch_threshold_size_mb,
    uint32_t telemetry_export_max_files_per_batch) {
  std::shared_ptr<santa::Serializer> serializer;
  std::shared_ptr<santa::Writer> writer;

  switch (log_type) {
    case SNTEventLogTypeFilelog:
      serializer = BasicString::Create(esapi, std::move(decision_cache));
      writer = File::Create(event_log_path, kFlushBufferTimeoutMS, kBufferBatchSizeBytes,
                            kMaxExpectedWriteSizeBytes);
      break;
    case SNTEventLogTypeSyslog:
      serializer = BasicString::Create(esapi, std::move(decision_cache), false);
      writer = Syslog::Create();
      break;
    case SNTEventLogTypeNull:
      serializer = Empty::Create();
      writer = Null::Create();
      break;
    case SNTEventLogTypeProtobuf:
      serializer = Protobuf::Create(esapi, std::move(decision_cache));
      writer = Spool<::fsspool::AnyBatcher>::Create(
          ::fsspool::AnyBatcher(), [spool_log_path UTF8String], spool_dir_size_threshold,
          spool_file_size_threshold, spool_flush_timeout_ms);
      break;
    case SNTEventLogTypeProtobufStream:
      serializer = Protobuf::Create(esapi, std::move(decision_cache));
      writer = Spool<::fsspool::UncompressedStreamBatcher>::Create(
          ::fsspool::UncompressedStreamBatcher(), [spool_log_path UTF8String],
          spool_dir_size_threshold, spool_file_size_threshold, spool_flush_timeout_ms);
      break;
    case SNTEventLogTypeProtobufStreamGzip:
      serializer = Protobuf::Create(esapi, std::move(decision_cache));
      writer = Spool<::fsspool::GzipStreamBatcher>::Create(
          ::fsspool::GzipStreamBatcher(^(google::protobuf::io::ZeroCopyOutputStream *raw_stream) {
            return std::make_shared<google::protobuf::io::GzipOutputStream>(raw_stream);
          }),
          [spool_log_path UTF8String], spool_dir_size_threshold, spool_file_size_threshold,
          spool_flush_timeout_ms);
      break;
    case SNTEventLogTypeProtobufStreamZstd:
      serializer = Protobuf::Create(esapi, std::move(decision_cache));
      writer = Spool<::fsspool::ZstdStreamBatcher>::Create(
          ::fsspool::ZstdStreamBatcher(^(google::protobuf::io::ZeroCopyOutputStream *raw_stream) {
            return ::fsspool::ZstdOutputStream::Create(raw_stream);
          }),
          [spool_log_path UTF8String], spool_dir_size_threshold, spool_file_size_threshold,
          spool_flush_timeout_ms);
      break;
    case SNTEventLogTypeJSON:
      serializer = Protobuf::Create(esapi, std::move(decision_cache), true);
      writer = File::Create(event_log_path, kFlushBufferTimeoutMS, kBufferBatchSizeBytes,
                            kMaxExpectedWriteSizeBytes);
      break;
    default: LOGE(@"Invalid log type: %ld", log_type); return nullptr;
  }

  auto logger = std::make_unique<Logger>(
      std::move(sleigh_launcher), getExportConfigBlock, telemetry_mask,
      telemetry_export_timeout_seconds, telemetry_export_batch_threshold_size_mb,
      telemetry_export_max_files_per_batch, std::move(serializer), std::move(writer));

  logger->SetTimerInterval(telemetry_export_seconds);

  return logger;
}

Logger::Logger(std::unique_ptr<santa::SleighLauncher> sleigh_launcher,
               GetExportConfigBlock get_export_config_block, TelemetryEvent telemetry_mask,
               uint32_t telemetry_export_timeout_seconds,
               uint32_t telemetry_export_batch_threshold_size_mb,
               uint32_t telemetry_export_max_files_per_batch,
               std::shared_ptr<santa::Serializer> serializer, std::shared_ptr<santa::Writer> writer)
    : Timer<Logger>(kMinTelemetryExportIntervalSecs, kMaxTelemetryExportIntervalSecs,
                    Timer::OnStart::kFireImmediately, "TelemetryExportIntervalSec",
                    Logger::RescheduleMode::kTrailingEdge),
      sleigh_launcher_(std::move(sleigh_launcher)),
      get_export_config_block_(get_export_config_block),
      telemetry_mask_(telemetry_mask),
      serializer_(std::move(serializer)),
      writer_(std::move(writer)),
      tracker_(ExportTracker::Create()),
      export_batch_threshold_size_bytes_(std::make_unique<std::atomic_uint64_t>()),
      export_max_files_per_batch_(std::make_unique<std::atomic_uint32_t>()),
      export_timeout_secs_(std::make_unique<std::atomic_uint32_t>()) {
  // Provide a default block instead of leaving nil
  if (get_export_config_block_ == nil) {
    get_export_config_block_ = ^SNTExportConfiguration *() {
      return nil;
    };
  }

  export_queue_ = dispatch_queue_create("com.northpolesec.santa.daemon.export",
                                        DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);

  SetBatchThresholdSizeMB(telemetry_export_batch_threshold_size_mb);
  SetMaxFilesPerBatch(telemetry_export_max_files_per_batch);
  SetTelmetryExportTimeoutSecs(telemetry_export_timeout_seconds);
}

void Logger::SetBatchThresholdSizeMB(uint32_t val) {
  // Limit between 10 MB to 5 GB
  constexpr uint64_t mb_multiplier = 1024 * 1024;
  constexpr uint32_t upload_mb_min = 1;
  constexpr uint32_t upload_mb_max = 5120;

  uint32_t new_val = std::clamp(val, upload_mb_min, upload_mb_max);
  if (new_val != val) {
    LOGW(@"Export batch threshold size must be between %u and %u MB. Clamped to: %u", upload_mb_min,
         upload_mb_max, new_val);
  }

  export_batch_threshold_size_bytes_->store(new_val * mb_multiplier, std::memory_order_relaxed);
}

void Logger::SetMaxFilesPerBatch(uint32_t val) {
  // Ensure a sane max in order to limit the number of simultaneously opened files.
  // Limit between 1 to 100
  static constexpr uint32_t opened_min = 1;
  static constexpr uint32_t opened_max = 100;

  uint32_t new_val = std::clamp(val, opened_min, opened_max);

  if (new_val != val) {
    LOGW(@"Export max files per batch must be between %u and %u. Clamped to: %u", opened_min,
         opened_max, new_val);
  }

  export_max_files_per_batch_->store(new_val, std::memory_order_relaxed);
}

void Logger::SetTelmetryExportTimeoutSecs(uint32_t val) {
  static constexpr uint32_t timeout_min = 1;
  static constexpr uint32_t timeout_max = 600;

  uint32_t new_val = std::clamp(val, timeout_min, timeout_max);

  if (new_val != val) {
    LOGW(@"Export timeout must be between %u and %u seconds. Clamped to: %u", timeout_min,
         timeout_max, new_val);
  }

  export_timeout_secs_->store(new_val, std::memory_order_relaxed);
}

void Logger::SetTelemetryMask(TelemetryEvent mask) {
  telemetry_mask_ = mask;
}

bool Logger::OnTimer() {
  ExportTelemetry();
  return true;
}

void Logger::ExportTelemetry() {
  dispatch_sync(export_queue_, ^{
    ExportTelemetrySerialized();
  });
}

void Logger::ExportTelemetrySerialized() {
  // Check if sleigh launcher is available
  if (!sleigh_launcher_) {
    LOGW(@"Telemetry export enabled, but no Sleigh launcher configured.");
    return;
  }

  // Get a copy of the current export config to be used for the entire export
  SNTExportConfiguration *export_config = get_export_config_block_();
  if (!export_config) {
    LOGW(@"Telemetry export enabled, but no export configuration is set.");
    return;
  }

  uint32_t max_files_per_batch = export_max_files_per_batch_->load(std::memory_order_relaxed);
  uint64_t max_batch_size_bytes =
      export_batch_threshold_size_bytes_->load(std::memory_order_relaxed);
  bool continue_processing = true;

  while (continue_processing) {
    uint64_t total_bytes = 0;
    std::vector<std::string> files_to_export;

    continue_processing = false;

    while (std::optional<std::string> file_to_export = writer_->NextFileToExport()) {
      NSString *path = @((*file_to_export).c_str());

      struct stat sb;
      if (stat(path.fileSystemRepresentation, &sb) != 0) {
        LOGW(@"Failed to stat telemetry file to export: %@", path);
        tracker_.AckCompleted(*file_to_export);
        continue;
      }

      if (!S_ISREG(sb.st_mode)) {
        LOGW(@"Telemetry file to export is not a regular file: %@", path);
        tracker_.AckCompleted(*file_to_export);
        continue;
      }

      // Track all files as initially unsuccessfully processed
      // in case the export times out.
      tracker_.Track(*file_to_export);

      files_to_export.push_back(*file_to_export);
      total_bytes += sb.st_size;

      if (files_to_export.size() >= max_files_per_batch || total_bytes >= max_batch_size_bytes) {
        // Current batch is full
        continue_processing = true;
        break;
      }
    }

    if (files_to_export.empty()) {
      // Nothing left to process
      // Drain the tracker in case there were non-uploadable files encountered
      writer_->FilesExported(tracker_.Drain());
      break;
    }

    // Launch sleigh
    absl::Status result = sleigh_launcher_->Launch(
        files_to_export, export_timeout_secs_->load(std::memory_order_relaxed));

    if (result.ok()) {
      LOGD(@"Successfully exported %zu telemetry files via sleigh", files_to_export.size());
      for (const auto &file : files_to_export) {
        tracker_.AckCompleted(file);
      }
    } else {
      LOGE(@"Failed to export telemetry via sleigh: %s", std::string(result.message()).c_str());
      // Don't continue processing after a failure
      continue_processing = false;
    }

    writer_->FilesExported(tracker_.Drain());
  }
}

void Logger::Log(std::unique_ptr<EnrichedMessage> msg) {
  if (ShouldLog(msg->GetTelemetryEvent())) {
    writer_->Write(serializer_->SerializeMessage(std::move(msg)));
  }
}

void Logger::LogAllowlist(const Message &msg, const std::string_view hash,
                          const std::string_view target_path) {
  if (ShouldLog(TelemetryEvent::kAllowlist)) {
    writer_->Write(serializer_->SerializeAllowlist(msg, hash, target_path));
  }
}

void Logger::LogBundleHashingEvents(NSArray<SNTStoredExecutionEvent *> *events) {
  if (ShouldLog(TelemetryEvent::kBundle)) {
    for (SNTStoredExecutionEvent *se in events) {
      writer_->Write(serializer_->SerializeBundleHashingEvent(se));
    }
  }
}

void Logger::LogDiskAppeared(NSDictionary *props, bool allowed) {
  if (ShouldLog(TelemetryEvent::kDisk)) {
    writer_->Write(serializer_->SerializeDiskAppeared(props, allowed));
  }
}

void Logger::LogDiskDisappeared(NSDictionary *props) {
  if (ShouldLog(TelemetryEvent::kDisk)) {
    writer_->Write(serializer_->SerializeDiskDisappeared(props));
  }
}

void Logger::LogNetworkFlows(SNDProcessFlows *processFlows, struct timespec window_start,
                             struct timespec window_end) {
  writer_->Write(serializer_->SerializeNetworkFlows(processFlows, window_start, window_end));
}

void Logger::LogFileAccess(const std::string &policy_version, const std::string &policy_name,
                           const santa::Message &msg,
                           const santa::EnrichedProcess &enriched_process, size_t target_index,
                           std::optional<santa::EnrichedFile> enriched_event_target,
                           FileAccessPolicyDecision decision) {
  if (ShouldLog(TelemetryEvent::kFileAccess)) {
    writer_->Write(serializer_->SerializeFileAccess(policy_version, policy_name, msg,
                                                    enriched_process, target_index,
                                                    std::move(enriched_event_target), decision));
  }
}

void Logger::Flush() {
  writer_->Flush();
}

void Logger::UpdateMachineIDLogging() const {
  serializer_->UpdateMachineID();
}

}  // namespace santa
