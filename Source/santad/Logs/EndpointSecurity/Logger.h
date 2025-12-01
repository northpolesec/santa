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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_LOGGER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_LOGGER_H

#import <Foundation/Foundation.h>

#include <atomic>
#include <memory>
#include <string_view>

#import "Source/common/SNTCommonEnums.h"
#include "Source/common/TelemetryEventMap.h"
#include "Source/common/Timer.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/EventProviders/EndpointSecurity/EnrichedTypes.h"
#include "Source/santad/EventProviders/EndpointSecurity/Message.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Serializer.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"
#import "Source/santad/SNTDecisionCache.h"

// Forward declarations
@class SNTExportConfiguration;
@class SNTStoredExecutionEvent;
@class SNTSyncdQueue;
namespace santa {
class LoggerPeer;
}

namespace santa {

using GetExportConfigBlock = SNTExportConfiguration * (^)(void);

class Logger : public Timer<Logger> {
 public:
  enum class ExportLogType {
    kUnknown = 0,
    kUncompressedStream,
    kGzipStream,
    kZstdStream,
  };

  static std::unique_ptr<Logger> Create(
      std::shared_ptr<santa::EndpointSecurityAPI> esapi, SNTSyncdQueue *syncd_queue,
      GetExportConfigBlock getExportConfigBlock, TelemetryEvent telemetry_mask,
      SNTEventLogType log_type, SNTDecisionCache *decision_cache, NSString *event_log_path,
      NSString *spool_log_path, size_t spool_dir_size_threshold, size_t spool_file_size_threshold,
      uint64_t spool_flush_timeout_ms, uint32_t telemetry_export_seconds,
      uint32_t telemetry_export_timeout_seconds, uint32_t telemetry_export_batch_threshold_size_mb,
      uint32_t telemetry_export_max_files_per_batch);

  Logger(SNTSyncdQueue *syncd_queue, GetExportConfigBlock getExportConfigBlock,
         TelemetryEvent telemetry_mask, uint32_t telemetry_export_timeout_seconds,
         uint32_t telemetry_export_batch_threshold_size_mb,
         uint32_t telemetry_export_max_files_per_batch,
         std::shared_ptr<santa::Serializer> serializer, std::shared_ptr<santa::Writer> writer);

  virtual ~Logger() = default;

  Logger(Logger &&) = default;
  Logger &operator=(Logger &&rhs) = default;
  Logger(Logger &) = delete;
  Logger &operator=(Logger &rhs) = delete;

  virtual void Log(std::unique_ptr<santa::EnrichedMessage> msg);

  void LogAllowlist(const santa::Message &msg, const std::string_view hash);

  void LogBundleHashingEvents(NSArray<SNTStoredExecutionEvent *> *events);

  void LogDiskAppeared(NSDictionary *props);
  void LogDiskDisappeared(NSDictionary *props);

  virtual void LogFileAccess(const std::string &policy_version, const std::string &policy_name,
                             const santa::Message &msg,
                             const santa::EnrichedProcess &enriched_process,
                             const std::string &target, const es_file_t *event_target,
                             std::optional<santa::EnrichedFile> enriched_event_target,
                             FileAccessPolicyDecision decision);

  void Flush();

  void SetTelemetryMask(TelemetryEvent mask);

  inline bool ShouldLog(TelemetryEvent event) { return ((event & telemetry_mask_) == event); }

  void UpdateMachineIDLogging() const;

  bool OnTimer();

  /// Export existing telemetry files.
  void ExportTelemetry();

  void SetBatchThresholdSizeMB(uint32_t val);
  void SetMaxFilesPerBatch(uint32_t val);
  void SetTelmetryExportTimeoutSecs(uint32_t val);

  static ExportLogType GetLogType(NSFileHandle *handle, NSString *path);
  static std::pair<NSString *, NSString *> GetContentTypeAndExtension(ExportLogType log_type);

  friend class santa::LoggerPeer;

 private:
  class ExportTracker {
   public:
    static ExportTracker Create() {
      dispatch_queue_t q = dispatch_queue_create("com.northpolesec.santa.daemon.export_tracker",
                                                 DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
      return ExportTracker(q);
    }

    ExportTracker(dispatch_queue_t q) : q_(q) {}
    ExportTracker(ExportTracker &&) = default;
    ExportTracker &operator=(ExportTracker &&rhs) = default;
    ExportTracker(ExportTracker &) = default;
    ExportTracker &operator=(ExportTracker &rhs) = default;

    /// Track a new key. If the key isn't yet tracked, its value will be set
    /// to false. If the key is already tracked, its value will not be changed.
    void Track(std::string file_path) {
      dispatch_sync(q_, ^{
        file_state_.try_emplace(std::move(file_path), false);
      });
    }

    /// Mark the given key as completed. If the key doesn't previously exist,
    /// it will automatically start being tracked.
    void AckCompleted(std::string file_path) {
      dispatch_sync(q_, ^{
        file_state_.insert_or_assign(std::move(file_path), true);
      });
    }

    /// Empty the map and return the previous state
    absl::flat_hash_map<std::string, bool> Drain() {
      __block absl::flat_hash_map<std::string, bool> return_state;
      dispatch_sync(q_, ^{
        std::swap(return_state, file_state_);
      });
      return return_state;
    }

    friend class santa::LoggerPeer;

   private:
    absl::flat_hash_map<std::string, bool> file_state_;
    dispatch_queue_t q_;
  };

  void ExportTelemetrySerialized();

  SNTSyncdQueue *syncd_queue_;
  GetExportConfigBlock get_export_config_block_;
  TelemetryEvent telemetry_mask_;
  std::shared_ptr<santa::Serializer> serializer_;
  std::shared_ptr<santa::Writer> writer_;
  ExportTracker tracker_;
  std::unique_ptr<std::atomic_uint64_t> export_batch_threshold_size_bytes_;
  std::unique_ptr<std::atomic_uint32_t> export_max_files_per_batch_;
  std::unique_ptr<std::atomic_uint32_t> export_timeout_secs_;
  dispatch_queue_t export_queue_;
};

}  // namespace santa

#endif
