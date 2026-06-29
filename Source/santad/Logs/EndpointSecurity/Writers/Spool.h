/// Copyright 2022 Google LLC
/// Copyright 2025 North Pole Security, Inc.
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

#ifndef SANTA_SANTAD_LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H
#define SANTA_SANTAD_LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTMetricSet.h"
#include "Source/common/ScopedFile.h"
#include "Source/common/santa.pb.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"

// Forward declarations
namespace santa {
template <typename T>
class SpoolPeer;
}

namespace santa {

template <::fsspool::BatcherInterface T>
class Spool : public Writer, public std::enable_shared_from_this<Spool<T>> {
 public:
  // Factory
  static std::shared_ptr<Spool<T>> Create(
      T batcher, std::string_view base_dir, size_t max_spool_disk_size, size_t max_spool_batch_size,
      uint64_t flush_timeout_ms,
      void (^file_closed_f)(std::string, std::shared_ptr<santa::ScopedFile>) = nullptr) {
    dispatch_queue_t q = dispatch_queue_create("com.northpolesec.santa.daemon.file_base_q",
                                               DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                              NSEC_PER_MSEC * flush_timeout_ms, 0);

    // Records how many spool files are erased when the spool exceeds its size limit.
    SNTMetricCounter* eviction_counter = [[SNTMetricSet sharedInstance]
        counterWithName:@"/santa/spool/eviction_count"
             fieldNames:@[]
               helpText:@"Number of spool files erased to stay under the spool size limit"];
    std::function<void(size_t)> eviction_callback = [eviction_counter](size_t erased) {
      [eviction_counter incrementBy:static_cast<long long>(erased) forFieldValues:@[]];
    };

    // Reports the current on-disk size of the spool directory, sampled at metric export time.
    SNTMetricInt64Gauge* size_gauge = [[SNTMetricSet sharedInstance]
        int64GaugeWithName:@"/santa/spool/size_bytes"
                fieldNames:@[]
                  helpText:@"Current on-disk size of the telemetry spool directory in bytes"];
    std::string spool_dir =
        ::fsspool::SpoolNewDirectory(absl::string_view(base_dir.data(), base_dir.length()));
    [[SNTMetricSet sharedInstance] registerCallback:^{
      auto size = ::fsspool::EstimateDirSize(spool_dir);
      [size_gauge set:(size.ok() ? static_cast<long long>(*size) : 0) forFieldValues:@[]];
    }];

    auto spool_writer = std::make_shared<Spool<T>>(
        q, timer_source, std::move(batcher), base_dir, max_spool_disk_size, max_spool_batch_size,
        nullptr, nullptr, file_closed_f, std::move(eviction_callback));

    spool_writer->BeginFlushTask();

    return spool_writer;
  }

  Spool(dispatch_queue_t q, dispatch_source_t timer_source, T batcher, std::string_view base_dir,
        size_t max_spool_disk_size, size_t max_spool_file_size,
        void (^write_complete_f)(void) = nullptr, void (^flush_task_complete_f)(void) = nullptr,
        void (^file_closed_f)(std::string, std::shared_ptr<santa::ScopedFile>) = nullptr,
        std::function<void(size_t)> eviction_callback = nullptr)
      : q_(q),
        timer_source_(timer_source),
        spool_reader_(absl::string_view(base_dir.data(), base_dir.length())),
        spool_writer_(std::move(batcher), absl::string_view(base_dir.data(), base_dir.length()),
                      max_spool_disk_size, std::move(eviction_callback)),
        spool_file_size_threshold_(max_spool_file_size),
        spool_file_size_threshold_leniency_(spool_file_size_threshold_ *
                                            spool_file_size_threshold_leniency_factor_),
        write_complete_f_(write_complete_f),
        flush_task_complete_f_(flush_task_complete_f),
        file_closed_f_(file_closed_f) {}

  ~Spool() {
    // Note: `log_batch_writer_` is automatically flushed when destroyed
    if (!flush_task_started_) {
      // The timer_source_ must be resumed to ensure it has a proper retain count before being
      // destroyed. Additionally, it should first be cancelled to ensure the timer isn't ever fired
      // (see man page for `dispatch_source_cancel(3)`).
      dispatch_source_cancel(timer_source_);
      dispatch_resume(timer_source_);
    }
  }

  void Write(std::vector<uint8_t>&& bytes) override {
    auto shared_this = this->shared_from_this();

    // Workaround to move `bytes` into the block without a copy
    __block std::vector<uint8_t> temp_bytes = std::move(bytes);

    dispatch_async(q_, ^{
      std::vector<uint8_t> moved_bytes = std::move(temp_bytes);

      if (shared_this->accumulated_bytes_ >= shared_this->spool_file_size_threshold_) {
        shared_this->FlushSerialized();
      }

      // Only write the new message if we have room left.
      // This will account for Flush failing above.
      // Use the more lenient threshold here in case the Flush failures are transitory.
      if (shared_this->accumulated_bytes_ < shared_this->spool_file_size_threshold_leniency_) {
        size_t bytes_written = moved_bytes.size();
        auto status = shared_this->spool_writer_.Write(std::move(moved_bytes));
        if (!status.ok()) {
          if (absl::IsDataLoss(status)) {
            // Nop for now. We haven't historically logged on drops as that would
            // spam the console when the spool is filled and that isn't very useful.
            // There will be periodic messages that the spool is full.
          } else {
            LOGE(@"Failed to log event: %s", status.ToString().c_str());
          }
        } else {
          shared_this->accumulated_bytes_ += bytes_written;
        }
      }

      if (shared_this->write_complete_f_) {
        shared_this->write_complete_f_();
      }
    });
  }

  void Flush() override {
    dispatch_sync(q_, ^{
      FlushSerialized();
    });
  }

  std::optional<absl::flat_hash_set<std::string>> GetFilesToExport(size_t max_count) override {
    __block absl::StatusOr<absl::flat_hash_set<std::string>> paths;
    dispatch_sync(q_, ^{
      paths = spool_reader_.BatchMessagePaths(max_count);
    });

    return paths.ok() ? std::make_optional(std::move(*paths)) : std::nullopt;
  }

  std::optional<std::string> NextFileToExport() override {
    std::optional<absl::flat_hash_set<std::string>> paths = GetFilesToExport(1);
    if (paths.has_value() && paths->size() == 1) {
      return *paths->begin();
    } else {
      return std::nullopt;
    }
  }

  void FilesExported(absl::flat_hash_map<std::string, bool> files_exported) override {
    dispatch_async(q_, ^{
      for (const auto& file_exported : files_exported) {
        if (!spool_reader_.AckMessage(file_exported.first, file_exported.second).ok()) {
          LOGW(@"Unable to delete exported file.");
        }
      }
    });
  }

  void BeginFlushTask() {
    if (flush_task_started_) {
      return;
    }

    std::weak_ptr<Spool> weak_writer = this->weak_from_this();
    dispatch_source_set_event_handler(timer_source_, ^{
      std::shared_ptr<Spool> shared_writer = weak_writer.lock();
      if (!shared_writer) {
        return;
      }

      if (!shared_writer->FlushSerialized()) {
        LOGE(@"Spool writer: periodic flush failed.");
      }

      if (shared_writer->flush_task_complete_f_) {
        shared_writer->flush_task_complete_f_();
      }
    });

    dispatch_resume(timer_source_);
    flush_task_started_ = true;
  }

  // Peer class for testing
  friend class santa::SpoolPeer<T>;

 private:
  bool FlushSerialized() {
    absl::StatusOr<std::optional<std::string>> result = spool_writer_.Flush();
    if (!result.ok()) {
      return false;
    }
    accumulated_bytes_ = 0;
    // A spool file was just closed (renamed into the spool dir). Hand its path and a read-only fd
    // off to the file-closed callback. The callback MUST be cheap (it runs on this serial queue
    // `q_`) — it should dispatch any real work elsewhere.
    //
    // Acquiring the fd here on `q_` is ordered before any export selection or deletion of this
    // file (BatchMessagePaths and the AckMessage/remove both run on `q_`), so the open always
    // succeeds. The open fd then keeps the inode's data alive for the asynchronous signal scan
    // even after the telemetry exporter unlinks the path — so scan and export need no coordination.
    if (file_closed_f_ && result->has_value()) {
      const std::string& closed_path = result->value();
      std::shared_ptr<santa::ScopedFile> scoped_file;
      int fd = open(closed_path.c_str(), O_RDONLY);
      if (fd >= 0) {
        scoped_file = std::make_shared<santa::ScopedFile>(fd);
      } else {
        LOGW(@"Spool: failed to open closed file for signal scan: %s (errno %d)",
             closed_path.c_str(), errno);
      }
      file_closed_f_(closed_path, std::move(scoped_file));
    }
    return true;
  }

  dispatch_queue_t q_ = NULL;
  dispatch_source_t timer_source_ = NULL;
  ::fsspool::FsSpoolReader spool_reader_;
  ::fsspool::FsSpoolWriter<T> spool_writer_;
  const size_t spool_file_size_threshold_;
  // Make a "leniency factor" of 20%. This will be used to allow some more
  // records to accumulate in the event flushing fails for some reason.
  const double spool_file_size_threshold_leniency_factor_ = 1.2;
  const size_t spool_file_size_threshold_leniency_;
  bool flush_task_started_ = false;
  void (^write_complete_f_)(void);
  void (^flush_task_complete_f_)(void);
  void (^file_closed_f_)(std::string, std::shared_ptr<santa::ScopedFile>);

  size_t accumulated_bytes_ = 0;
};

}  // namespace santa

#endif  // SANTA_SANTAD_LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H
