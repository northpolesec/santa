/// Copyright 2022 Google LLC
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_SPOOL_H

#import <Foundation/Foundation.h>
#include <dispatch/dispatch.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#import "Source/common/SNTLogging.h"
#include "Source/common/santa_proto_include_wrapper.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/Writer.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"

// Forward declarations
namespace santa {
class SpoolPeer;
}

namespace santa {

template <::fsspool::BatcherInterface T>
class Spool : public Writer, public std::enable_shared_from_this<Spool<T>> {
 public:
  // Factory
  static std::shared_ptr<Spool<T>> Create(std::string_view base_dir, size_t max_spool_disk_size,
                                          size_t max_spool_batch_size, uint64_t flush_timeout_ms) {
    dispatch_queue_t q = dispatch_queue_create("com.northpolesec.santa.daemon.file_base_q",
                                               DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
    dispatch_source_t timer_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, q);
    dispatch_source_set_timer(timer_source, dispatch_time(DISPATCH_TIME_NOW, 0),
                              NSEC_PER_MSEC * flush_timeout_ms, 0);

    auto spool_writer = std::make_shared<Spool<T>>(q, timer_source, base_dir, max_spool_disk_size,
                                                   max_spool_batch_size);

    spool_writer->BeginFlushTask();

    return spool_writer;
  }

  Spool(dispatch_queue_t q, dispatch_source_t timer_source, std::string_view base_dir,
        size_t max_spool_disk_size, size_t max_spool_file_size,
        void (^write_complete_f)(void) = nullptr, void (^flush_task_complete_f)(void) = nullptr)
      : q_(q),
        timer_source_(timer_source),
        spool_reader_(absl::string_view(base_dir.data(), base_dir.length())),
        spool_writer_(absl::string_view(base_dir.data(), base_dir.length()), max_spool_disk_size),
        spool_file_size_threshold_(max_spool_file_size),
        spool_file_size_threshold_leniency_(spool_file_size_threshold_ *
                                            spool_file_size_threshold_leniency_factor_),
        write_complete_f_(write_complete_f),
        flush_task_complete_f_(flush_task_complete_f) {}

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

  void Write(std::vector<uint8_t> &&bytes) override {
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
      for (const auto &file_exported : files_exported) {
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
  friend class santa::SpoolPeer;

 private:
  bool FlushSerialized() {
    if (spool_writer_.Flush().ok()) {
      accumulated_bytes_ = 0;
      return true;
    } else {
      return false;
    }
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

  size_t accumulated_bytes_ = 0;
};

}  // namespace santa

#endif
