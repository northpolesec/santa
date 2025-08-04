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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLLOGBATCHWRITER_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLLOGBATCHWRITER_H

#include <string>
#include <vector>

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/binaryproto.pb.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/fsspool.h"
#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "google/protobuf/any.pb.h"

namespace fsspool {

// Provides FsSpool batching mechanism in the form of LogBatch proto messages.
//
// Example:
//   FsSpoolWriter fsspool_writer(...);
//   FsSpoolLogBatchWriter batch_writer(&fsspool_writer, 10);
//   ASSERT_OK(batch_writer.WriteMessage(vector_of_bytes);
//
// Automatic flush happens in the event of the object destruction.
//
// Flush() method is provided, so the users of this class can implement periodic
// flushes or due to some external indicator.
//
// The class is thread-safe.
class FsSpoolLogBatchWriter {
 public:
  FsSpoolLogBatchWriter(
      std::function<absl::Status(std::string)> flush_callback);
  ~FsSpoolLogBatchWriter();

  // Wraps given bytes in an Any proto message and writes them to the FsSpool.
  // The write is cached until flushed.
  absl::Status WriteMessage(std::vector<uint8_t> bytes);

  // Flush internal FsSpoolLogBatchWriter cache to disk. Calling this method is
  // not necessary as the cache is flushed after max_batch_size limit is reached
  // or when the objects is destroyed.
  absl::Status Flush();

  std::string TypeURL() const { return type_url_; }

 private:
  absl::Mutex writer_mutex_ ABSL_ACQUIRED_AFTER(cache_mutex_);
  std::function<absl::Status(std::string)> flush_callback_
      ABSL_GUARDED_BY(writer_mutex_);
  std::string type_url_;
  absl::Mutex cache_mutex_;
  santa::fsspool::binaryproto::LogBatch cache_ ABSL_GUARDED_BY(cache_mutex_);

  absl::Status FlushNoLock() ABSL_EXCLUSIVE_LOCKS_REQUIRED(cache_mutex_);
};

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_FSSPOOLLOGBATCHWRITER_H
