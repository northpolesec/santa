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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_STREAMBATCHER_H_
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_STREAMBATCHER_H_

#include <vector>

#include "src/common/SNTXxhash.h"
#include "src/common/Unit.h"
#include "src/santad/logs/endpoint_security/writers/fsspool/ZstdOutputStream.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/gzip_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"

namespace fsspool {

static constexpr uint32_t kStreamBatcherMagic = 0x21544E53;

template <typename T>
class StreamBatcher {
 public:
  template <typename F>
  StreamBatcher(F &&factory) : factory_(std::forward<F>(factory)) {}

  inline bool ShouldInitializeBeforeWrite() { return true; }

  absl::Status InitializeBatch(int fd) {
    raw_output_ = std::make_shared<google::protobuf::io::FileOutputStream>(fd);
    compressed_output_ = factory_(raw_output_.get());
    if (!compressed_output_) {
      return absl::InternalError("Creating compressed stream batcher failed");
    }
    coded_output_ = std::make_shared<google::protobuf::io::CodedOutputStream>(
        compressed_output_.get());
    return absl::OkStatus();
  }

  inline bool NeedToOpenFile() { return true; }

  absl::Status Write(std::vector<uint8_t> bytes) {
    if (bytes.size() > INT_MAX) {
      return absl::InternalError("Telemetry event size too large");
    }

    coded_output_->WriteLittleEndian32(kStreamBatcherMagic);

    santa::Xxhash64 hash;
    hash.Update(bytes.data(), bytes.size());
    hash.Digest([&](const uint8_t *buf, size_t length) {
      assert(length == sizeof(uint64_t));
      coded_output_->WriteRaw(buf, (int)length);
    });

    // Note: Protobuf library is inconsistent on size parameters. Casts are
    // intentionally for different types.
    coded_output_->WriteVarint32(static_cast<uint32_t>(bytes.size()));
    coded_output_->WriteRaw(bytes.data(), static_cast<int>(bytes.size()));
    return absl::OkStatus();
  }

  absl::StatusOr<size_t> CompleteBatch(int fd) {
    int bytes_written = coded_output_->ByteCount();
    coded_output_.reset();
    compressed_output_.reset();
    raw_output_.reset();
    return bytes_written;
  }

 private:
  std::function<std::shared_ptr<T>(
      google::protobuf::io::ZeroCopyOutputStream *)>
      factory_;
  std::shared_ptr<google::protobuf::io::ZeroCopyOutputStream> raw_output_;
  std::shared_ptr<T> compressed_output_;
  std::shared_ptr<google::protobuf::io::CodedOutputStream> coded_output_;
};

// Note: This is a specialization of the StreamBatcher class template when no
// compression is desired. Its implementation is near-identical to the generic
// template, aside from InitializeBatch and CompleteBatch. This could have been
// written instead with a generic base class to dedupe the logic in the `Write`
// method, but would come at a cost of a vtable lookup at runtime within this
// hot path.
template <>
class StreamBatcher<::santa::Unit> {
 public:
  StreamBatcher() = default;

  inline bool ShouldInitializeBeforeWrite() { return true; }

  absl::Status InitializeBatch(int fd) {
    raw_output_ = std::make_shared<google::protobuf::io::FileOutputStream>(fd);
    coded_output_ = std::make_shared<google::protobuf::io::CodedOutputStream>(
        raw_output_.get());
    return absl::OkStatus();
  }

  inline bool NeedToOpenFile() { return true; }

  absl::Status Write(std::vector<uint8_t> bytes) {
    if (bytes.size() > INT_MAX) {
      return absl::InternalError("Telemetry event size too large");
    }

    coded_output_->WriteLittleEndian32(kStreamBatcherMagic);

    santa::Xxhash64 hash;
    hash.Update(bytes.data(), bytes.size());
    hash.Digest([&](const uint8_t *buf, size_t length) {
      assert(length == sizeof(uint64_t));
      coded_output_->WriteRaw(buf, (int)length);
    });

    coded_output_->WriteVarint32(static_cast<uint32_t>(bytes.size()));
    coded_output_->WriteRaw(bytes.data(), static_cast<int>(bytes.size()));
    return absl::OkStatus();
  }

  absl::StatusOr<size_t> CompleteBatch(int fd) {
    int bytes_written = coded_output_->ByteCount();
    coded_output_.reset();
    raw_output_.reset();
    return bytes_written;
  }

 private:
  std::shared_ptr<google::protobuf::io::ZeroCopyOutputStream> raw_output_;
  std::shared_ptr<google::protobuf::io::CodedOutputStream> coded_output_;
};

// Convenience type aliases
using GzipStreamBatcher = StreamBatcher<google::protobuf::io::GzipOutputStream>;
using ZstdStreamBatcher = StreamBatcher<fsspool::ZstdOutputStream>;
using UncompressedStreamBatcher = StreamBatcher<::santa::Unit>;

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_STREAMBATCHER_H_
