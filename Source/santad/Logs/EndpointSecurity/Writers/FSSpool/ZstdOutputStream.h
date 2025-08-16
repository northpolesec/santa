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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_ZSTDOUTPUTSTREAM_H
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_ZSTDOUTPUTSTREAM_H

#include "google/protobuf/io/zero_copy_stream.h"
#include "google/protobuf/stubs/common.h"
#include "zstd.h"

namespace fsspool {

class ZstdOutputStream : public google::protobuf::io::ZeroCopyOutputStream {
 public:
  // Matches the Gzip default buffer size
  static constexpr size_t kDefaultBufferSize = 64 * 1024;

  static std::unique_ptr<ZstdOutputStream> Create(
      google::protobuf::io::ZeroCopyOutputStream* output,
      int compression_level = ZSTD_CLEVEL_DEFAULT,
      size_t buffer_size = kDefaultBufferSize);

  ZstdOutputStream(google::protobuf::io::ZeroCopyOutputStream* output,
                   ZSTD_CStream* cstream,
                   size_t buffer_size = kDefaultBufferSize);

  ~ZstdOutputStream();

  // ZeroCopyOutputStream interface
  bool Next(void** data, int* size) override;
  void BackUp(int count) override;
  int64_t ByteCount() const override;

  // Flush any remaining compressed data to the underlying stream
  // Must be called before destroying the stream or the data may be incomplete
  bool Flush();

 private:
  bool CompressAndFlush(ZSTD_EndDirective end_directive);
  bool FlushOutput(size_t bytes_to_write);

  google::protobuf::io::ZeroCopyOutputStream* output_;
  ZSTD_CStream* cstream_;

  // Input buffer for uncompressed data
  std::vector<uint8_t> input_buffer_;
  size_t input_position_;
  size_t input_available_;

  // Output buffer for compressed data
  std::vector<uint8_t> output_buffer_;

  int64_t byte_count_;
  bool closed_;
};

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_ZSTDOUTPUTSTREAM_H
