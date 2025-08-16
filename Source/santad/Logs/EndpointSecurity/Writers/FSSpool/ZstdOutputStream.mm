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

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/ZstdOutputStream.h"

#include <climits>
#include <cstdint>
#include <iostream>

namespace fsspool {

std::unique_ptr<ZstdOutputStream> ZstdOutputStream::Create(
    google::protobuf::io::ZeroCopyOutputStream *output, int compression_level, size_t buffer_size) {
  ZSTD_CStream *cstream = ZSTD_createCStream();
  if (!cstream) {
    return nullptr;
  }

  size_t result = ZSTD_initCStream(cstream, compression_level);
  if (ZSTD_isError(result)) {
    ZSTD_freeCStream(cstream);
    return nullptr;
  }

  return std::make_unique<ZstdOutputStream>(output, cstream, buffer_size);
}

ZstdOutputStream::ZstdOutputStream(google::protobuf::io::ZeroCopyOutputStream *output,
                                   ZSTD_CStream *cstream, size_t buffer_size)
    : output_(output),
      cstream_(cstream),
      input_buffer_(buffer_size),
      input_position_(0),
      input_available_(0),
      output_buffer_(buffer_size),
      byte_count_(0),
      closed_(false) {}

ZstdOutputStream::~ZstdOutputStream() {
  if (!closed_) {
    Flush();
  }
  if (cstream_) {
    ZSTD_freeCStream(cstream_);
  }
}

bool ZstdOutputStream::Next(void **data, int *size) {
  if (closed_) {
    return false;
  }

  // If we have pending compressed data, flush it first
  if (input_available_ > 0) {
    if (!CompressAndFlush(ZSTD_e_continue)) {
      return false;
    }
  }

  // Provide the entire input buffer to the caller
  *data = input_buffer_.data();
  *size = static_cast<int>(input_buffer_.size());

  input_position_ = 0;
  input_available_ = input_buffer_.size();
  byte_count_ += input_buffer_.size();

  return true;
}

void ZstdOutputStream::BackUp(int count) {
  if (closed_ || count < 0 || static_cast<size_t>(count) > input_available_) {
    return;
  }

  input_available_ -= count;
  byte_count_ -= count;
}

int64_t ZstdOutputStream::ByteCount() const {
  return byte_count_;
}

bool ZstdOutputStream::Flush() {
  if (closed_) {
    return false;
  }

  // Compress any remaining data and end the stream
  bool success = CompressAndFlush(ZSTD_e_end);
  closed_ = true;
  return success;
}

bool ZstdOutputStream::CompressAndFlush(ZSTD_EndDirective end_directive) {
  ZSTD_inBuffer input = {
      .src = input_buffer_.data(),
      .size = input_available_,
      .pos = 0,
  };

  size_t remaining;
  do {
    ZSTD_outBuffer output = {
        .dst = output_buffer_.data(),
        .size = output_buffer_.size(),
        .pos = 0,
    };

    remaining = ZSTD_compressStream2(cstream_, &output, &input, end_directive);
    if (ZSTD_isError(remaining)) {
      return false;
    }

    // Write compressed data to underlying stream if any was produced
    if (output.pos > 0) {
      if (!FlushOutput(output.pos)) {
        return false;
      }
    }
  } while ((end_directive == ZSTD_e_end) ? (remaining != 0) : (input.pos < input.size));

  // Reset input buffer
  input_available_ = 0;
  input_position_ = 0;

  return true;
}

bool ZstdOutputStream::FlushOutput(size_t bytes_to_write) {
  if (bytes_to_write == 0) {
    bytes_to_write = output_buffer_.size();
  }

  size_t remaining = bytes_to_write;
  const uint8_t *data = output_buffer_.data();

  while (remaining > 0) {
    void *buffer;
    int size;

    if (!output_->Next(&buffer, &size)) {
      return false;
    }

    size_t to_write = std::min(remaining, static_cast<size_t>(size));
    std::memcpy(buffer, data, to_write);

    if (to_write < static_cast<size_t>(size)) {
      output_->BackUp(static_cast<int>(size - to_write));
    }

    data += to_write;
    remaining -= to_write;
  }

  return true;
}

}  // namespace fsspool
