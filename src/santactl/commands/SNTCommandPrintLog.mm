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

#import <Foundation/Foundation.h>
#include <google/protobuf/json/json.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#import "src/common/NSData+Zlib.h"
#include "src/common/SNTLogging.h"
#import "src/common/SNTXxhash.h"
#include "src/common/ScopedFile.h"
#include "src/common/santa_proto_include_wrapper.h"
#import "src/santactl/SNTCommand.h"
#import "src/santactl/SNTCommandController.h"
#include "src/santad/logs/endpoint_security/writers/fsspool/AnyBatcher.h"
#include "src/santad/logs/endpoint_security/writers/fsspool/StreamBatcher.h"
#include "src/santad/logs/endpoint_security/writers/fsspool/binaryproto_proto_include_wrapper.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "google/protobuf/any.pb.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"

#define ZSTD_STATIC_LINKING_ONLY
#include "zstd.h"

using JsonPrintOptions = google::protobuf::json::PrintOptions;
using google::protobuf::json::MessageToJsonString;
using santa::ScopedFile;
using santa::fsspool::binaryproto::LogBatch;
namespace pbv1 = ::santa::pb::v1;

// Semi-arbitrary max compressed file size that will be operated upon.
// The current implementation decompresses in memory. This variable
// is used to keep memory requirements semi-reasonable.
static constexpr size_t kMaxCompressedSize = 1024 * 1024 * 250;

class MessageSource {
 public:
  // Factory method to return either a AnyMessageSource or StreamMessageSource based
  // on the type of the log file being parsed.
  static absl::StatusOr<std::unique_ptr<MessageSource>> Create(NSString *path);

  virtual ~MessageSource() = default;

  // Not copyable
  MessageSource(const MessageSource &) = delete;
  MessageSource &operator=(const MessageSource &) = delete;

  virtual absl::StatusOr<::pbv1::SantaMessage> Next() = 0;

 protected:
  MessageSource(ScopedFile scoped_file) : scoped_file_(std::move(scoped_file)) {}

 private:
  ScopedFile scoped_file_;
};

class AnyMessageSource : public MessageSource {
 public:
  static std::unique_ptr<AnyMessageSource> Create(ScopedFile scoped_file) {
    LogBatch batch;
    if (!batch.ParseFromFileDescriptor(scoped_file.UnsafeFD())) {
      return nullptr;
    }

    return std::make_unique<AnyMessageSource>(std::move(scoped_file), std::move(batch));
  }

  AnyMessageSource(ScopedFile scoped_file, LogBatch batch)
      : MessageSource(std::move(scoped_file)), batch_(std::move(batch)), current_index_(0) {}

  absl::StatusOr<::pbv1::SantaMessage> Next() override {
    // Check if we've reached the end of the batch
    if (current_index_ >= static_cast<size_t>(batch_.records_size())) {
      return absl::OutOfRangeError("No more data");
    }

    ::pbv1::SantaMessage santa_msg;
    if (!santa_msg.ParseFromString(batch_.records(current_index_++).value())) {
      return absl::InternalError("Failed to parse Any proto");
    }

    return santa_msg;
  }

 private:
  LogBatch batch_;
  int current_index_;
};

class StreamMessageSource : public MessageSource {
 public:
  static std::unique_ptr<StreamMessageSource> Create(ScopedFile scoped_file) {
    auto file_input =
        std::make_unique<google::protobuf::io::FileInputStream>(scoped_file.UnsafeFD());
    auto coded_input = std::make_unique<google::protobuf::io::CodedInputStream>(file_input.get());

    return std::unique_ptr<StreamMessageSource>(new StreamMessageSource(
        std::move(scoped_file), std::move(file_input), std::move(coded_input)));
  }

  StreamMessageSource(ScopedFile scoped_file,
                      std::unique_ptr<google::protobuf::io::FileInputStream> file_input,
                      std::unique_ptr<google::protobuf::io::CodedInputStream> coded_input)
      : MessageSource(std::move(scoped_file)),
        file_input_(std::move(file_input)),
        coded_input_(std::move(coded_input)) {}

  absl::StatusOr<::pbv1::SantaMessage> Next() override {
    // Check the magic value
    // Failing to read the first value indicates we're at the end of a file.
    uint32_t magic;
    if (!coded_input_->ReadLittleEndian32(&magic)) {
      return absl::OutOfRangeError("No more data");
    }
    if (magic != ::fsspool::kStreamBatcherMagic) {
      return absl::InternalError("Invalid magic value");
    }

    // Check the hash
    uint64_t expected_hash;
    if (!coded_input_->ReadRaw(&expected_hash, sizeof(expected_hash))) {
      return absl::InternalError("Failed to parse hash data");
    }

    // Read the length
    uint32_t message_length;
    if (!coded_input_->ReadVarint32(&message_length)) {
      return absl::InternalError("Failed to parse message length");
    }

    // Read the raw message data
    std::vector<uint8_t> msg_buf(message_length);
    if (!coded_input_->ReadRaw(msg_buf.data(), message_length)) {
      return absl::InternalError("Failed to read message into buffer");
    }

    if (expected_hash != 0) {
      santa::Xxhash64 xxhash;
      xxhash.Update(msg_buf.data(), msg_buf.size());
      __block uint64_t got_hash;
      xxhash.Digest(^(const uint8_t *buf, size_t size) {
        got_hash = *(uint64_t *)buf;
      });

      if (got_hash != expected_hash) {
        return absl::InternalError("Message corruption detected");
      }
    }

    ::pbv1::SantaMessage santa_msg;
    if (!santa_msg.ParseFromArray(msg_buf.data(), (int)msg_buf.size())) {
      return absl::InternalError("Failed to parse message data");
    }

    return santa_msg;
  }

 private:
  std::unique_ptr<google::protobuf::io::FileInputStream> file_input_;
  std::unique_ptr<google::protobuf::io::CodedInputStream> coded_input_;
};

absl::Status CanProcessFile(const ScopedFile &scoped_file) {
  struct stat sb;
  if (fstat(scoped_file.UnsafeFD(), &sb) != 0) {
    return absl::ErrnoToStatus(errno, "Unable to stat file");
  }

  if (sb.st_size > kMaxCompressedSize) {
    return absl::OutOfRangeError(absl::StrFormat(
        "Compressed file too large. Please decompress first. (Max allowed compressed size: %zu",
        kMaxCompressedSize));
  }

  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<MessageSource>> CreateStreamSource(NSData *buffer) {
  auto temp_file = santa::ScopedFile::CreateTemporary();
  if (!temp_file.ok()) {
    return temp_file.status();
  }

  NSFileHandle *temp_handle = temp_file->Writer();
  NSError *err;
  if (![temp_handle writeData:buffer error:&err]) {
    return absl::InternalError(absl::StrFormat("Failed to write decompressed data to temp file: %s",
                                               err.localizedDescription.UTF8String));
  }

  // Reset back to the beginning for reading
  [temp_handle seekToFileOffset:0];

  return StreamMessageSource::Create(std::move(*temp_file));
}

absl::StatusOr<std::unique_ptr<MessageSource>> HandleGzipFileSource(ScopedFile scoped_file) {
  if (absl::Status status = CanProcessFile(scoped_file); !status.ok()) {
    return status;
  }

  NSFileHandle *handle = scoped_file.Reader();
  NSError *err;
  NSData *compressed = [handle readDataToEndOfFileAndReturnError:&err];
  if (err) {
    return absl::InternalError(
        absl::StrFormat("Failed to read compressed file: %s", err.localizedDescription.UTF8String));
  }

  NSData *decompressed = [compressed gzipDecompressed];
  if (!decompressed) {
    return absl::InternalError("Failed to decompress file");
  }

  return CreateStreamSource(decompressed);
}

absl::StatusOr<std::unique_ptr<MessageSource>> HandleZstdFileSource(ScopedFile scoped_file) {
  if (absl::Status status = CanProcessFile(scoped_file); !status.ok()) {
    return status;
  }

  NSFileHandle *handle = scoped_file.Reader();
  NSError *err;
  NSData *compressed = [handle readDataToEndOfFileAndReturnError:&err];
  if (err) {
    return absl::InternalError(
        absl::StrFormat("Failed to read compressed file: %s", err.localizedDescription.UTF8String));
  }

  uint64_t max_size = ZSTD_decompressBound(compressed.bytes, compressed.length);
  if (max_size == ZSTD_CONTENTSIZE_ERROR) {
    return absl::OutOfRangeError("Failed to calculate decompressed size");
  }

  NSMutableData *decompressed = [[NSMutableData alloc] initWithCapacity:max_size];
  decompressed.length = max_size;

  size_t bytes_decompressed =
      ZSTD_decompress(decompressed.mutableBytes, max_size, compressed.bytes, compressed.length);
  if (ZSTD_isError(bytes_decompressed)) {
    return absl::InternalError(absl::StrFormat("Failed to decompress zstd file: %d: %s",
                                               ZSTD_getErrorCode(bytes_decompressed),
                                               ZSTD_getErrorName(bytes_decompressed)));
  }

  // Clamp the length now that we know the true size
  decompressed.length = bytes_decompressed;

  return CreateStreamSource(decompressed);
}

absl::StatusOr<std::unique_ptr<MessageSource>> MessageSource::Create(NSString *path) {
  // Open the file
  int fd = open(path.UTF8String, O_RDONLY);
  if (fd < 0) {
    return absl::InvalidArgumentError("Failed to open file");
  }

  // Ensure the file gets closed appropriately
  ScopedFile scoped_file(fd);

  // Read the first 4 bytes to check for the stream protobuf magic number
  uint32_t magic_number = 0;
  errno = 0;
  ssize_t bytes_read = read(fd, &magic_number, sizeof(magic_number));

  // Note: Allow "parsing" of empty files so it isn't treated as an error
  if (bytes_read != 0 && bytes_read != sizeof(magic_number)) {
    return absl::InvalidArgumentError("Failed to determine file type");
  }

  // Reset file position back to the beginning
  if (lseek(fd, 0, SEEK_SET) != 0) {
    return absl::InternalError("Failed to reset file position for reading");
  }

  // Determine which derived class to instantiate based on magic number
  if (magic_number == ::fsspool::kStreamBatcherMagic) {
    return StreamMessageSource::Create(std::move(scoped_file));
  } else if (magic_number == 0xfd2fb528) {
    return HandleZstdFileSource(std::move(scoped_file));
  } else if ((magic_number & 0xffff) == 0x8b1f) {
    return HandleGzipFileSource(std::move(scoped_file));
  } else if ((magic_number & 0xff) == 0x0a) {
    return AnyMessageSource::Create(std::move(scoped_file));
  } else {
    return absl::InvalidArgumentError("Unsupported file type");
  }
}

@interface SNTCommandPrintLog : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandPrintLog

REGISTER_COMMAND_NAME(@"printlog")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Prints the contents of Santa protobuf log files as JSON.";
}

+ (NSString *)longHelpText {
  return @"Prints the contents of serialized Santa protobuf logs as JSON.\n"
         @"Multiple paths can be provided. The output is a list of all the \n"
         @"SantaMessage entries per-file. E.g.: \n"
         @"  [\n"
         @"    [\n"
         @"      ... file 1 contents ...\n"
         @"    ],\n"
         @"    [\n"
         @"      ... file N contents ...\n"
         @"    ]\n"
         @"  ]";
}

- (void)runWithArguments:(NSArray *)arguments {
  JsonPrintOptions options;
  options.always_print_enums_as_ints = false;
  options.always_print_fields_with_no_presence = true;
  options.preserve_proto_field_names = true;
  options.add_whitespace = true;

  bool printed_opening_brace = false;

  for (NSString *path in arguments) {
    auto source = MessageSource::Create(path);
    if (!source.ok()) {
      TEE_LOGE(@"%@: %s", path, source.status().ToString().c_str());
      continue;
    }

    if (printed_opening_brace) {
      std::cout << ",";
    } else {
      // Print the opening outer JSON array
      std::cout << "[";
      printed_opening_brace = true;
    }

    // Print the opening inner JSON array
    std::cout << "\n[\n";

    bool first_message = true;
    while (true) {
      auto message = (*source)->Next();
      if (!message.ok()) {
        // Check if we've reached the end of the source, or some other error
        if (!absl::IsOutOfRange(message.status())) {
          TEE_LOGE(@"%@: Error reading message: %s", path, message.status().ToString().c_str());
        }
        break;
      }

      // Print the comma between records
      if (first_message) {
        first_message = false;
      } else {
        std::cout << ",\n";
      }

      std::string json;
      if (!MessageToJsonString(*message, &json, options).ok()) {
        TEE_LOGE(@"Unable to convert message to JSON in file: '%@'\n", path);
      }
      std::cout << json;
    }

    std::cout << "]" << std::flush;
  }

  if (printed_opening_brace) {
    // Print the closing outer JSON array
    std::cout << "\n]\n";
  }

  exit(EXIT_SUCCESS);
}

@end
