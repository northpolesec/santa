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
#include <cstring>

#include <iostream>
#include <memory>
#include <string>

#include "Source/common/SNTLogging.h"
#include "Source/common/santa_proto_include_wrapper.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/AnyBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h"
#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/binaryproto_proto_include_wrapper.h"
#include "absl/status/statusor.h"
#include "google/protobuf/any.pb.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"

using JsonPrintOptions = google::protobuf::json::PrintOptions;
using google::protobuf::json::MessageToJsonString;
using santa::fsspool::binaryproto::LogBatch;
namespace pbv1 = ::santa::pb::v1;

class MessageSource {
 public:
  // Factory method to return either a AnyMessageSource or StreamMessageSource based
  // on the type of the log file being parsed.
  static absl::StatusOr<std::unique_ptr<MessageSource>> Create(NSString *path);

  virtual ~MessageSource() { close(fd_); };

  // Not copyable
  MessageSource(const MessageSource &) = delete;
  MessageSource &operator=(const MessageSource &) = delete;

  virtual absl::StatusOr<::pbv1::SantaMessage> Next() = 0;

 protected:
  MessageSource(int fd) : fd_(fd) {}

 private:
  int fd_;
};

class AnyMessageSource : public MessageSource {
 public:
  static std::unique_ptr<AnyMessageSource> Create(int fd) {
    LogBatch batch;
    if (!batch.ParseFromFileDescriptor(fd)) {
      return nullptr;
    }

    return std::make_unique<AnyMessageSource>(fd, std::move(batch));
  }

  AnyMessageSource(int fd, LogBatch batch)
      : MessageSource(fd), batch_(std::move(batch)), current_index_(0) {}

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
  static std::unique_ptr<StreamMessageSource> Create(int fd) {
    auto file_input = std::make_unique<google::protobuf::io::FileInputStream>(fd);
    auto coded_input = std::make_unique<google::protobuf::io::CodedInputStream>(file_input.get());

    return std::unique_ptr<StreamMessageSource>(
        new StreamMessageSource(fd, std::move(coded_input), std::move(file_input)));
  }

  StreamMessageSource(int fd, std::unique_ptr<google::protobuf::io::CodedInputStream> coded_input,
                      std::unique_ptr<google::protobuf::io::FileInputStream> file_input)
      : MessageSource(fd),
        coded_input_(std::move(coded_input)),
        file_input_(std::move(file_input)) {}

  absl::StatusOr<::pbv1::SantaMessage> Next() override {
    // Check the magic value
    // Failing to read the first value indicates we're at the end of a file.
    uint32_t magic;
    if (!coded_input_->ReadLittleEndian32(&magic)) {
      return absl::OutOfRangeError("No more data");
    }
    if (magic != ::fsspool::StreamBatcher::kStreamBatcherMagic) {
      return absl::InternalError("Invalid magic value");
    }

    // Check the hash
    // TODO(mlw): Verify the hash
    uint64_t hash;
    if (!coded_input_->ReadLittleEndian64(&hash)) {
      return absl::InternalError("Failed to parse hash data");
    }

    // Read the length
    uint32_t message_length;
    if (!coded_input_->ReadVarint32(&message_length)) {
      return absl::InternalError("Failed to parse message length");
    }

    // Use a ScopedLimit to ensure we don't read past the end of the message.
    google::protobuf::io::CodedInputStream::Limit limit = coded_input_->PushLimit(message_length);

    // Read the raw message data
    ::pbv1::SantaMessage santa_msg;
    if (!santa_msg.ParseFromCodedStream(coded_input_.get())) {
      return absl::InternalError("Failed to parse message data");
    }

    coded_input_->PopLimit(limit);

    return santa_msg;
  }

 private:
  std::unique_ptr<google::protobuf::io::CodedInputStream> coded_input_;
  std::unique_ptr<google::protobuf::io::FileInputStream> file_input_;
};

absl::StatusOr<std::unique_ptr<MessageSource>> MessageSource::Create(NSString *path) {
  // Open the file
  int fd = open(path.UTF8String, O_RDONLY);
  if (fd < 0) {
    return absl::InvalidArgumentError("Failed to open file");
  }

  // Read the first 4 bytes to check for the stream protobuf magic number
  uint32_t magic_number = 0;
  errno = 0;
  ssize_t bytes_read = read(fd, &magic_number, sizeof(magic_number));

  // Note: Allow "parsing" of empty files so it isn't treated as an error
  if (bytes_read != 0 && bytes_read != sizeof(magic_number)) {
    close(fd);
    return absl::InvalidArgumentError("Failed to determine file type");
  }

  // Reset file position back to the beginning
  if (lseek(fd, 0, SEEK_SET) != 0) {
    close(fd);
    return absl::InternalError("Failed to reset file position for reading");
  }

  // Determine which derived class to instantiate based on magic number
  if (magic_number == ::fsspool::StreamBatcher::kStreamBatcherMagic) {
    return StreamMessageSource::Create(fd);
  } else {
    return AnyMessageSource::Create(fd);
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
