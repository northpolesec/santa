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

#include "Source/santad/Logs/EndpointSecurity/Writers/FSSpool/StreamBatcher.h"

namespace fsspool {

void StreamBatcher::InitializeBatch(int fd) {
  raw_output_ = std::make_shared<google::protobuf::io::FileOutputStream>(fd);
  coded_output_ = std::make_shared<google::protobuf::io::CodedOutputStream>(
      raw_output_.get());
}

bool StreamBatcher::NeedToOpenFile() {
  // The stream batcher has no precondition and always needs to open a new file.
  return true;
}

absl::Status StreamBatcher::Write(std::vector<uint8_t> bytes) {
  coded_output_->WriteLittleEndian32(kStreamBatcherMagic);
  // TODO(mlw): This will be XXH3 64bit hash of the buffer
  coded_output_->WriteLittleEndian64(0);
  coded_output_->WriteVarint32(bytes.size());
  coded_output_->WriteRaw(bytes.data(), bytes.size());
  return absl::OkStatus();
}

absl::StatusOr<size_t> StreamBatcher::CompleteBatch(int fd) {
  int bytes_written = coded_output_->ByteCount();
  coded_output_.reset();
  raw_output_.reset();
  return bytes_written;
}

}  // namespace fsspool
