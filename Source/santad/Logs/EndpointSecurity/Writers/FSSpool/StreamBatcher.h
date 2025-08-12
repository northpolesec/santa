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

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "google/protobuf/io/coded_stream.h"
#include "google/protobuf/io/zero_copy_stream_impl.h"

namespace fsspool {

class StreamBatcher {
 public:
  static constexpr uint32_t kStreamBatcherMagic = 0x21544E53;

  StreamBatcher() = default;

  inline bool ShouldInitializeBeforeWrite() { return true; }
  void InitializeBatch(int fd);
  bool NeedToOpenFile();
  absl::Status Write(std::vector<uint8_t> bytes);
  absl::StatusOr<size_t> CompleteBatch(int fd);

 private:
  std::shared_ptr<google::protobuf::io::ZeroCopyOutputStream> raw_output_;
  std::shared_ptr<google::protobuf::io::CodedOutputStream> coded_output_;
};

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_STREAMBATCHER_H_
