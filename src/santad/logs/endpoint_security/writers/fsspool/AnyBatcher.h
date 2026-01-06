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

#ifndef SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_ANYBATCHER_H_
#define SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_ANYBATCHER_H_

#include <vector>

#include "src/santad/logs/endpoint_security/writers/fsspool/binaryproto.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace fsspool {

class AnyBatcher {
 public:
  AnyBatcher();

  inline bool ShouldInitializeBeforeWrite() { return false; }
  absl::Status InitializeBatch(int fd);
  bool NeedToOpenFile();
  absl::Status Write(std::vector<uint8_t> bytes);
  absl::StatusOr<size_t> CompleteBatch(int fd);

  std::string TypeURL() { return type_url_; }

 private:
  std::string type_url_;
  santa::fsspool::binaryproto::LogBatch cache_;
};

}  // namespace fsspool

#endif  // SANTA__SANTAD__LOGS_ENDPOINTSECURITY_WRITERS_FSSPOOL_ANYBATCHER_H_
