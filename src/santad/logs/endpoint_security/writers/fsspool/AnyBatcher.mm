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

#include "src/santad/logs/endpoint_security/writers/fsspool/AnyBatcher.h"

#include "src/common/santa_proto_include_wrapper.h"
#include "src/santad/logs/endpoint_security/writers/fsspool/fsspool_platform_specific.h"
#include "absl/strings/str_cat.h"

static const char *kTypeGoogleApisComPrefix = "type.googleapis.com/";
static constexpr int kReservedBatchSize = 2048;

namespace fsspool {

AnyBatcher::AnyBatcher() {
  type_url_ = absl::StrCat(kTypeGoogleApisComPrefix,
                           ::santa::pb::v1::SantaMessage::descriptor()->full_name());
}

absl::Status AnyBatcher::InitializeBatch(int fd) {
  return absl::OkStatus();
}

bool AnyBatcher::NeedToOpenFile() {
  // Only indicate a new file should be opened if there are records to write.
  return cache_.records().size() > 0;
}

absl::Status AnyBatcher::Write(std::vector<uint8_t> bytes) {
  google::protobuf::Any any;
  any.set_value(absl::string_view((const char *)bytes.data(), bytes.size()));
  any.set_type_url(type_url_);

  *cache_.mutable_records()->Add() = any;

  return absl::OkStatus();
}

absl::StatusOr<size_t> AnyBatcher::CompleteBatch(int fd) {
  std::string msg;
  if (!cache_.SerializeToString(&msg)) {
    return absl::InternalError("Failed to serialize internal LogBatch cache.");
  }

  absl::Status status = WriteBuffer(fd, msg);

  cache_ = santa::fsspool::binaryproto::LogBatch();
  cache_.mutable_records()->Reserve(kReservedBatchSize);

  return msg.size();
}

}  // namespace fsspool
