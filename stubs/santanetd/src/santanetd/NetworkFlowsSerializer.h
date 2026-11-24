/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA_STUBS_SANTANETD_SRC_SANTANETD_NETWORKFLOWSSERIALIZER_H
#define SANTA_STUBS_SANTANETD_SRC_SANTANETD_NETWORKFLOWSSERIALIZER_H

#include <functional>
#include <string>
#include <vector>

#include "google/protobuf/arena.h"

// Forward declare for stub
namespace santa::telemetry::v1 {
class SantaMessage;
}  // namespace santa::telemetry::v1

@class SNDProcessFlows;
@class SNTCachedDecision;

namespace santanetd {

using NewSantaMessage =
    std::function<::santa::telemetry::v1::SantaMessage*(google::protobuf::Arena*)>;
using WriteSantaMessage = std::function<void(::santa::telemetry::v1::SantaMessage*)>;

// Writes nothing.
void SerializeNetworkActivity(SNDProcessFlows* processFlows, SNTCachedDecision* cd, bool network,
                              bool dns, const NewSantaMessage& newMessage,
                              const WriteSantaMessage& write);

// Returns no entries.
std::vector<std::string> FormatNetworkActivityBasicString(SNDProcessFlows* processFlows,
                                                          SNTCachedDecision* cd, bool network,
                                                          bool dns);

}  // namespace santanetd

#endif  // SANTA_STUBS_SANTANETD_SRC_SANTANETD_NETWORKFLOWSSERIALIZER_H
