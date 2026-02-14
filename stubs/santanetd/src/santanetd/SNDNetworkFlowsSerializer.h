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

#ifndef SND_NETWORK_FLOWS_SERIALIZER_H
#define SND_NETWORK_FLOWS_SERIALIZER_H

#include <string>

#include "google/protobuf/arena.h"

// Forward declare for stub
namespace santa::pb::v1 {
class NetworkActivity_Process;
}  // namespace santa::pb::v1

@class SNDFlowInfo;
@class SNDProcessInfo;
@class SNTCachedDecision;

namespace santanetd {

void PopulateNetworkActivityFlow(google::protobuf::Arena *arena,
                                 ::santa::pb::v1::NetworkActivity_Process *process,
                                 SNDProcessInfo *processInfo, SNDFlowInfo *flow,
                                 SNTCachedDecision *cd);

std::string FormatNetworkFlowBasicString(SNDProcessInfo *processInfo, SNDFlowInfo *flow,
                                         SNTCachedDecision *cd);

}  // namespace santanetd

#endif
