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

#import "src/santanetd/NetworkFlowsSerializer.h"

#import "Source/common/SNTCachedDecision.h"

@class SNDProcessFlows;

namespace santanetd {

void PopulateNetworkActivityProcess(google::protobuf::Arena*,
                                    ::santa::pb::v1::NetworkActivity_Process*, SNDProcessFlows*,
                                    SNTCachedDecision* cd) {
  // The real serializer reads rawSigningID, and nothing in santa does. Reading it here
  // keeps santa from dropping it without noticing.
  (void)cd.rawSigningID;
}

std::string FormatNetworkFlowsBasicString(SNDProcessFlows*, SNTCachedDecision*) {
  return {};
}

}  // namespace santanetd
