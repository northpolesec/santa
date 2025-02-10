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

#include "Source/santasyncservice/SNTPolaris.h"

#include <iostream>
#include <sstream>
#include <string>

#import <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>

#include "Source/common/SNTLogging.h"
#include "Source/common/SNTSystemInfo.h"
#include "Source/common/String.h"

#ifdef SANTA_ENABLE_POLARIS
#include <google/protobuf/arena.h>

#include <grpc/grpc.h>
#include <grpcpp/channel.h>
#include <grpcpp/client_context.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/credentials.h>

#include "stats/v1.grpc.pb.h"

namespace pbv1 = ::santa::stats::v1;
#endif

namespace santa {

const char *kPolarisHostname = "polaris.northpole.security";

std::string machineIdHash(std::string_view machineID) {
  unsigned char md[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(machineID.data(), (CC_LONG)machineID.length(), md);
  return BufToHexString(md, CC_SHA256_DIGEST_LENGTH);
}

void SubmitStats(NSString *orgID) {
#ifdef SANTA_ENABLE_POLARIS
  google::protobuf::Arena arena;
  auto channel_creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
  auto chan = grpc::CreateChannel(kPolarisHostname, channel_creds);

  std::unique_ptr<pbv1::StatsService::Stub> stub(pbv1::StatsService::NewStub(chan));

  grpc::ClientContext context;

  auto request = google::protobuf::Arena::Create<::pbv1::SubmitStatsRequest>(&arena);

  if ([SNTSystemInfo hardwareUUID].length) {
    request->set_machine_id_hash(
        machineIdHash(NSStringToUTF8StringView([SNTSystemInfo hardwareUUID])));
  }
  if ([SNTSystemInfo santaFullVersion].length) {
    request->set_santa_version(NSStringToUTF8StringView([SNTSystemInfo santaFullVersion]));
  }
  if ([SNTSystemInfo osVersion].length) {
    request->set_macos_version(NSStringToUTF8StringView([SNTSystemInfo osVersion]));
  }
  if ([SNTSystemInfo osBuild].length) {
    request->set_macos_build(NSStringToUTF8StringView([SNTSystemInfo osBuild]));
  }
  if ([SNTSystemInfo modelIdentifier].length) {
    request->set_mac_model(NSStringToUTF8StringView([SNTSystemInfo modelIdentifier]));
  }
  if (orgID) {
    request->set_org_id(NSStringToUTF8StringView(orgID));
  }

  pbv1::SubmitStatsResponse response;
  grpc::Status s = stub->SubmitStats(&context, *request, &response);
  if (!s.ok()) {
    LOGE(@"Failed to submit stats: %s", s.error_message().c_str());
    return;
  }
  LOGI(@"Submitted stats to %s", kPolarisHostname);
#else
  LOGI(@"Stats submission is disabled in non-release builds");
#endif  // SANTA_ENABLE_POLARIS
}

}  // namespace santa
