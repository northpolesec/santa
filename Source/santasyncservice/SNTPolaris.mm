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

#include <google/protobuf/arena.h>

#include "stats/v1.pb.h"

namespace pbv1 = ::santa::stats::v1;

namespace santa {

const char *kPolarisSubmissionURL =
    "https://polaris.northpole.security/santa.stats.v1.StatsService/SubmitStats";
const int kRequestTimeoutSeconds = 30;

std::string machineIdHash(std::string_view machineID) {
  unsigned char md[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(machineID.data(), (CC_LONG)machineID.length(), md);
  return BufToHexString(md, CC_SHA256_DIGEST_LENGTH);
}

::pbv1::SubmitStatsRequest *createRequestProto(NSString *orgID) {
  google::protobuf::Arena arena;
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
  return request;
}

NSError *makeRequest(NSURLRequest *req) {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSHTTPURLResponse *_response;
  __block NSError *_error;
  NSURLSessionDataTask *task = [[NSURLSession sharedSession]
      dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
          if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
            _response = (NSHTTPURLResponse *)response;
          }
          _error = error;
          dispatch_semaphore_signal(sema);
        }];
  [task resume];

  if (dispatch_semaphore_wait(
          sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * kRequestTimeoutSeconds))) {
    [task cancel];
  }

  if (_error) {
    return _error;
  }
  if (_response.statusCode != 200) {
    return [NSError errorWithDomain:NSURLErrorDomain code:_response.statusCode userInfo:nil];
  }
  return nil;
}

void SubmitStats(NSString *orgID) {
  auto pb = createRequestProto(orgID);
  std::string data;
  if (!pb->SerializeToString(&data)) {
    LOGE(@"Failed to serialize proto");
    return;
  }

  NSURL *u = [NSURL URLWithString:@(kPolarisSubmissionURL)];
  NSMutableURLRequest *req = [[NSMutableURLRequest alloc] initWithURL:u];
  [req setHTTPMethod:@"POST"];
  [req setValue:@"application/proto" forHTTPHeaderField:@"Content-Type"];
  [req setHTTPBody:[NSData dataWithBytes:data.data() length:data.size()]];

#ifdef DEBUG
  LOGI(@"Stats submission is disabled in non-release builds");
  return;
#else
  NSError *error = makeRequest(req);
  if (error) {
    LOGE(@"Failed to submit stats: %@", error);
    return;
  }
  LOGI(@"Submitted stats to %@", u.host);
#endif
}

}  // namespace santa
