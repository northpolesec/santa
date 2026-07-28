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

#import "Source/santasyncservice/SNTSantaCommandHandler+BinaryUpload.h"

#include <memory>

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"

namespace pbv1 = ::santa::commands::v1;

// Semi-arbitrary bound on how long to wait for santad to finish an upload.
// santad SIGKILLs Sleigh 6 minutes into a launch and serializes launches, so a
// request can sit behind one in-flight upload before its own deadline even
// starts. This covers that with margin, while still guaranteeing the serial
// sync drain can't wedge forever if santad dies mid-request: MOLXPCConnection
// hands out a proxy whose error handler invalidates the connection without
// invoking the reply block, so a lost reply is simply never delivered.
static constexpr int64_t kBinaryUploadResponseTimeoutSeconds = 15 * 60;

@implementation SNTSantaCommandHandler (BinaryUpload)

- (void)handleBinaryUploadRequest:(const pbv1::BinaryUploadRequest&)request
                       completion:(void (^)(const pbv1::BinaryUploadResponse& response))completion {
  id<SNTDaemonControlXPC> daemon = [[self.syncDelegate daemonConnection] remoteObjectProxy];
  if (!daemon) {
    LOGE(@"SantaCommand: BinaryUploadRequest failed - no connection to santad");
    pbv1::BinaryUploadResponse response;
    response.set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    response.set_message("santasyncservice has no connection to santad");
    completion(response);
    return;
  }

  std::string serializedRequest;
  request.SerializeToString(&serializedRequest);

  [daemon
      uploadBinary:[NSData dataWithBytes:serializedRequest.data() length:serializedRequest.size()]
             reply:^(NSData* responseData) {
               pbv1::BinaryUploadResponse response;
               if (!responseData ||
                   !response.ParseFromArray(responseData.bytes, (int)responseData.length)) {
                 LOGE(@"SantaCommand: BinaryUploadRequest got no parseable response from "
                      @"santad");
                 response.Clear();
                 response.set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
                 response.set_message("no parseable response from santad");
               }
               completion(response);
             }];
}

- (pbv1::BinaryUploadResponse*)handleBinaryUploadRequestAndWait:
                                   (const pbv1::BinaryUploadRequest&)request
                                                        onArena:(google::protobuf::Arena*)arena {
  auto pbResponse = google::protobuf::Arena::Create<pbv1::BinaryUploadResponse>(arena);

  // Held by the completion block so a reply that lands after the wait below
  // gives up still writes to live memory. Only read once the semaphore has been
  // signalled, so the timeout path never races that write.
  auto received = std::make_shared<pbv1::BinaryUploadResponse>();
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  [self handleBinaryUploadRequest:request
                       completion:^(const pbv1::BinaryUploadResponse& response) {
                         *received = response;
                         dispatch_semaphore_signal(sema);
                       }];

  if (dispatch_semaphore_wait(
          sema, dispatch_time(DISPATCH_TIME_NOW,
                              kBinaryUploadResponseTimeoutSeconds * NSEC_PER_SEC)) != 0) {
    LOGE(@"SantaCommand: BinaryUploadRequest timed out waiting for santad");
    pbResponse->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    pbResponse->set_message("timed out waiting for santad to finish the upload");
    return pbResponse;
  }

  *pbResponse = *received;
  return pbResponse;
}

@end
