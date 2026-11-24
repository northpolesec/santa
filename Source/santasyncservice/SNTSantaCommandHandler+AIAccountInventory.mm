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

#import "Source/santasyncservice/SNTSantaCommandHandler+AIAccountInventory.h"

#import "Source/common/SNTLogging.h"
#import "Source/common/SNTXPCControlInterface.h"

namespace pbv1 = ::santa::commands::v1;

@implementation SNTSantaCommandHandler (AIAccountInventory)

- (::pbv1::AIAccountInventoryResponse*)
    handleAIAccountInventoryRequest:(const ::pbv1::AIAccountInventoryRequest&)request
                            onArena:(google::protobuf::Arena*)arena
                       errorMessage:(std::string*)errorMessage {
  auto pbResponse = google::protobuf::Arena::Create<::pbv1::AIAccountInventoryResponse>(arena);

  id<SNTPushNotificationsSyncDelegate> strongSyncDelegate = self.syncDelegate;
  if (!strongSyncDelegate) {
    LOGE(@"SantaCommand: AIAccountInventoryRequest failed - no sync delegate");
    pbResponse->set_error(::pbv1::AIAccountInventoryResponse::ERROR_INTERNAL);
    if (errorMessage) *errorMessage = "no sync delegate";
    return pbResponse;
  }

  MOLXPCConnection* daemonConnection = [strongSyncDelegate daemonConnection];
  id<SNTDaemonControlXPC> remoteProxy = daemonConnection.remoteObjectProxy;
  if (!remoteProxy) {
    LOGE(@"SantaCommand: AIAccountInventoryRequest failed - no daemon connection");
    pbResponse->set_error(::pbv1::AIAccountInventoryResponse::ERROR_INTERNAL);
    if (errorMessage) *errorMessage = "no daemon connection";
    return pbResponse;
  }

  std::string serializedRequest;
  if (!request.SerializeToString(&serializedRequest)) {
    LOGE(@"SantaCommand: AIAccountInventoryRequest failed - could not serialize request");
    pbResponse->set_error(::pbv1::AIAccountInventoryResponse::ERROR_INTERNAL);
    if (errorMessage) *errorMessage = "could not serialize request";
    return pbResponse;
  }
  NSData* requestData = [NSData dataWithBytes:serializedRequest.data()
                                       length:serializedRequest.size()];

  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSData* responseData = nil;
  [remoteProxy runAIAccountInventory:requestData
                               reply:^(NSData* data) {
                                 responseData = data;
                                 dispatch_semaphore_signal(sema);
                               }];

  // santad owns and bounds the Sleigh execution (it has the Full Disk Access
  // needed to walk the filesystem). Its XPC reply is therefore the authoritative
  // completion signal; if the daemon connection is interrupted, SNTSyncService's
  // invalidation handler spins down this process.
  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

  if (!responseData || !pbResponse->ParseFromArray(responseData.bytes, (int)responseData.length)) {
    LOGE(@"SantaCommand: AIAccountInventoryRequest got no parseable response from santad");
    pbResponse->set_error(::pbv1::AIAccountInventoryResponse::ERROR_INTERNAL);
    if (errorMessage) *errorMessage = "no parseable response from santad";
    return pbResponse;
  }

  if (pbResponse->error() != ::pbv1::AIAccountInventoryResponse::ERROR_UNSPECIFIED &&
      errorMessage) {
    *errorMessage = "AI account inventory scan failed";
  }
  return pbResponse;
}

@end
