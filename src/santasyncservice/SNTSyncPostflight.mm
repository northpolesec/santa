/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "src/santasyncservice/SNTSyncPostflight.h"

#import "src/common/MOLXPCConnection.h"
#import "src/common/SNTLogging.h"
#import "src/common/SNTSyncConstants.h"
#import "src/common/SNTXPCControlInterface.h"
#import "src/common/String.h"
#include "src/santasyncservice/ProtoTraits.h"
#import "src/santasyncservice/SNTSyncConfigBundle.h"
#import "src/santasyncservice/SNTSyncState.h"
#include "google/protobuf/arena.h"

namespace {

template <bool IsV2>
BOOL Postflight(SNTSyncPostflight *self) {
  using Traits = santa::ProtoTraits<IsV2>;
  google::protobuf::Arena arena;
  auto req = google::protobuf::Arena::Create<typename Traits::PostflightRequestT>(&arena);
  req->set_machine_id(santa::NSStringToUTF8String(self.syncState.machineID));
  req->set_rules_received(static_cast<uint32_t>(self.syncState.rulesReceived));
  req->set_rules_processed(static_cast<uint32_t>(self.syncState.rulesProcessed));
  if constexpr (IsV2) {
    req->set_file_access_rules_received(
        static_cast<uint32_t>(self.syncState.fileAccessRulesReceived));
    req->set_file_access_rules_processed(
        static_cast<uint32_t>(self.syncState.fileAccessRulesProcessed));
  }

  switch (self.syncState.syncType) {
    case SNTSyncTypeNormal: req->set_sync_type(Traits::NORMAL); break;
    case SNTSyncTypeClean: req->set_sync_type(Traits::CLEAN); break;
    case SNTSyncTypeCleanAll: req->set_sync_type(Traits::CLEAN_ALL); break;
  }

  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];
  [rop databaseRulesHash:^(NSString *execRulesHash, NSString *faaRulesHash) {
    req->set_rules_hash(santa::NSStringToUTF8String(execRulesHash));
    if constexpr (IsV2) {
      req->set_file_access_rules_hash(santa::NSStringToUTF8String(faaRulesHash));
    }
  }];

  typename Traits::PostflightResponseT response;
  [self performRequest:[self requestWithMessage:req] intoMessage:&response timeout:30];
  [rop updateSyncSettings:PostflightConfigBundle(self.syncState)
                    reply:^{
                    }];

  return YES;
}

}  // namespace

@implementation SNTSyncPostflight

- (NSURL *)stageURL {
  NSString *stageName = [@"postflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  if (self.syncState.isSyncV2) {
    return Postflight<true>(self);
  } else {
    return Postflight<false>(self);
  }
}

@end
