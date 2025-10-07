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

#import "Source/santasyncservice/SNTSyncPostflight.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#import "Source/santasyncservice/SNTSyncConfigBundle.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include <google/protobuf/arena.h>
#include "sync/v1.pb.h"
namespace pbv1 = ::santa::sync::v1;

using santa::NSStringToUTF8String;

@implementation SNTSyncPostflight

- (NSURL *)stageURL {
  NSString *stageName = [@"postflight" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  google::protobuf::Arena arena;
  auto req = google::protobuf::Arena::Create<::pbv1::PostflightRequest>(&arena);
  req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));
  req->set_rules_received(static_cast<uint32_t>(self.syncState.rulesReceived));
  req->set_rules_processed(static_cast<uint32_t>(self.syncState.rulesProcessed));
  req->set_file_access_rules_received(
      static_cast<uint32_t>(self.syncState.fileAccessRulesReceived));
  req->set_file_access_rules_processed(
      static_cast<uint32_t>(self.syncState.fileAccessRulesProcessed));

  switch (self.syncState.syncType) {
    case SNTSyncTypeNormal: req->set_sync_type(::pbv1::NORMAL); break;
    case SNTSyncTypeClean: req->set_sync_type(::pbv1::CLEAN); break;
    case SNTSyncTypeCleanAll: req->set_sync_type(::pbv1::CLEAN_ALL); break;
  }

  id<SNTDaemonControlXPC> rop = [self.daemonConn synchronousRemoteObjectProxy];
  [rop databaseRulesHash:^(NSString *execRulesHash, NSString *faaRulesHash) {
    req->set_rules_hash(NSStringToUTF8String(execRulesHash));
    req->set_file_access_rules_hash(NSStringToUTF8String(faaRulesHash));
  }];

  ::pbv1::PostflightResponse response;
  [self performRequest:[self requestWithMessage:req] intoMessage:&response timeout:30];
  [rop updateSyncSettings:PostflightConfigBundle(self.syncState)
                    reply:^{
                    }];

  return YES;
}

@end
