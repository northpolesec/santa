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

#import <Foundation/Foundation.h>

#include <google/protobuf/arena.h>
#include <string>

#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#include "commands/v1.pb.h"

/// Event upload command execution, shared by every command transport.
@interface SNTSantaCommandHandler (EventUpload)

/// Start an event upload for the requested paths. Returns immediately: the
/// returned response only reflects request validity, the upload itself runs on
/// the sync delegate's serial event-upload queue. If `completion` is non-nil it
/// is invoked exactly once after every path has been processed, with nil on
/// success or the first per-path error otherwise. When the returned response
/// carries an error the upload was never started and `completion` is not
/// invoked.
- (santa::commands::v1::EventUploadResponse*)
    handleEventUploadRequest:(const santa::commands::v1::EventUploadRequest&)request
                     onArena:(google::protobuf::Arena*)arena
                  completion:(void (^)(NSError* error))completion;

/// Blocking variant used for queued (HTTP) command delivery: starts the upload
/// and waits until every path has been processed. Each path is bounded by the
/// sync delegate's per-path timeouts, so this returns in bounded time without a
/// separate overall deadline. On upload failure the returned response carries
/// ERROR_INTERNAL and `errorMessage` (when non-null) receives free-text context
/// for the command result.
- (santa::commands::v1::EventUploadResponse*)
    handleEventUploadRequestAndWait:(const santa::commands::v1::EventUploadRequest&)request
                            onArena:(google::protobuf::Arena*)arena
                       errorMessage:(std::string*)errorMessage;

@end
