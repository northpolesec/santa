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

#import "Source/santasyncservice/SNTSantaCommandHandler.h"
#include "commands/v1.pb.h"

/// Binary upload command execution, shared by every command transport. The
/// upload itself happens in santad: this forwards the request over XPC, santad
/// opens the file as root and launches Sleigh to POST it to the presigned URL
/// carried in the request.
@interface SNTSantaCommandHandler (BinaryUpload)

/// Start a binary upload. Returns immediately; `completion` is invoked exactly
/// once with the response to report, either from the XPC reply or synchronously
/// with DISPOSITION_INTERNAL_ERROR when the request could not be handed to
/// santad at all. `completion` must not be nil.
- (void)handleBinaryUploadRequest:(const santa::commands::v1::BinaryUploadRequest&)request
                       completion:
                           (void (^)(const santa::commands::v1::BinaryUploadResponse& response))
                               completion;

/// Blocking variant used for queued (HTTP) command delivery: hands the request
/// to santad and waits for the upload to finish. Bounded by an internal
/// deadline comfortably longer than santad's own, so a santad that never
/// replies can't wedge the sync drain. Never returns nullptr.
- (santa::commands::v1::BinaryUploadResponse*)
    handleBinaryUploadRequestAndWait:(const santa::commands::v1::BinaryUploadRequest&)request
                             onArena:(google::protobuf::Arena*)arena;

@end
