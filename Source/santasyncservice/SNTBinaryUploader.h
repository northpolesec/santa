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

#ifndef SANTA_SANTASYNCSERVICE_SNTBINARYUPLOADER_H
#define SANTA_SANTASYNCSERVICE_SNTBINARYUPLOADER_H

#import <Foundation/Foundation.h>

#include "commands/v1.pb.h"

NS_ASSUME_NONNULL_BEGIN

// Callback that publishes a SantaCommandResponse to the given NATS reply
// subject. SNTBinaryUploader does not know how to talk to NATS itself;
// SNTPushClientNATS supplies this block so the uploader stays free of NATS
// library coupling.
typedef void (^SNTBinaryUploaderPublishBlock)(
    NSString *replyTopic,
    const ::santa::commands::v1::SantaCommandResponse &response);

// Owns a serial dispatch queue dedicated to binary uploads so a slow upload
// cannot block Ping/Kill/EventUpload commands sharing SNTPushClientNATS's
// messageQueue. Each -handleUploadRequest:replyTopic: call enqueues one
// upload and returns immediately.
@interface SNTBinaryUploader : NSObject

// Designated initializer used by production code. Constructs a long-lived
// MOLAuthenticatingURLSession for outbound HTTPS to the bucket URL.
- (instancetype)initWithPublishBlock:(SNTBinaryUploaderPublishBlock)publishBlock;

// Test-only initializer accepting an injected NSURLSession. Callers must
// pre-configure the session (e.g., via NSURLProtocol for unit tests, or
// MOLAuthenticatingURLSession.session in production).
- (instancetype)initWithPublishBlock:(SNTBinaryUploaderPublishBlock)publishBlock
                             session:(NSURLSession *)session NS_DESIGNATED_INITIALIZER;

- (instancetype)init NS_UNAVAILABLE;

// Enqueues an upload onto the uploader's serial queue. The caller must have
// already captured replyTopic from natsMsg_GetReply before natsMsg_Destroy.
// Returns immediately; the publish block fires when the upload settles.
- (void)handleUploadRequest:(const ::santa::commands::v1::BinaryUploadRequest &)request
                 replyTopic:(NSString *)replyTopic;

@end

NS_ASSUME_NONNULL_END

#endif  // SANTA_SANTASYNCSERVICE_SNTBINARYUPLOADER_H
