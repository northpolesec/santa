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

#import "Source/santasyncservice/SNTSantaCommandHandler+EventUpload.h"

#import "Source/common/SNTLogging.h"
#include "Source/common/String.h"

namespace pbv1 = ::santa::commands::v1;
using santa::NSStringToUTF8String;
using santa::StringToNSString;

@implementation SNTSantaCommandHandler (EventUpload)

- (::pbv1::EventUploadResponse*)handleEventUploadRequest:
                                    (const ::pbv1::EventUploadRequest&)eventUploadRequest
                                                 onArena:(google::protobuf::Arena*)arena
                                              completion:(void (^)(NSError* error))completion {
  auto pbResponse = google::protobuf::Arena::Create<::pbv1::EventUploadResponse>(arena);

  // Collect the non-empty paths from the repeated `paths` field.
  NSMutableArray<NSString*>* paths =
      [NSMutableArray arrayWithCapacity:eventUploadRequest.paths_size()];
  for (const std::string& path : eventUploadRequest.paths()) {
    NSString* nsPath = StringToNSString(path);
    if (nsPath.length > 0) {
      [paths addObject:nsPath];
    }
  }

  if (paths.count == 0) {
    LOGE(@"SantaCommand: EventUploadRequest has no valid paths");
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INVALID_PATH);
    return pbResponse;
  }

  id<SNTPushNotificationsSyncDelegate> strongSyncDelegate = self.syncDelegate;
  if (!strongSyncDelegate) {
    LOGE(@"SantaCommand: EventUploadRequest failed - no sync delegate");
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INTERNAL);
    return pbResponse;
  }

  // The delegate processes the paths serially on its event-upload queue and
  // invokes the reply block once per path, so the counter below needs no
  // synchronization. The aggregate completion fires once, after the last path.
  NSUInteger expectedReplies = paths.count;
  __block NSUInteger receivedReplies = 0;
  __block NSError* firstError = nil;
  [strongSyncDelegate eventUploadForPaths:paths
                                    reply:^(NSError* error) {
                                      if (error) {
                                        LOGE(@"SantaCommand: EventUploadRequest failed: %@", error);
                                        if (!firstError) firstError = error;
                                      } else {
                                        LOGI(@"SantaCommand: EventUploadRequest completed");
                                      }
                                      if (++receivedReplies == expectedReplies && completion) {
                                        completion(firstError);
                                      }
                                    }];

  return pbResponse;
}

- (::pbv1::EventUploadResponse*)handleEventUploadRequestAndWait:
                                    (const ::pbv1::EventUploadRequest&)eventUploadRequest
                                                        onArena:(google::protobuf::Arena*)arena
                                                   errorMessage:(std::string*)errorMessage {
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSError* uploadError = nil;
  auto* pbResponse = [self handleEventUploadRequest:eventUploadRequest
                                            onArena:arena
                                         completion:^(NSError* error) {
                                           uploadError = error;
                                           dispatch_semaphore_signal(sema);
                                         }];
  if (pbResponse->has_error()) {
    // Validation failed: the upload never started and the completion will not
    // fire, so there is nothing to wait on.
    return pbResponse;
  }

  // Each path is bounded by the delegate's per-path timeouts (bundle-service
  // generation plus upload retries), so the aggregate completion is guaranteed
  // to fire in bounded time. Wait for it and report the real outcome — there is
  // no separate outer deadline for the serial per-path work to outlast.
  dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
  if (uploadError) {
    pbResponse->set_error(::pbv1::EventUploadResponse::ERROR_INTERNAL);
    if (errorMessage) *errorMessage = NSStringToUTF8String(uploadError.localizedDescription);
  }

  return pbResponse;
}

@end
