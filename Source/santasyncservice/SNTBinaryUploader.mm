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

#import "Source/santasyncservice/SNTBinaryUploader.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "absl/cleanup/cleanup.h"
#import "Source/common/MOLAuthenticatingURLSession.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"

namespace pbv1 = ::santa::commands::v1;

@interface SNTBinaryUploader ()
@property(nonatomic) dispatch_queue_t uploadQueue;
@property(nonatomic, copy) SNTBinaryUploaderPublishBlock publishBlock;
@property(nonatomic, strong) NSURLSession *session;
@end

@implementation SNTBinaryUploader

- (instancetype)initWithPublishBlock:(SNTBinaryUploaderPublishBlock)publishBlock {
  NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
  MOLAuthenticatingURLSession *authSession =
      [[MOLAuthenticatingURLSession alloc] initWithSessionConfiguration:config];
  return [self initWithPublishBlock:publishBlock session:authSession.session];
}

- (instancetype)initWithPublishBlock:(SNTBinaryUploaderPublishBlock)publishBlock
                             session:(NSURLSession *)session {
  self = [super init];
  if (self) {
    _uploadQueue = dispatch_queue_create("com.northpolesec.santa.nats.binary_uploader",
                                         DISPATCH_QUEUE_SERIAL);
    _publishBlock = [publishBlock copy];
    _session = session;
  }
  return self;
}

- (void)handleUploadRequest:(const ::pbv1::BinaryUploadRequest &)request
                 replyTopic:(NSString *)replyTopic {
  // Copy the request out of the proto reference (which may go out of scope
  // before our queue runs) and hold the reply topic by value.
  pbv1::BinaryUploadRequest requestCopy = request;
  NSString *replyTopicCopy = [replyTopic copy];

  dispatch_async(self.uploadQueue, ^{
    [self performUploadForRequest:requestCopy replyTopic:replyTopicCopy];
  });
}

- (void)performUploadForRequest:(const ::pbv1::BinaryUploadRequest &)request
                     replyTopic:(NSString *)replyTopic {
  pbv1::SantaCommandResponse response;
  pbv1::BinaryUploadResponse *bu = response.mutable_binary_upload();

  NSString *path = [NSString stringWithUTF8String:request.path().c_str()];
  if (path.length == 0) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND);
    bu->set_message("empty path");
    self.publishBlock(replyTopic, response);
    return;
  }

  NSError *fileInfoError = nil;
  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithResolvedPath:path error:&fileInfoError];
  if (!fileInfo) {
    // SNTFileInfo returns nil for ENOENT, "not a regular file", and other
    // open failures. Distinguish ENOENT from other errors via stat().
    struct stat st;
    if (stat(path.UTF8String, &st) != 0 && errno == ENOENT) {
      bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_NOT_FOUND);
    } else {
      bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    }
    const char *desc = fileInfoError.localizedDescription.UTF8String;
    bu->set_message(desc ? desc : "open failed");
    self.publishBlock(replyTopic, response);
    return;
  }

  NSString *computedSha256 = [fileInfo SHA256];
  if (computedSha256.length == 0) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    bu->set_message("hash failed");
    self.publishBlock(replyTopic, response);
    return;
  }

  if (!request.sha256().empty() &&
      strcasecmp(request.sha256().c_str(), computedSha256.UTF8String) != 0) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_HASH_MISMATCH);
    bu->set_sha256_computed(computedSha256.UTF8String);
    bu->set_message("file at path does not match request.sha256");
    self.publishBlock(replyTopic, response);
    return;
  }

  // ---- Upload phase ----
  bu->set_sha256_computed(computedSha256.UTF8String);

  NSString *urlString = [NSString stringWithUTF8String:request.signed_post().url().c_str()];
  NSURL *url = urlString.length > 0 ? [NSURL URLWithString:urlString] : nil;
  // Reject empty / unparseable URLs and URLs that aren't HTTP(S) — NSURLSession
  // happily accepts file:// and other schemes that would never reach a bucket.
  if (!url || !url.scheme ||
      !([url.scheme.lowercaseString isEqualToString:@"https"] ||
        [url.scheme.lowercaseString isEqualToString:@"http"])) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    bu->set_message("invalid signed_post.url");
    self.publishBlock(replyTopic, response);
    return;
  }

  NSMutableDictionary<NSString *, NSString *> *form = [NSMutableDictionary dictionary];
  for (const auto &kv : request.signed_post().form_values()) {
    NSString *k = [NSString stringWithUTF8String:kv.first.c_str()];
    NSString *v = [NSString stringWithUTF8String:kv.second.c_str()];
    if (k) form[k] = v ?: @"";
  }

  NSString *boundary = [NSString stringWithFormat:@"santa-%@", [[NSUUID UUID] UUIDString]];
  NSString *bodyPath = [self buildMultipartBodyForFile:path formValues:form boundary:boundary];
  if (!bodyPath) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    bu->set_message("failed to build multipart body");
    self.publishBlock(replyTopic, response);
    return;
  }
  absl::Cleanup cleanupBody = [bodyPath] {
    unlink(bodyPath.UTF8String);
  };

  NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
  req.HTTPMethod = @"POST";
  [req setValue:[NSString stringWithFormat:@"multipart/form-data; boundary=%@", boundary]
      forHTTPHeaderField:@"Content-Type"];

  struct stat bodyStat;
  if (stat(bodyPath.UTF8String, &bodyStat) != 0) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_INTERNAL_ERROR);
    bu->set_message("failed to stat multipart body");
    self.publishBlock(replyTopic, response);
    return;
  }
  [req setValue:[NSString stringWithFormat:@"%lld", (long long)bodyStat.st_size]
      forHTTPHeaderField:@"Content-Length"];

  dispatch_semaphore_t done = dispatch_semaphore_create(0);
  __block NSData *taskResponseBody = nil;
  __block NSHTTPURLResponse *taskHTTPResponse = nil;
  __block NSError *taskError = nil;

  NSURLSessionUploadTask *task = [self.session
        uploadTaskWithRequest:req
                     fromFile:[NSURL fileURLWithPath:bodyPath]
            completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
              taskResponseBody = data;
              taskHTTPResponse = (NSHTTPURLResponse *)resp;
              taskError = err;
              dispatch_semaphore_signal(done);
            }];

  NSDate *startedAt = [NSDate date];
  [task resume];
  dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
  NSTimeInterval elapsed = -[startedAt timeIntervalSinceNow];
  bu->set_upload_duration_ms((int64_t)(elapsed * 1000.0));

  if (taskError) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_HTTP_ERROR);
    const char *desc = taskError.localizedDescription.UTF8String;
    bu->set_message(desc ? desc : "network error");
    self.publishBlock(replyTopic, response);
    return;
  }

  NSInteger status = taskHTTPResponse.statusCode;
  if (status >= 200 && status < 300) {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_COMPLETED);
    // bytes_uploaded is the actual on-the-wire body size, which is the
    // multipart body length (file bytes plus boundaries and form parts).
    bu->set_bytes_uploaded((int64_t)bodyStat.st_size);
    bu->set_message("ok");
  } else {
    bu->set_disposition(pbv1::BinaryUploadResponse::DISPOSITION_HTTP_ERROR);
    NSString *snippet = @"";
    if (taskResponseBody.length > 0) {
      NSUInteger snippetLen = MIN(taskResponseBody.length, (NSUInteger)512);
      snippet = [[NSString alloc] initWithBytes:taskResponseBody.bytes
                                         length:snippetLen
                                       encoding:NSUTF8StringEncoding]
                    ?: @"";
    }
    NSString *msg = [NSString stringWithFormat:@"%ld: %@", (long)status, snippet];
    bu->set_message(msg.UTF8String);
  }
  self.publishBlock(replyTopic, response);
}

- (NSString *)buildMultipartBodyForFile:(NSString *)filePath
                             formValues:(NSDictionary<NSString *, NSString *> *)formValues
                               boundary:(NSString *)boundary {
  // Use /tmp (mode 1777, sticky, world-writable) rather than
  // NSTemporaryDirectory(). The latter returns the per-user confstr temp
  // (/var/folders/zz/...), which a launchd-managed daemon may not have
  // write access to depending on Hardened Runtime and per-process temp
  // container behavior.
  char tmpTemplate[] = "/tmp/santa-upload-body.XXXXXXXXXX";
  int outFd = mkstemp(tmpTemplate);
  if (outFd < 0) {
    LOGE(@"SNTBinaryUploader: failed to create multipart body file: %s", strerror(errno));
    return nil;
  }
  // mkstemp doesn't set FD_CLOEXEC; match the close-on-exec discipline of
  // the rest of the file.
  int flags = fcntl(outFd, F_GETFD);
  if (flags != -1) {
    fcntl(outFd, F_SETFD, flags | FD_CLOEXEC);
  }
  NSString *bodyPath = [NSString stringWithUTF8String:tmpTemplate];

  // Writes UTF-8 bytes from s; loops over partial writes; returns NO on
  // failure. The body is unusable if any write fails — fail closed by
  // unlinking on the way out.
  BOOL (^writeString)(NSString *) = ^BOOL(NSString *s) {
    const char *bytes = s.UTF8String;
    size_t len = strlen(bytes);
    while (len > 0) {
      ssize_t w = write(outFd, bytes, len);
      if (w < 0) {
        if (errno == EINTR) continue;
        return NO;
      }
      bytes += w;
      len -= (size_t)w;
    }
    return YES;
  };

  // Each form_values entry becomes its own part. NSDictionary's
  // -keyEnumerator order is unspecified; ordering across form entries is
  // not load-bearing for S3/GCS policy compliance — what matters is that
  // every entry is present and the file part is LAST.
  for (NSString *key in formValues) {
    NSString *value = formValues[key];
    NSString *part = [NSString
        stringWithFormat:@"--%@\r\nContent-Disposition: form-data; name=\"%@\"\r\n\r\n%@\r\n",
                         boundary, key, value];
    if (!writeString(part)) {
      close(outFd);
      unlink(bodyPath.UTF8String);
      return nil;
    }
  }

  // File part header. The Content-Type on the file part is part of the file
  // part's sub-headers, not a separate form field, so S3 POST policy does
  // not reject it. application/octet-stream is the safe universal choice.
  NSString *fileName = [filePath lastPathComponent] ?: @"file";
  NSString *fileHeader = [NSString
      stringWithFormat:@"--%@\r\nContent-Disposition: form-data; name=\"file\"; "
                       @"filename=\"%@\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                       boundary, fileName];
  if (!writeString(fileHeader)) {
    close(outFd);
    unlink(bodyPath.UTF8String);
    return nil;
  }

  int inFd = open(filePath.UTF8String, O_RDONLY | O_CLOEXEC);
  if (inFd < 0) {
    close(outFd);
    unlink(bodyPath.UTF8String);
    return nil;
  }

  static const size_t kCopyChunk = 256 * 1024;
  char buf[kCopyChunk];
  for (;;) {
    ssize_t r = read(inFd, buf, sizeof(buf));
    if (r == 0) break;
    if (r < 0) {
      if (errno == EINTR) continue;
      close(inFd);
      close(outFd);
      unlink(bodyPath.UTF8String);
      return nil;
    }
    char *p = buf;
    size_t remain = (size_t)r;
    while (remain > 0) {
      ssize_t w = write(outFd, p, remain);
      if (w < 0) {
        if (errno == EINTR) continue;
        close(inFd);
        close(outFd);
        unlink(bodyPath.UTF8String);
        return nil;
      }
      p += w;
      remain -= (size_t)w;
    }
  }
  close(inFd);

  NSString *closing = [NSString stringWithFormat:@"\r\n--%@--\r\n", boundary];
  if (!writeString(closing)) {
    close(outFd);
    unlink(bodyPath.UTF8String);
    return nil;
  }

  close(outFd);
  return bodyPath;
}

@end
