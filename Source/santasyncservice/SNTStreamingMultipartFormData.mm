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

#import "Source/santasyncservice/SNTStreamingMultipartFormData.h"

#include <sys/stat.h>
#include <unistd.h>

#import "Source/common/SNTLogging.h"

static const NSUInteger kChunkSize = 256 * 1024;  // 256 KiB

@interface SNTStreamingMultipartFormData () <NSStreamDelegate>
@property(atomic) NSData *formData;
@property(readonly) NSString *boundary;
@property(readonly) NSData *closingBoundary;
@property(readonly) NSArray<NSFileHandle *> *fds;
@property(readonly) NSOutputStream *output;
@property(readonly) dispatch_queue_t streamQueue;
@property NSUInteger currentFileIndex;
@end

@implementation SNTStreamingMultipartFormData

- (instancetype)initWithFormParts:(NSDictionary<NSString *, NSString *> *)formParts
                            files:(NSArray<NSFileHandle *> *)fds
                   filesTotalSize:(NSUInteger)filesTotalSize
                 filesContentType:(NSString *)filesContentType
                         fileName:(NSString *)fileName {
  self = [super init];
  if (self) {
    if (!fds.count || !fileName.length) {
      return nil;
    }
    _boundary = [[NSUUID UUID] UUIDString];
    _closingBoundary = [[NSString stringWithFormat:@"\r\n--%@--\r\n", _boundary]
        dataUsingEncoding:NSUTF8StringEncoding];
    _fds = [fds copy];

    NSMutableData *formData = [NSMutableData data];
    [formParts enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *value, BOOL *stop) {
      // The key field determines the name of the object. It already has the correct object prefix,
      // just add the file name.
      if ([key isEqualToString:@"key"]) {
        value = [value stringByAppendingString:fileName];
      }
      [formData appendData:[self partWithName:key value:value]];
    }];
    [formData appendData:[self partWithName:@"file"
                                   filename:@"upload"
                                contentType:filesContentType ?: @"application/octet-stream"]];

    // The form data is not streamed, it will be written all in one go.
    if (formData.length > kChunkSize) {
      LOGE(@"Form data is too large: %li > %li", formData.length, kChunkSize);
      return nil;
    }

    // Form data will be written once the stream is opened.
    _formData = formData;

    _contentLength = formData.length + filesTotalSize + _closingBoundary.length;

    // The queue where the NSStreamDelegate methods will be called.
    _streamQueue = dispatch_queue_create("com.northpolesec.santa.syncservice.multipartstream",
                                         DISPATCH_QUEUE_SERIAL);

    // Create a bounded stream. This object will write to one end, and a
    // consumer will read from the other.
    NSInputStream *steam;
    NSOutputStream *output;
    [NSStream getBoundStreamsWithBufferSize:kChunkSize inputStream:&steam outputStream:&output];
    _stream = steam;
    _output = output;

    // Sample Apple code [0] shows that initialization should be on the same serial queue where the
    // stream will handle events. This makes sense. Otherwise the stream's delegate could start
    // executing while the stream was still being opened. Here is a crash from a flaky test when
    // opening the stream from the main thread:
    //
    // clang-format off
    //
    // Thread 0::  Dispatch queue: com.apple.main-thread
    // 0   libsystem_kernel.dylib                0x185a7cc54 __psynch_mutexdrop + 8
    // 1   libsystem_pthread.dylib               0x185ab80d0 _pthread_mutex_firstfit_wake + 28
    // 2   libsystem_pthread.dylib               0x185ab5cac _pthread_mutex_firstfit_unlock_slow + 244
    // 3   CoreFoundation                        0x185b7dee4 CFRunLoopWakeUp + 376
    // 4   CoreFoundation                        0x185bf00cc _wakeUpRunLoop + 76
    // 5   CoreFoundation                        0x185bc5ba0 _CFStreamSignalEvent + 552
    // 6   CoreFoundation                        0x185c7b110 boundPairWriteOpen + 68
    // 7   CoreFoundation                        0x185b6ba5c _CFStreamOpen + 140
    // 8   SNTStreamingMultipartFormDataTest     0x10768ce4c -[SNTStreamingMultipartFormData initWithFormParts:file:fileName:] + 2180
    // ...
    // Thread 1 Crashed::  Dispatch queue: com.northpolesec.santa.syncservice.multipartstream
    // 0   libsystem_pthread.dylib               0x185ab54f8 pthread_mutex_lock + 12
    // 1   CoreFoundation                        0x185c0f484 _CFStreamSetDispatchQueue + 244
    // 2   SNTStreamingMultipartFormDataTest     0x10768d9cc -[SNTStreamingMultipartFormData closeWithError:] + 776
    // 3   SNTStreamingMultipartFormDataTest     0x10768e82c -[SNTStreamingMultipartFormData stream:handleEvent:] + 1244
    // 4   CoreFoundation                        0x185bc5ec8 _outputStreamCallbackFunc + 76
    //
    // clang-format on
    //
    // The example code also shows an order for initialization:
    // 1. Set the delegate
    // 2. Set the GCD queue
    // 3. The finally open the stream.
    //
    // [0]
    // https://developer.apple.com/library/archive/samplecode/sc1236/Listings/TLSTool_TLSToolCommon_m.html
    dispatch_sync(_streamQueue, ^{
      // The first implementation used the run loop to pump delegate messages, as the very old
      // documentation [0] suggests. This model is inflexible and I was happy to come across
      // this post [1] about using CFWriteStreamSetDispatchQueue. [0]
      // https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/Streams/Articles/WritingOutputStreams.html#//apple_ref/doc/uid/20002274-1002103
      // [1]
      // https://stackoverflow.com/questions/31306642/how-to-deal-with-concurrency-issues-brought-by-nsstream-run-loop-scheduling-usin
      [output setDelegate:self];
      CFWriteStreamSetDispatchQueue((__bridge CFWriteStreamRef)output, _streamQueue);
      [output open];
    });
  }
  return self;
}

- (NSData *)partWithName:(NSString *)name value:(NSString *)value {
  NSMutableString *partString = [[NSMutableString alloc] init];
  [partString appendFormat:@"--%@\r\n", self.boundary];
  [partString appendFormat:@"Content-Disposition: form-data; name=\"%@\"\r\n", name];
  [partString appendString:@"\r\n"];
  [partString appendString:value];
  [partString appendString:@"\r\n"];
  return [partString dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSData *)partWithName:(NSString *)name
                filename:(NSString *)filename
             contentType:(NSString *)contentType {
  NSMutableString *partString = [[NSMutableString alloc] init];
  [partString appendFormat:@"--%@\r\n", self.boundary];
  [partString appendFormat:@"Content-Disposition: form-data; name=\"%@\"; filename=\"%@\"\r\n",
                           name, filename];
  if (contentType.length) {
    [partString appendFormat:@"Content-Type: %@\r\n", contentType];
  }
  [partString appendString:@"\r\n"];
  return [partString dataUsingEncoding:NSUTF8StringEncoding];
}

- (NSString *)contentType {
  return [NSString stringWithFormat:@"multipart/form-data; boundary=%@", self.boundary];
}

- (void)closeWithError:(NSError *)error {
  // Write the closing boundary.
  if (!error) {
    if ([self.output write:(const uint8_t *)self.closingBoundary.bytes
                 maxLength:self.closingBoundary.length] != self.closingBoundary.length) {
      error = self.output.streamError;
    }
  }
  self.output.delegate = nil;
  CFWriteStreamSetDispatchQueue((__bridge CFWriteStreamRef)self.output, NULL);
  [self.output close];
  if (error) {
    LOGE(@"Stream error: %@", error);
  }
}

- (void)writeNextFileChunk {
  NSError *error;
  NSData *data = [self.fds[self.currentFileIndex] readDataUpToLength:kChunkSize error:&error];
  if (error) {
    LOGE(@"Failed to read from file: %@", error);
    [self closeWithError:error];
    return;
  }

  // End of the current file.
  if (data.length == 0) {
    // If there is another file, start streaming it.
    if (self.currentFileIndex + 1 < self.fds.count) {
      ++self.currentFileIndex;
      return [self writeNextFileChunk];
    }
    // Otherwise end the stream.
    [self closeWithError:nil];
    return;
  }

  NSUInteger bytesWritten = [self.output write:(const uint8_t *)data.bytes maxLength:data.length];

  // There was a stream error.
  if (bytesWritten == -1) {
    [self closeWithError:self.output.streamError];
    return;
  }

  // A perfect write.
  if (bytesWritten == data.length) {
    return;
  }

  // A partial write to stream has occurred, adjust the fd offset so the next
  // write operation picks up where this partial write left off.
  if (lseek(self.fds[self.currentFileIndex].fileDescriptor, -(data.length - bytesWritten),
            SEEK_CUR) == -1) {
    NSError *posixError = [NSError
        errorWithDomain:NSPOSIXErrorDomain
                   code:errno
               userInfo:@{
                 NSLocalizedDescriptionKey : [NSString stringWithUTF8String:strerror(errno)]
               }];
    [self closeWithError:posixError];
    return;
  }
}

// NSStreamDelegate
- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode {
  switch (eventCode) {
    case NSStreamEventHasSpaceAvailable: {
      if (self.formData) {
        // Load up the stream with form data. This does not need to be chunked
        // since it is the first bit of data that is written and it is smaller
        // than the buffer.
        if ([self.output write:(const uint8_t *)self.formData.bytes
                     maxLength:self.formData.length] != self.formData.length) {
          LOGE(@"Failed to write form data: %@", self.output.streamError);
          [self closeWithError:self.output.streamError];
          break;
        };

        // Once the form data is sent we can free it. On the next delegate
        // invocation we will start writing the file payload. This is safe
        // because we are on a serial queue.
        self.formData = nil;

        // We need to wait for the next delegate invocation to write again.
        break;
      }
      [self writeNextFileChunk];
      break;
    }
    case NSStreamEventErrorOccurred: {
      [self closeWithError:self.output.streamError];
      break;
    }
    case NSStreamEventEndEncountered: {
      [self closeWithError:nil];
      break;
    }
  }
}

@end
