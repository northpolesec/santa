
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

#import <XCTest/XCTest.h>
#import "Source/santasyncservice/SNTStreamingMultipartFormData.h"

#include <unistd.h>

class TemporaryFile {
 public:
  TemporaryFile() {
    char temp[] = "/tmp/santa_test_XXXXXX";
    fd_ = mkstemp(temp);
    XCTAssertFalse(fd_ == -1, "%s", strerror(errno));
    unlink(temp);  // The fd remains open
  }

  ~TemporaryFile() { close(fd_); }

  TemporaryFile(const TemporaryFile &) = delete;
  TemporaryFile &operator=(const TemporaryFile &) = delete;

  NSFileHandle *reader() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

  NSFileHandle *writer() const {
    return [[NSFileHandle alloc] initWithFileDescriptor:dup(fd_) closeOnDealloc:YES];
  }

 private:
  int fd_ = -1;
};

// Reads data off a stream until it closes.
@interface SNTStreamConsumer : NSObject <NSStreamDelegate>
@property NSInputStream *stream;
@property NSMutableData *data;
@property dispatch_queue_t q;
@property(copy) void (^reply)();
@end

@implementation SNTStreamConsumer
- (instancetype)initWithStream:(NSInputStream *)stream reply:(void (^)())reply {
  self = [super init];
  if (self) {
    _stream = stream;
    _data = [NSMutableData data];
    _reply = reply;
    _q = dispatch_queue_create("com.northpolesec.santa.test.streamreader", DISPATCH_QUEUE_SERIAL);
    dispatch_sync(_q, ^{
      [stream setDelegate:self];
      CFReadStreamSetDispatchQueue((__bridge CFReadStreamRef)stream, _q);
      [stream open];
    });
  }
  return self;
}

- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode {
  switch (eventCode) {
    case NSStreamEventHasBytesAvailable: {
      uint8_t buffer[256];
      NSInteger bytesRead = [self.stream read:buffer maxLength:sizeof(buffer)];
      if (bytesRead <= 0) {
        break;
      }
      [self.data appendBytes:buffer length:bytesRead];
      break;
    }
    case NSStreamEventEndEncountered: {
      self.stream.delegate = nil;
      CFReadStreamSetDispatchQueue((__bridge CFReadStreamRef)self.stream, NULL);
      [self.stream close];
      self.reply();
      break;
    }
  }
}

@end

@interface SNTStreamingMultipartFormDataTest : XCTestCase
@end

@implementation SNTStreamingMultipartFormDataTest

- (void)testNoFiles {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                         files:nil
                                                filesTotalSize:0
                                              filesContentType:nil
                                                      fileName:nil];
  XCTAssertNil(stream);
}

- (void)testEmptyFile {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  TemporaryFile file;
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                         files:@[ file.reader() ]
                                                filesTotalSize:0
                                              filesContentType:nil
                                                      fileName:@"test"];
  XCTAssertNotNil(stream);
  XCTAssertNotNil(stream.stream);
  XCTAssertTrue([stream.contentType containsString:@"multipart/form-data"]);
  XCTAssertEqual(stream.contentLength, 386);

  XCTestExpectation *expectation = [self expectationWithDescription:@"stream complete"];
  SNTStreamConsumer *c = [[SNTStreamConsumer alloc] initWithStream:stream.stream
                                                             reply:^{
                                                               [expectation fulfill];
                                                             }];
  [self waitForExpectationsWithTimeout:10.0 handler:nil];
  XCTAssertEqual(stream.contentLength, c.data.length);
}

- (void)testEmptyNonEmptyFile {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  TemporaryFile file;
  NSFileHandle *writer = file.writer();
  NSError *error;
  [writer writeData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
  [writer seekToFileOffset:0];
  XCTAssertNil(error);
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                         files:@[ file.reader() ]
                                                filesTotalSize:5
                                              filesContentType:nil
                                                      fileName:@"test"];
  XCTAssertNotNil(stream);
  XCTAssertNotNil(stream.stream);
  XCTAssertTrue([stream.contentType containsString:@"multipart/form-data"]);
  XCTAssertEqual(stream.contentLength, 391);

  XCTestExpectation *expectation = [self expectationWithDescription:@"stream complete"];
  SNTStreamConsumer *c = [[SNTStreamConsumer alloc] initWithStream:stream.stream
                                                             reply:^{
                                                               [expectation fulfill];
                                                             }];
  [self waitForExpectationsWithTimeout:10.0 handler:nil];
  XCTAssertEqual(stream.contentLength, c.data.length);
}

- (void)testBigFile {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  TemporaryFile file;
  NSFileHandle *writer = file.writer();
  NSString *bigString = [@"A" stringByPaddingToLength:1024 * 1024
                                           withString:@"A"
                                      startingAtIndex:0];
  NSError *error;

  [writer writeData:[bigString dataUsingEncoding:NSUTF8StringEncoding] error:&error];
  [writer seekToFileOffset:0];
  XCTAssertNil(error);
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                         files:@[ file.reader() ]
                                                filesTotalSize:1024 * 1024
                                              filesContentType:nil
                                                      fileName:@"test"];
  XCTAssertNotNil(stream);
  XCTAssertNotNil(stream.stream);
  XCTAssertTrue([stream.contentType containsString:@"multipart/form-data"]);
  XCTAssertEqual(stream.contentLength, 1048962);

  XCTestExpectation *expectation = [self expectationWithDescription:@"stream complete"];
  SNTStreamConsumer *c = [[SNTStreamConsumer alloc] initWithStream:stream.stream
                                                             reply:^{
                                                               [expectation fulfill];
                                                             }];
  [self waitForExpectationsWithTimeout:10.0 handler:nil];
  XCTAssertEqual(stream.contentLength, c.data.length);
}

- (void)testMultipleFiles {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  NSError *error;
  NSString *bigString = [@"A" stringByPaddingToLength:1024 * 512 withString:@"A" startingAtIndex:0];
  NSData *bigData = [bigString dataUsingEncoding:NSUTF8StringEncoding];

  TemporaryFile file1;
  TemporaryFile file2;
  NSFileHandle *writer1 = file1.writer();
  NSFileHandle *writer2 = file2.writer();

  [writer1 writeData:bigData error:&error];
  XCTAssertNil(error);
  [writer2 writeData:bigData error:&error];
  XCTAssertNil(error);

  [writer1 seekToFileOffset:0];
  [writer2 seekToFileOffset:0];

  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                         files:@[
                                                           file1.reader(),
                                                           file2.reader(),
                                                         ]
                                                filesTotalSize:1024 * 1024
                                              filesContentType:nil
                                                      fileName:@"test"];
  XCTAssertNotNil(stream);
  XCTAssertNotNil(stream.stream);
  XCTAssertTrue([stream.contentType containsString:@"multipart/form-data"]);
  XCTAssertEqual(stream.contentLength, 1048962);

  XCTestExpectation *expectation = [self expectationWithDescription:@"stream complete"];
  SNTStreamConsumer *c = [[SNTStreamConsumer alloc] initWithStream:stream.stream
                                                             reply:^{
                                                               [expectation fulfill];
                                                             }];
  [self waitForExpectationsWithTimeout:10.0 handler:nil];
  XCTAssertEqual(stream.contentLength, c.data.length);
}

- (void)testFileContentType {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  TemporaryFile file;
  NSFileHandle *writer = file.writer();
  NSError *error;
  [writer writeData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
  [writer seekToFileOffset:0];
  XCTAssertNil(error);
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                         files:@[ file.reader() ]
                                                filesTotalSize:5
                                              filesContentType:@"application/test"
                                                      fileName:@"test"];
  XCTAssertNotNil(stream);
  XCTAssertNotNil(stream.stream);
  XCTAssertTrue([stream.contentType containsString:@"multipart/form-data"]);
  XCTAssertEqual(stream.contentLength, 383);

  XCTestExpectation *expectation = [self expectationWithDescription:@"stream complete"];
  SNTStreamConsumer *c = [[SNTStreamConsumer alloc] initWithStream:stream.stream
                                                             reply:^{
                                                               [expectation fulfill];
                                                             }];
  [self waitForExpectationsWithTimeout:10.0 handler:nil];
  XCTAssertEqual(stream.contentLength, c.data.length);
  NSString *stringBody = [[NSString alloc] initWithData:c.data encoding:NSUTF8StringEncoding];
  XCTAssertTrue([stringBody containsString:@"application/test"]);
}

@end
