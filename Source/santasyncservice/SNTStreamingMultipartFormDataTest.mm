
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
    [stream setDelegate:self];
    CFReadStreamSetDispatchQueue((__bridge CFReadStreamRef)stream, _q);
    [stream open];
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
      CFReadStreamSetDispatchQueue((__bridge CFReadStreamRef)self.stream, NULL);
      [self.stream close];
      self.reply();
      break;
    }
  }
}

@end

@interface SNTStreamingMultipartFormDataTest : XCTestCase
@property NSString *tempFilePath;
@property NSFileHandle *tempFileReader;
@property NSFileHandle *tempFileWriter;

@end

@implementation SNTStreamingMultipartFormDataTest

- (void)setUp {
  [super setUp];

  NSString *tempDir = NSTemporaryDirectory();
  NSString *fileName = [NSString stringWithFormat:@"testfile_%@.txt", [[NSUUID UUID] UUIDString]];
  self.tempFilePath = [tempDir stringByAppendingPathComponent:fileName];
  XCTAssertTrue([[NSFileManager defaultManager] createFileAtPath:self.tempFilePath
                                                        contents:nil
                                                      attributes:nil]);
  self.tempFileReader = [NSFileHandle fileHandleForReadingAtPath:self.tempFilePath];
  XCTAssertNotNil(self.tempFileReader);
  self.tempFileWriter = [NSFileHandle fileHandleForWritingAtPath:self.tempFilePath];
  XCTAssertNotNil(self.tempFileWriter);
}

- (void)tearDown {
  [self.tempFileReader closeFile];
  [self.tempFileWriter closeFile];
  XCTAssertTrue([[NSFileManager defaultManager] removeItemAtPath:self.tempFilePath error:nil]);
  [super tearDown];
}

- (void)testNoFiles {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts file:nil fileName:nil];
  XCTAssertNil(stream);
}

- (void)testEmptyFile {
  NSDictionary *formParts = @{@"field1" : @"value1", @"key" : @"object-"};
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                          file:self.tempFileReader
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
  NSError *error;
  [self.tempFileWriter writeData:[@"hello" dataUsingEncoding:NSUTF8StringEncoding] error:&error];
  XCTAssertNil(error);
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                          file:self.tempFileReader
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
  NSError *error;
  NSString *bigString = [@"A" stringByPaddingToLength:1024 * 1024
                                           withString:@"A"
                                      startingAtIndex:0];
  [self.tempFileWriter writeData:[bigString dataUsingEncoding:NSUTF8StringEncoding] error:&error];
  XCTAssertNil(error);
  SNTStreamingMultipartFormData *stream =
      [[SNTStreamingMultipartFormData alloc] initWithFormParts:formParts
                                                          file:self.tempFileReader
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

@end
