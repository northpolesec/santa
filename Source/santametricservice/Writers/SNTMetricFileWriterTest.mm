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

#import <XCTest/XCTest.h>

#import "Source/santametricservice/Writers/SNTMetricFileWriter.h"

@interface SNTMetricFileWriterTest : XCTestCase
@property NSString* tempDir;
@end

@implementation SNTMetricFileWriterTest

- (void)setUp {
  // create a temp dir
  char dirTemplate[] = "/tmp/sntmetricfileoutputtest.XXXXXXX";
  char* tempPath = mkdtemp(dirTemplate);

  if (tempPath == NULL) {
    NSLog(@"Unable to make temp directory");
    exit(1);
  }

  self.tempDir =
      [[NSFileManager defaultManager] stringWithFileSystemRepresentation:tempPath
                                                                  length:strlen(tempPath)];
}

- (void)tearDown {
  // delete the temp dir
  NSError* err;
  [[NSFileManager defaultManager] removeItemAtPath:self.tempDir error:&err];

  if (err != nil) {
    NSLog(@"unable to remove %@, error: %@", self.tempDir, err);
  }
}

- (void)testWritingToNonFileURLFails {
  NSString* testURL = @"http://www.google.com";

  SNTMetricFileWriter* fileWriter = [[SNTMetricFileWriter alloc] init];

  NSError* err;

  NSData* firstLine = [@"AAAAAAAA" dataUsingEncoding:NSUTF8StringEncoding];

  NSArray<NSData*>* input = @[ firstLine ];

  BOOL result = [fileWriter write:input toURL:[NSURL URLWithString:testURL] error:&err];
  XCTAssertFalse(result);
}

- (void)testWritingDataToFileWorks {
  NSURL* url = [NSURL fileURLWithPathComponents:@[ self.tempDir, @"test.data" ]];

  SNTMetricFileWriter* fileWriter = [[SNTMetricFileWriter alloc] init];

  NSError* err;

  NSData* firstLine = [@"AAAAAAAA" dataUsingEncoding:NSUTF8StringEncoding];
  NSData* secondLine = [@"BBBBBBBB" dataUsingEncoding:NSUTF8StringEncoding];

  NSArray<NSData*>* input = @[ firstLine ];

  BOOL success = [fileWriter write:input toURL:url error:&err];

  XCTAssertTrue(success, @"error: %@", err);
  XCTAssertNil(err);

  const char newline[1] = {'\n'};

  // Read file ensure it only contains the first line followed by a Newline
  NSData* testFileContents = [NSData dataWithContentsOfFile:url.path];
  NSMutableData* expected = [NSMutableData dataWithData:firstLine];

  [expected appendBytes:newline length:1];

  XCTAssertEqualObjects(expected, testFileContents);

  [expected appendData:secondLine];
  [expected appendBytes:newline length:1];

  // Test that calling a second time overwrites the file and that multiple rows
  // are separated by a newline
  input = @[ firstLine, secondLine ];

  success = [fileWriter write:input toURL:url error:&err];
  XCTAssertTrue(success, @"error: %@", err);

  testFileContents = [NSData dataWithContentsOfFile:url.path];
  XCTAssertEqualObjects(expected, testFileContents);
}

- (void)testThatPassingANilOrNullErrorDoesNotCrash {
  NSString* testFile = [NSString pathWithComponents:@[ @"file://", self.tempDir, @"test.data" ]];
  NSURL* url = [NSURL URLWithString:testFile];

  SNTMetricFileWriter* fileWriter = [[SNTMetricFileWriter alloc] init];

  NSData* firstLine = [@"AAAAAAAA" dataUsingEncoding:NSUTF8StringEncoding];

  BOOL success = [fileWriter write:@[ firstLine ] toURL:url error:nil];
  XCTAssertTrue(success);
  success = [fileWriter write:@[ firstLine ] toURL:url error:NULL];
  XCTAssertTrue(success);
}
@end
