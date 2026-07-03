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

#include "Source/santad/TTYWriter.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

using santa::TTYWriter;

@interface TTYWriterTest : XCTestCase
@end

@implementation TTYWriterTest

- (NSString*)tempPathNamed:(NSString*)name {
  NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:name];
  [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
  [[NSFileManager defaultManager] createFileAtPath:path contents:nil attributes:nil];
  return path;
}

- (NSString*)contentsAtPath:(NSString*)path {
  return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
}

- (void)testCanWritePath {
  XCTAssertTrue(TTYWriter::CanWrite(@"/dev/ttys003"));
  XCTAssertFalse(TTYWriter::CanWrite((NSString*)nil));
  XCTAssertFalse(TTYWriter::CanWrite(@""));
}

- (void)testWriteWithoutSignalPathWritesMessage {
  // Inject a serial queue we own so the async write can be flushed deterministically:
  // dispatch_sync on the same serial queue runs only after the enqueued write completes.
  dispatch_queue_t q =
      dispatch_queue_create("com.northpolesec.santa.ttywritertest", DISPATCH_QUEUE_SERIAL);
  TTYWriter writer(q, /*silent_tty_mode=*/false);
  NSString* path = [self tempPathNamed:@"ttywriter-write.txt"];

  writer.WriteWithoutSignal(path, @"hello-from-flow-block");
  dispatch_sync(q, ^{
                });  // wait for the write to land

  NSString* got = [self contentsAtPath:path];
  XCTAssertTrue([got containsString:@"hello-from-flow-block"], @"got: %@", got);
}

- (void)testSilentModeSuppressesPathWrite {
  dispatch_queue_t q =
      dispatch_queue_create("com.northpolesec.santa.ttywritertest", DISPATCH_QUEUE_SERIAL);
  TTYWriter writer(q, /*silent_tty_mode=*/true);
  NSString* path = [self tempPathNamed:@"ttywriter-silent.txt"];

  writer.WriteWithoutSignal(path, @"should-not-appear");
  dispatch_sync(q, ^{
                });  // silent mode enqueues no write; this drains immediately

  NSString* got = [self contentsAtPath:path];
  XCTAssertEqual(got.length, 0u, @"got: %@", got);
}

// Non-writable paths (nil, empty) are silent no-ops that leave the writer
// functional; a subsequent valid write still lands.
- (void)testNilPathIsNoOp {
  dispatch_queue_t q =
      dispatch_queue_create("com.northpolesec.santa.ttywritertest", DISPATCH_QUEUE_SERIAL);
  TTYWriter writer(q, /*silent_tty_mode=*/false);
  writer.WriteWithoutSignal((NSString*)nil, @"nope");
  writer.WriteWithoutSignal(@"", @"nope");

  NSString* path = [self tempPathNamed:@"ttywriter-nil-then-valid.txt"];
  writer.WriteWithoutSignal(path, @"still-works");
  dispatch_sync(q, ^{
                });  // wait for the valid write to land

  NSString* got = [self contentsAtPath:path];
  XCTAssertTrue([got containsString:@"still-works"], @"got: %@", got);
}

@end
