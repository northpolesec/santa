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

#include <unistd.h>

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

// TTYWriter writes on a private serial queue; poll for content (~2s budget).
- (NSString*)waitForContentsAtPath:(NSString*)path {
  for (int i = 0; i < 200; i++) {
    NSString* s = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
    if (s.length > 0) return s;
    usleep(10000);
  }
  return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
}

- (void)testCanWritePath {
  XCTAssertTrue(TTYWriter::CanWrite(@"/dev/ttys003"));
  XCTAssertFalse(TTYWriter::CanWrite((NSString*)nil));
  XCTAssertFalse(TTYWriter::CanWrite(@""));
}

- (void)testWriteWithoutSignalPathWritesMessage {
  auto writer = TTYWriter::Create(/*silent_tty_mode=*/false);
  XCTAssertNotEqual(writer.get(), nullptr);
  NSString* path = [self tempPathNamed:@"ttywriter-write.txt"];

  writer->WriteWithoutSignal(path, @"hello-from-flow-block");

  NSString* got = [self waitForContentsAtPath:path];
  XCTAssertTrue([got containsString:@"hello-from-flow-block"], @"got: %@", got);
}

- (void)testSilentModeSuppressesPathWrite {
  auto writer = TTYWriter::Create(/*silent_tty_mode=*/true);
  NSString* path = [self tempPathNamed:@"ttywriter-silent.txt"];

  writer->WriteWithoutSignal(path, @"should-not-appear");

  usleep(200000);  // give any erroneous async write a chance to land
  NSString* got = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
  XCTAssertEqual(got.length, 0u, @"got: %@", got);
}

// Non-writable paths (nil, empty) are silent no-ops that leave the writer
// functional; a subsequent valid write still lands.
- (void)testNilPathIsNoOp {
  auto writer = TTYWriter::Create(/*silent_tty_mode=*/false);
  writer->WriteWithoutSignal((NSString*)nil, @"nope");
  writer->WriteWithoutSignal(@"", @"nope");

  NSString* path = [self tempPathNamed:@"ttywriter-nil-then-valid.txt"];
  writer->WriteWithoutSignal(path, @"still-works");

  NSString* got = [self waitForContentsAtPath:path];
  XCTAssertTrue([got containsString:@"still-works"], @"got: %@", got);
}

@end
