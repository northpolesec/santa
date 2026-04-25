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

#include "Source/common/ScopedFile.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <errno.h>

#include "Source/common/TestUtils.h"
#include "absl/status/statusor.h"

@interface ScopedFileTest : XCTestCase
@end

@implementation ScopedFileTest

- (void)testCloseOnDestruct {
  int savedFD;
  {
    auto file = santa::ScopedFile::CreateTemporary();
    XCTAssertStatusOk(file);

    savedFD = file->UnsafeFD();
  }

  XCTAssertLessThan(close(savedFD), 0);
  XCTAssertEqual(errno, EBADF);
}

- (void)testCreateTemporary {
  NSString* prefix = @"foo/bar";
  NSString* uuid = [[NSUUID UUID] UUIDString];

  NSString* fullPath =
      [NSString stringWithFormat:@"%@/%@/%@", NSTemporaryDirectory(), prefix, uuid];

  NSFileManager* fileMgr = [NSFileManager defaultManager];

  // The shouldn't exist before creating the temporary file
  XCTAssertFalse([fileMgr fileExistsAtPath:fullPath]);

  auto file = santa::ScopedFile::CreateTemporary(prefix, /*size=*/0, uuid);
  XCTAssertStatusOk(file);

  // The path still shouldn't exist after getting a handle
  XCTAssertFalse([fileMgr fileExistsAtPath:fullPath]);

  // Ensure we can read/write the file
  NSFileHandle* writer = file->Writer();
  NSData* writeContents = [@"foo" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertTrue([writer writeData:writeContents error:nil]);
  [writer seekToFileOffset:0];

  NSFileHandle* reader = file->Reader();
  NSData* readContents = [reader readDataToEndOfFileAndReturnError:nil];

  XCTAssertEqualObjects(readContents, writeContents);
}

- (void)testCreateTemporaryWithSize {
  auto file = santa::ScopedFile::CreateTemporary(/*path_prefix=*/nil, /*size=*/1024);
  XCTAssertStatusOk(file);

  struct stat sb;
  XCTAssertEqual(fstat(file->UnsafeFD(), &sb), 0);
  XCTAssertEqual(sb.st_size, 1024);
}

- (void)testCreateTemporaryKeepsPathWhenRequested {
  NSFileManager* fileMgr = [NSFileManager defaultManager];
  NSString* savedPath;
  {
    auto file = santa::ScopedFile::CreateTemporary(/*path_prefix=*/nil, /*size=*/16,
                                                   /*filename_template=*/@"santa_test_XXXXXX",
                                                   /*keep_path=*/true);
    XCTAssertStatusOk(file);
    XCTAssertNotNil(file->Path());
    XCTAssertTrue([fileMgr fileExistsAtPath:file->Path()]);
    savedPath = file->Path();
  }
  // Destructor should have unlinked the path.
  XCTAssertFalse([fileMgr fileExistsAtPath:savedPath]);
}

- (void)testMoveAssignmentClosesExistingFD {
  int originalFD;
  int movedFD;

  auto file1 = santa::ScopedFile::CreateTemporary();
  XCTAssertStatusOk(file1);
  originalFD = file1->UnsafeFD();

  auto file2 = santa::ScopedFile::CreateTemporary();
  XCTAssertStatusOk(file2);
  movedFD = file2->UnsafeFD();

  // Move-assign file2 into file1. file1's original FD should be closed.
  *file1 = std::move(*file2);

  XCTAssertEqual(file1->UnsafeFD(), movedFD);
  XCTAssertEqual(file2->UnsafeFD(), -1);

  // The original FD should have been closed by the move assignment.
  XCTAssertLessThan(close(originalFD), 0);
  XCTAssertEqual(errno, EBADF);
}

@end
