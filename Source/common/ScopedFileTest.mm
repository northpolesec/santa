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

#include <Foundation/Foundation.h>
#include <XCTest/XCTest.h>
#include <errno.h>

#include "Source/common/TestUtils.h"
#include "absl/status/statusor.h"

namespace santa {

class ScopedFilePeer : public ScopedFile {
 public:
  using ScopedFile::fd_;
};

}  // namespace santa

@interface ScopedFileTest : XCTestCase
@end

@implementation ScopedFileTest

- (void)testCloseOnDestruct {
  int savedFD;
  {
    auto file = santa::ScopedFile::CreateTemporary();
    XCTAssertStatusOk(file);

    santa::ScopedFilePeer *peer = static_cast<santa::ScopedFilePeer *>(&(*file));
    savedFD = peer->fd_;
  }

  XCTAssertLessThan(close(savedFD), 0);
  XCTAssertEqual(errno, EBADF);
}

- (void)testCreateTemporary {
  NSString *prefix = @"foo/bar";
  NSString *uuid = [[NSUUID UUID] UUIDString];

  NSString *fullPath =
      [NSString stringWithFormat:@"%@/%@/%@", NSTemporaryDirectory(), prefix, uuid];

  NSFileManager *fileMgr = [NSFileManager defaultManager];

  // The shouldn't exist before creating the temporary file
  XCTAssertFalse([fileMgr fileExistsAtPath:fullPath]);

  auto file = santa::ScopedFile::CreateTemporary(prefix, uuid);
  XCTAssertStatusOk(file);

  // The path still shouldn't exist after getting a handle
  XCTAssertFalse([fileMgr fileExistsAtPath:fullPath]);

  // Ensure we can read/write the file
  NSFileHandle *writer = file->Writer();
  NSData *writeContents = [@"foo" dataUsingEncoding:NSUTF8StringEncoding];
  XCTAssertTrue([writer writeData:writeContents error:nil]);
  [writer seekToFileOffset:0];

  NSFileHandle *reader = file->Reader();
  NSData *readContents = [reader readDataToEndOfFileAndReturnError:nil];

  XCTAssertEqualObjects(readContents, writeContents);
}

@end
