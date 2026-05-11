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

#include "Source/common/verifyinghasher/FileReader.h"

#import <XCTest/XCTest.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

#include "Source/common/ScopedFile.h"
#include "Source/common/verifyinghasher/MemoryFileReader.h"

using santa::FdFileReader;
using santa::MemoryFileReader;

@interface FileReaderTest : XCTestCase
@end

@implementation FileReaderTest

- (void)testMemoryReaderHonorsOffsetAndEof {
  MemoryFileReader r({0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
  uint8_t buf[4] = {};
  XCTAssertEqual(r.Pread(buf, 4, 2), 4);
  XCTAssertEqual(buf[0], 2);
  XCTAssertEqual(buf[3], 5);
  XCTAssertEqual(r.Pread(buf, 4, 8), 2);    // partial near EOF
  XCTAssertEqual(r.Pread(buf, 4, 100), 0);  // past EOF
  XCTAssertEqual(r.Pread(buf, 4, -1), -1);  // negative offset
  XCTAssertEqual(r.Size(), 10u);
}

- (void)testFdReaderPreadsRealFile {
  santa::ScopedFile sf(::open("/etc/hosts", O_RDONLY | O_CLOEXEC));
  XCTAssertGreaterThanOrEqual(sf.UnsafeFD(), 0);
  struct stat st{};
  XCTAssertEqual(::fstat(sf.UnsafeFD(), &st), 0);
  FdFileReader r(sf.UnsafeFD(), st.st_size);
  uint8_t buf[16] = {};
  ssize_t n = r.Pread(buf, sizeof(buf), 0);
  XCTAssertGreaterThan(n, 0);
  XCTAssertLessThanOrEqual(n, static_cast<ssize_t>(sizeof(buf)));
  // /etc/hosts is ASCII; first byte should be printable.
  XCTAssertTrue(buf[0] >= 0x20 || buf[0] == '\n' || buf[0] == '#');
}

- (void)testFdReaderHandlesShortRead {
  santa::ScopedFile sf(::open("/etc/hosts", O_RDONLY | O_CLOEXEC));
  XCTAssertGreaterThanOrEqual(sf.UnsafeFD(), 0);
  struct stat st{};
  XCTAssertEqual(::fstat(sf.UnsafeFD(), &st), 0);
  FdFileReader r(sf.UnsafeFD(), st.st_size);
  // Read past EOF — should return only what's available.
  uint8_t buf[8] = {};
  ssize_t n = r.Pread(buf, sizeof(buf), st.st_size - 4);
  XCTAssertEqual(n, 4);
  XCTAssertEqual(r.Pread(buf, sizeof(buf), st.st_size + 100), 0);
}

@end
