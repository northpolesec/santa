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

#include "Source/common/verifyinghasher/UninitBuffer.h"

#import <XCTest/XCTest.h>

#include <cstdint>
#include <cstring>

using santa::UninitBuffer;

@interface UninitBufferTest : XCTestCase
@end

@implementation UninitBufferTest

- (void)testDefaultConstructedIsEmpty {
  UninitBuffer buf;
  XCTAssertEqual(buf.size(), 0u);
  XCTAssertTrue(buf.empty());
  // data() may legitimately be nullptr on a default-constructed buffer.
  // The contract is that view() yields a zero-sized span — readers see
  // no bytes regardless of pointer value.
  XCTAssertEqual(buf.view().size(), 0u);
}

- (void)testAllocateGivesUsableBuffer {
  UninitBuffer buf;
  buf.Allocate(32);
  XCTAssertEqual(buf.size(), 32u);
  XCTAssertFalse(buf.empty());
  XCTAssertNotEqual(buf.data(), nullptr);
  // The buffer is writable and the bytes round-trip — proves
  // `data_` and `size_` agree (a swap of assignment order would
  // surface here as either a crash or a size mismatch).
  std::memset(buf.data(), 0xab, buf.size());
  for (size_t i = 0; i < buf.size(); ++i) {
    XCTAssertEqual(buf.data()[i], 0xab);
  }
}

- (void)testViewMatchesDataAndSize {
  UninitBuffer buf;
  buf.Allocate(16);
  std::memset(buf.data(), 0x5a, buf.size());

  auto v = buf.view();
  XCTAssertEqual(v.size(), buf.size());
  XCTAssertEqual(v.data(), buf.data());
  // view() returns std::span<const uint8_t> — readers can compare
  // the bytes without writing through the span.
  for (auto b : v) {
    XCTAssertEqual(b, 0x5a);
  }
}

- (void)testConstDataMatchesNonConst {
  UninitBuffer buf;
  buf.Allocate(8);
  buf.data()[0] = 0xff;
  const UninitBuffer& cref = buf;
  XCTAssertEqual(cref.data(), buf.data());
  XCTAssertEqual(cref.size(), buf.size());
  XCTAssertEqual(cref.data()[0], 0xff);
}

@end
