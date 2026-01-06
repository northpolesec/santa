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

#include "src/common/SNTXxhash.h"

#import <XCTest/XCTest.h>

#include "src/common/String.h"
#include "src/common/TestUtils.h"

#include <string>

@interface SNTXxhashTest : XCTestCase
@end

@implementation SNTXxhashTest

- (void)testXxhash64 {
  santa::Xxhash64 state;

  state.Update("hello", 5);
  XCTAssertCppStringEqual(state.HexDigest(), "9555e8555c62dcfd");

  state.Update("world", 5);
  XCTAssertCppStringEqual(state.HexDigest(), "ffdcce9d0e1f7d46");

  std::vector<uint8_t> want = santa::HexStringToBuf(state.HexDigest());
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  state.Digest(^(const uint8_t *buf, size_t length) {
    XCTAssertEqual(want.size(), length);
    XCTAssertEqual(0, memcmp(want.data(), buf, length));
    dispatch_semaphore_signal(sema);
  });

  XCTAssertSemaTrue(sema, 0, "Digest callback block was not called");
}

- (void)testXxhashCopyState64 {
  santa::Xxhash64 state;
  state.Update("hello", 5);
  XCTAssertCppStringEqual(state.HexDigest(), "9555e8555c62dcfd");

  // Check that the copying of existing state works.
  santa::Xxhash64 state2(state);
  XCTAssertCppStringEqual(state2.HexDigest(), "9555e8555c62dcfd");
  state2.Update("bye", 3);
  XCTAssertCppStringEqual(state2.HexDigest(), "0a20389200c43514");

  // Ensure that the original state is not modified
  XCTAssertCppStringEqual(state.HexDigest(), "9555e8555c62dcfd");

  // Ensure that a second copy has identical results to the first.
  santa::Xxhash64 state3(state);
  XCTAssertCppStringEqual(state3.HexDigest(), "9555e8555c62dcfd");
  state3.Update("bye", 3);
  XCTAssertCppStringEqual(state3.HexDigest(), "0a20389200c43514");

  std::vector<uint8_t> want = santa::HexStringToBuf(state.HexDigest());
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  state.Digest(^(const uint8_t *buf, size_t length) {
    XCTAssertEqual(want.size(), length);
    XCTAssertEqual(0, memcmp(want.data(), buf, length));
    dispatch_semaphore_signal(sema);
  });

  XCTAssertSemaTrue(sema, 0, "Digest callback block was not called");
}

- (void)testXxhash128 {
  santa::Xxhash128 state;

  state.Update("hello", 5);
  XCTAssertCppStringEqual(state.HexDigest(), "b5e9c1ad071b3e7fc779cfaa5e523818");

  state.Update("world", 5);
  XCTAssertCppStringEqual(state.HexDigest(), "ddf7ff67be2b60f50f178df33653476f");

  std::vector<uint8_t> want = santa::HexStringToBuf(state.HexDigest());
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  state.Digest(^(const uint8_t *buf, size_t length) {
    XCTAssertEqual(want.size(), length);
    XCTAssertEqual(0, memcmp(want.data(), buf, length));
    dispatch_semaphore_signal(sema);
  });

  XCTAssertSemaTrue(sema, 0, "Digest callback block was not called");
}

- (void)testXxhashCopyState128 {
  santa::Xxhash128 state;
  state.Update("hello", 5);
  XCTAssertCppStringEqual(state.HexDigest(), "b5e9c1ad071b3e7fc779cfaa5e523818");

  // Check that the copying of existing state works.
  santa::Xxhash128 state2(state);
  XCTAssertCppStringEqual(state2.HexDigest(), "b5e9c1ad071b3e7fc779cfaa5e523818");
  state2.Update("bye", 3);
  XCTAssertCppStringEqual(state2.HexDigest(), "a02b1c0f54414e59c9cb785db0a4cfc8");

  // Ensure that the original state is not modified
  XCTAssertCppStringEqual(state.HexDigest(), "b5e9c1ad071b3e7fc779cfaa5e523818");

  // Ensure that a second copy has identical results to the first.
  santa::Xxhash128 state3(state);
  XCTAssertCppStringEqual(state3.HexDigest(), "b5e9c1ad071b3e7fc779cfaa5e523818");
  state3.Update("bye", 3);
  XCTAssertCppStringEqual(state3.HexDigest(), "a02b1c0f54414e59c9cb785db0a4cfc8");

  std::vector<uint8_t> want = santa::HexStringToBuf(state.HexDigest());
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  state.Digest(^(const uint8_t *buf, size_t length) {
    XCTAssertEqual(want.size(), length);
    XCTAssertEqual(0, memcmp(want.data(), buf, length));
    dispatch_semaphore_signal(sema);
  });

  XCTAssertSemaTrue(sema, 0, "Digest callback block was not called");
}

@end
