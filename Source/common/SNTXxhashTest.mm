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

#include "Source/common/SNTXxhash.h"

#import <XCTest/XCTest.h>

#include "Source/common/TestUtils.h"

#include <string>

@interface SNTXxhashTest : XCTestCase
@end

@implementation SNTXxhashTest

- (void)testXxhash {
  santa::Xxhash state;

  state.Update("hello", 5);
  XCTAssertCppStringEqual(state.Digest(), "b5e9c1ad071b3e7fc779cfaa5e523818");

  state.Update("world", 5);
  XCTAssertCppStringEqual(state.Digest(), "ddf7ff67be2b60f50f178df33653476f");
}

- (void)testXxhashCopyState {
  santa::Xxhash state;
  state.Update("hello", 5);
  XCTAssertCppStringEqual(state.Digest(), "b5e9c1ad071b3e7fc779cfaa5e523818");

  // Check that the copying of existing state works.
  santa::Xxhash state2(state);
  XCTAssertCppStringEqual(state2.Digest(), "b5e9c1ad071b3e7fc779cfaa5e523818");
  state2.Update("bye", 3);
  XCTAssertCppStringEqual(state2.Digest(), "a02b1c0f54414e59c9cb785db0a4cfc8");

  // Ensure that the original state is not modified
  XCTAssertCppStringEqual(state.Digest(), "b5e9c1ad071b3e7fc779cfaa5e523818");

  // Ensure that a second copy has identical results to the first.
  santa::Xxhash state3(state);
  XCTAssertCppStringEqual(state3.Digest(), "b5e9c1ad071b3e7fc779cfaa5e523818");
  state3.Update("bye", 3);
  XCTAssertCppStringEqual(state3.Digest(), "a02b1c0f54414e59c9cb785db0a4cfc8");
}

@end
