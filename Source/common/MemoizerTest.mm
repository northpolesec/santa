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

#include <type_traits>

#include "Source/common/Memoizer.h"

namespace {

// Counts copy constructions/assignments so tests can assert that accessing a
// memoized value does not duplicate it.
struct Counted {
  static int copies;

  int value = 0;

  Counted() = default;
  explicit Counted(int v) : value(v) {}
  Counted(const Counted& other) : value(other.value) { ++copies; }
  Counted& operator=(const Counted& other) {
    value = other.value;
    ++copies;
    return *this;
  }
  Counted(Counted&&) = default;
  Counted& operator=(Counted&&) = default;
};

int Counted::copies = 0;

}  // namespace

// Copying or moving a Memoizer would detach outstanding references from the
// instance that owns their storage; both are forbidden.
static_assert(!std::is_copy_constructible_v<santa::Memoizer<int>>);
static_assert(!std::is_copy_assignable_v<santa::Memoizer<int>>);
static_assert(!std::is_move_constructible_v<santa::Memoizer<int>>);
static_assert(!std::is_move_assignable_v<santa::Memoizer<int>>);

@interface MemoizerTest : XCTestCase
@end

@implementation MemoizerTest

- (void)testComputesOnce {
  int calls = 0;
  santa::Memoizer<int> m([&calls] {
    ++calls;
    return 42;
  });

  XCTAssertFalse(m.HasValue());
  XCTAssertEqual(m(), 42);
  XCTAssertTrue(m.HasValue());
  XCTAssertEqual(m(), 42);
  XCTAssertEqual(calls, 1);
}

- (void)testAccessDoesNotCopyValue {
  Counted::copies = 0;
  santa::Memoizer<Counted> m([] { return Counted(42); });

  XCTAssertEqual(m().value, 42);
  XCTAssertEqual(m().value, 42);

  // Neither materialization nor repeated access may copy the stored value.
  // Callers (e.g. cel::Activation) hand out references into the memoized
  // storage, so the value must be produced once and never duplicated.
  XCTAssertEqual(Counted::copies, 0);
}

- (void)testReturnsStableReference {
  santa::Memoizer<Counted> m([] { return Counted(7); });

  // Every access must return the same object: callers hold pointers into the
  // memoized storage across accesses (e.g. CEL evaluation wraps protos stored
  // in the cache), so the cache must never be re-materialized or moved.
  const Counted* first = &m();
  const Counted* second = &m();
  XCTAssertEqual(first, second);
}

@end
